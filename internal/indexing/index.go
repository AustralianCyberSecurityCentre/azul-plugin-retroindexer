package indexing

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	bedSet "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/settings"
)

var shaName = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var errCannotSplit = errors.New("failed batch cannot be split")

// ReadyDirs finds rotated batches in date and sequence order.
func (p *Pipeline) ReadyDirs() ([]string, error) {
	root, err := os.ReadDir(p.base())
	if err != nil {
		return nil, err
	}
	var dates []string
	for _, d := range root {
		if d.IsDir() && len(d.Name()) == 8 {
			if _, err := time.Parse("20060102", d.Name()); err == nil {
				dates = append(dates, d.Name())
			}
		}
	}
	sort.Strings(dates)
	var ready []string
	for _, date := range dates {
		children, err := os.ReadDir(filepath.Join(p.base(), date))
		if err != nil {
			return nil, err
		}
		sort.Slice(children, func(i, j int) bool {
			a, ea := strconv.Atoi(children[i].Name())
			b, eb := strconv.Atoi(children[j].Name())
			if ea == nil && eb == nil {
				return a < b
			}
			if ea == nil {
				return true
			}
			if eb == nil {
				return false
			}
			return children[i].Name() < children[j].Name()
		})
		for _, c := range children {
			if c.IsDir() {
				ready = append(ready, filepath.Join(p.base(), date, c.Name()))
			}
		}
	}
	return ready, nil
}
func (p *Pipeline) nextIndexBase() string {
	base := time.Now().UTC().Format("20060102T150405.000000000")
	for i := 0; ; i++ {
		name := base
		if i > 0 {
			name += fmt.Sprintf(".%03d", i)
		}
		candidate := filepath.Join(p.bgiDir(), name)
		if _, err := os.Stat(candidate + ".bgi"); os.IsNotExist(err) {
			return candidate
		}
	}
}

// collectInput writes the exact BigGrep line format used by the Python indexer.
func collectInput(dir string, w io.Writer) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	names := make([]string, 0)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), metaSuffix) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	buf := bufio.NewWriter(w)
	n := 0
	for _, name := range names {
		stem := strings.TrimSuffix(name, metaSuffix)
		if !shaName.MatchString(stem) {
			continue
		}
		dataPath := filepath.Join(dir, stem)
		if st, err := os.Stat(dataPath); err != nil || !st.Mode().IsRegular() {
			continue
		}
		meta, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return n, err
		}
		var m Metadata
		if err := json.Unmarshal(meta, &m); err != nil {
			log.Printf("ignoring malformed metadata %s: %v", name, err)
			continue
		}
		if err := validMetadata(m); err != nil {
			log.Printf("ignoring metadata %s: %v", name, err)
			continue
		}
		if _, err := fmt.Fprintf(buf, "%s,%s\n", dataPath, m.Format()); err != nil {
			return n, err
		}
		n++
	}
	return n, buf.Flush()
}
func (p *Pipeline) failedLastTime(dir string) bool {
	raw, err := os.ReadFile(p.lastAttempt())
	return err == nil && string(raw) == dir
}

// splitOrQuarantine halves a failed batch once; repeated failures remain on disk.
func splitOrQuarantine(dir string) error {
	// Do not delete failed inputs: data loss is unacceptable. Quarantine persistent failures.
	if strings.Contains(filepath.Base(dir), "-split") {
		return fmt.Errorf("%w: split directory %q failed again", errCannotSplit, dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var stems []string
	for _, e := range entries {
		if !e.IsDir() && shaName.MatchString(e.Name()) {
			stems = append(stems, e.Name())
		}
	}
	sort.Strings(stems)
	if len(stems) < 2 {
		return fmt.Errorf("%w: cannot split %s: fewer than two binaries", errCannotSplit, dir)
	}
	for i := 1; i <= 2; i++ {
		if err := os.Mkdir(dir+fmt.Sprintf("-split-part%d", i), 02775); err != nil {
			return err
		}
	}
	for i, stem := range stems {
		dest := dir + "-split-part1"
		if i >= len(stems)/2 {
			dest = dir + "-split-part2"
		}
		for _, file := range []string{stem, stem + metaSuffix} {
			old := filepath.Join(dir, file)
			if _, err := os.Stat(old); err == nil {
				if err := os.Rename(old, filepath.Join(dest, file)); err != nil {
					return err
				}
			}
		}
	}
	return os.Remove(dir)
}

// quarantineBatch moves a permanently failing batch outside ReadyDirs' date trees.
// The binary and metadata files remain on the PVC for manual inspection/recovery.
func (p *Pipeline) quarantineBatch(dir string, reason error) error {
	quarantineRoot := filepath.Join(p.stateDir(), "quarantine")
	if err := os.MkdirAll(quarantineRoot, 02775); err != nil {
		return err
	}
	// Include the original date and batch name to avoid collisions across days.
	basename := filepath.Base(filepath.Dir(dir)) + "-" + filepath.Base(dir)
	var dest string
	for i := 0; ; i++ {
		dest = filepath.Join(quarantineRoot, basename)
		if i > 0 {
			dest += fmt.Sprintf("-%d", i)
		}
		_, err := os.Lstat(dest)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := os.Rename(dir, dest); err != nil {
		return err
	}
	// A stale attempt marker must not affect the next ready batch.
	if err := os.Remove(p.lastAttempt()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("quarantined %s at %s but failed to clear attempt marker: %w", dir, dest, err)
	}
	bedSet.Logger.Error().Err(reason).Str("original", dir).Str("quarantine", dest).
		Msg("index batch quarantined after persistent indexing failure; files retained for manual recovery")
	return nil
}

// Generate runs bgindex against one ready batch and publishes its output
// atomically on the local filesystem before removing the source batch.
func (p *Pipeline) Generate(ctx context.Context, dir string) (string, error) {
	if p.failedLastTime(dir) && p.Config.SplitOnFailure {
		if err := splitOrQuarantine(dir); err != nil {
			if errors.Is(err, errCannotSplit) {
				if quarantineErr := p.quarantineBatch(dir, err); quarantineErr != nil {
					return "", quarantineErr
				}
				return "", nil // irreducible failures must not block all later batches
			}
			return "", err
		}
		// Clear the marker when split succeeds: the next directory has not failed.
		if err := os.Remove(p.lastAttempt()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return "", nil // another pass will pick up split directories
	}
	if err := os.WriteFile(p.lastAttempt(), []byte(dir), 0664); err != nil {
		return "", err
	}
	input, err := os.CreateTemp(p.stateDir(), "bgindex-input-")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := os.Remove(input.Name()); err != nil {
			bedSet.Logger.Error().Err(err).Msg("failed to remove temporary file")
		}
	}()
	count, err := collectInput(dir, input)
	if err != nil {
		if closeErr := input.Close(); closeErr != nil {
			bedSet.Logger.Error().Err(closeErr).Msg("failed to close temporary file")
		}
		return "", err
	}
	if count == 0 {
		if closeErr := input.Close(); closeErr != nil {
			bedSet.Logger.Error().Err(closeErr).Msg("failed to close temporary file")
		}
		return "", fmt.Errorf("no valid metadata+binary pairs in %s", dir)
	}

	if _, err := input.Seek(0, io.SeekStart); err != nil {
		if closeErr := input.Close(); closeErr != nil {
			bedSet.Logger.Error().Err(closeErr).Msg("failed to close temporary file")
		}
		return "", err
	}

	indexBase := p.nextIndexBase()

	// All indexes (including periodic snapshots) must have unique names.
	// Otherwise a newer periodic build can overwrite an older failed upload.
	// Writing to .hidden.bgi ensures readers never observe a partially built index.
	hidden := filepath.Join(p.bgiDir(), "."+filepath.Base(indexBase))

	defer func() {
		err := os.Remove(hidden + ".bgi")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			bedSet.Logger.Error().Err(err).Msg("failed to remove temporary index")
		}
	}()

	cctx, cancel := context.WithTimeout(ctx, p.Config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, p.Config.Bigindex, "-p", hidden, "-z", "-L")
	cmd.Stdin = input

	out, err := cmd.CombinedOutput()

	if closeErr := input.Close(); closeErr != nil {
		bedSet.Logger.Error().Err(closeErr).Msg("failed to close temporary file")
	}

	if err != nil {
		return "", fmt.Errorf("bgindex failed (%v): %s", err, string(out))
	}
	final := indexBase + ".bgi"
	if err := os.Rename(hidden+".bgi", final); err != nil {
		return "", err
	}
	// Do not delete originals until successful output exists.
	if err := os.RemoveAll(dir); err != nil {
		return final, err
	}
	if err := os.Remove(p.lastAttempt()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return final, err
	}
	return final, nil
}

// IndexReady processes staged batches; cloud publication is handled separately
// in normal operation, allowing failed uploads to be retried.
func (p *Pipeline) IndexReady(ctx context.Context, uploaded func(string) error) (int, error) {
	dirs, err := p.ReadyDirs()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, dir := range dirs {
		final, err := p.Generate(ctx, dir)
		if err != nil {
			return n, fmt.Errorf("index %s: %w", dir, err)
		}
		if final == "" {
			continue
		}
		bedSet.Logger.Info().
			Str("index", final).
			Msg("generated index")
		n++
		if uploaded != nil {
			if err := uploaded(final); err != nil {
				return n, fmt.Errorf("upload %s: %w", final, err)
			}
		}
	}
	return n, nil
}
