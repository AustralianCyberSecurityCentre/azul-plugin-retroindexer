package indexing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	bedSet "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/settings"
)

const MinDataSize = 4
const metaSuffix = "-meta"

// Metadata accompanies each cached binary and becomes a BigGrep input label.
type Metadata struct {
	StreamLabel  string  `json:"stream_label"`
	StreamSource string  `json:"stream_source"`
	JobID        *string `json:"job_id,omitempty"`
	FileFormat   string  `json:"file_format,omitempty"`
	Synthetic    bool    `json:"synthetic,omitempty"`
}

func (m Metadata) Format() string {
	out := "stream_label=" + m.StreamLabel + ",stream_source=" + m.StreamSource
	if m.Synthetic {
		out += ",synthetic=true"
	}
	if m.FileFormat != "" {
		out += ",file_format=" + m.FileFormat
	}
	if m.JobID != nil {
		out += ",job_id=" + *m.JobID
	}
	return out
}
func validMetadata(m Metadata) error {
	for _, s := range []string{m.StreamLabel, m.StreamSource} {
		if s == "" || strings.ContainsAny(s, ",\n\r=") {
			return fmt.Errorf("invalid metadata component %q", s)
		}
	}
	if strings.ContainsAny(m.FileFormat, ",\n\r=") {
		return errors.New("invalid file format")
	}
	if m.JobID != nil && strings.ContainsAny(*m.JobID, ",\n\r=") {
		return errors.New("invalid job id")
	}
	return nil
}

// Pipeline shares one staging area between Dispatcher ingestion and indexing.
// Its mutex protects cache writes and periodic flushes.
type Pipeline struct {
	Config       Config
	lastPeriodic time.Time
	mu           sync.Mutex
}

func New(c Config) (*Pipeline, error) {
	p := &Pipeline{Config: c, lastPeriodic: time.Now()}
	for _, d := range []string{p.cacheDir(), p.bgiDir(), p.stateDir()} {
		if err := os.MkdirAll(d, 02775); err != nil {
			return nil, err
		}
	}
	return p, nil
}
func (p *Pipeline) base() string     { return filepath.Join(p.Config.Root, p.Config.Name) }
func (p *Pipeline) cacheDir() string { return filepath.Join(p.base(), "cache") }
func (p *Pipeline) bgiDir() string   { return filepath.Join(p.base(), "bgi") }
func (p *Pipeline) stateDir() string { return filepath.Join(p.base(), "state") }
func (p *Pipeline) lastAttempt() string {
	return filepath.Join(p.stateDir(), "last_attempted_dir.state")
}

// CacheBytes totals all active partitions, including legacy files from an older layout.
func (p *Pipeline) CacheBytes() (int64, error) {
	var sum int64
	err := filepath.WalkDir(p.cacheDir(), func(path string, e os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e.IsDir() || strings.HasSuffix(e.Name(), metaSuffix) || strings.HasPrefix(e.Name(), ".") {
			return nil
		}
		if !shaName.MatchString(e.Name()) {
			return nil
		}
		st, err := e.Info()
		if err != nil {
			return err
		}
		sum += st.Size()
		return nil
	})
	return sum, err
}

func cacheBytesIn(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var sum int64
	for _, e := range entries {
		if !e.IsDir() && shaName.MatchString(e.Name()) {
			st, err := e.Info()
			if err != nil {
				return 0, err
			}
			sum += st.Size()
		}
	}
	return sum, nil
}

// freeSpaceGuard refuses writes when the PVC would dip below the configured
// reserve. The check is repeated during streaming so a large input cannot
// exhaust the volume between the first and last write.
type freeSpaceGuard struct {
	destination io.Writer
	directory   string
	reserve     int64
	sinceCheck  int64
}

func availableBytes(directory string) (int64, error) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(directory, &stats); err != nil {
		return 0, err
	}
	return int64(stats.Bavail) * int64(stats.Bsize), nil
}

func (w *freeSpaceGuard) Write(data []byte) (int, error) {
	if w.reserve > 0 && (w.sinceCheck == 0 || w.sinceCheck >= 16*1024*1024) {
		available, err := availableBytes(w.directory)
		if err != nil {
			return 0, fmt.Errorf("check staging PVC free space: %w", err)
		}
		if available-int64(len(data)) < w.reserve {
			return 0, fmt.Errorf("insufficient free PVC space for staging: available %d bytes, reserve %d bytes", available, w.reserve)
		}
		w.sinceCheck = 0
	}
	n, err := w.destination.Write(data)
	w.sinceCheck += int64(n)
	return n, err
}

// AddStream streams directly to a temporary cache file; multi-GiB content is never held in memory.
// A completed stream is atomically named by its CONTENT hash, matching the original Python ingestor.
func (p *Pipeline) AddStream(r io.Reader, m Metadata) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validMetadata(m); err != nil {
		return false, err
	}
	if !p.Config.StreamLabels[m.StreamLabel] {
		return false, nil
	}
	if err := os.MkdirAll(p.cacheDir(), 02775); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(p.stateDir(), ".incoming-")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() {
		if err := os.Remove(tmpName); err != nil && !errors.Is(err, os.ErrNotExist) {
			bedSet.Logger.Error().Err(err).Msg("failed to remove temporary file")
		}
	}()
	h := sha256.New()
	guarded := &freeSpaceGuard{destination: io.MultiWriter(tmp, h), directory: p.stateDir(), reserve: p.Config.MinFreeBytes}
	size, copyErr := io.Copy(guarded, io.LimitReader(r, p.Config.MaxBytes+1))
	closeErr := tmp.Close()
	if copyErr != nil {
		return false, copyErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if size < MinDataSize || size > p.Config.MaxBytes {
		return false, fmt.Errorf("stream size %d not in [%d,%d]", size, MinDataSize, p.Config.MaxBytes)
	}
	name := hex.EncodeToString(h.Sum(nil))
	// Each partition accumulates independently; no cross-format index is produced.
	part := partitionFor(m, size)
	activeDir := p.partitionCacheDir(part)
	if err := os.MkdirAll(activeDir, 02775); err != nil {
		return false, err
	}
	dest := filepath.Join(activeDir, name)
	if _, err := os.Stat(dest); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	cached, err := cacheBytesIn(activeDir)
	if err != nil {
		return false, err
	}
	// Rotate the existing batch before admitting a file that would exceed the limit.
	if cached+size > p.Config.MaxBytes && cached > 0 {
		if err := p.rotatePartition(activeDir); err != nil {
			return false, err
		}
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return false, err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return false, err
	}
	metaTmp, err := os.CreateTemp(activeDir, ".meta-")
	if err != nil {
		if removeErr := os.Remove(dest); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			bedSet.Logger.Error().Err(removeErr).Msg("failed to remove destination file")
		}
		return false, err
	}
	metaName := metaTmp.Name()
	defer func() {
		if err := os.Remove(metaName); err != nil && !errors.Is(err, os.ErrNotExist) {
			bedSet.Logger.Error().Err(err).Msg("failed to remove temporary metadata file")
		}
	}()
	if _, err = metaTmp.Write(payload); err == nil {
		err = metaTmp.Sync()
	}
	if e := metaTmp.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(metaName, dest+metaSuffix)
	}
	if err != nil {
		if removeErr := os.Remove(dest); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			bedSet.Logger.Error().Err(removeErr).Msg("failed to remove destination file")
		}
		return false, err
	}
	// Rotate immediately at the threshold; a subsequent stream is not required.
	// Metadata has already been atomically written, so the ready batch is complete.
	if cachedNow, err := cacheBytesIn(activeDir); err != nil {
		return true, err
	} else if cachedNow >= p.Config.MaxBytes {
		if err := p.rotatePartition(activeDir); err != nil {
			return true, err
		}
	}
	return true, nil
}
func (p *Pipeline) nextReadyDir() (string, error) {
	day := time.Now().Format("20060102")
	parent := filepath.Join(p.base(), day)
	if err := os.MkdirAll(parent, 02775); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			v, err := strconv.Atoi(e.Name())
			if err == nil && v > n {
				n = v
			}
		}
	}
	return filepath.Join(parent, strconv.Itoa(n+1)), nil
}

// rotatePartition atomically moves one homogeneous staging directory into the
// existing dated ready-batch namespace, preserving old index discovery logic.
func (p *Pipeline) rotatePartition(activeDir string) error {
	bytes, err := cacheBytesIn(activeDir)
	if err != nil || bytes == 0 {
		return err
	}
	if err := p.addSingleBatchDummy(activeDir); err != nil {
		return err
	}
	ready, err := p.nextReadyDir()
	if err != nil {
		return err
	}
	if err := os.Rename(activeDir, ready); err != nil {
		return err
	}
	return os.MkdirAll(activeDir, 02775)
}

// rotateCache flushes all partitions; legacy flat-cache content is also kept.
func (p *Pipeline) rotateCache() error {
	groups, err := os.ReadDir(p.cacheDir())
	if err != nil {
		return err
	}
	// Rotate legacy flat input as a separate batch during an upgrade.
	if bytes, err := cacheBytesIn(p.cacheDir()); err != nil {
		return err
	} else if bytes > 0 {
		if err := p.rotateLegacyCache(); err != nil {
			return err
		}
	}
	for _, group := range groups {
		if !group.IsDir() {
			continue
		}
		sizes, err := os.ReadDir(filepath.Join(p.cacheDir(), group.Name()))
		if err != nil {
			return err
		}
		for _, size := range sizes {
			if !size.IsDir() {
				continue
			}
			if err := p.rotatePartition(filepath.Join(p.cacheDir(), group.Name(), size.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Pipeline) rotateLegacyCache() error {
	// Move legacy files into a private staging directory, then publish the
	// completed batch with one rename. Never expose a half-migrated ready dir.
	if err := p.addSingleBatchDummy(p.cacheDir()); err != nil {
		return err
	}
	ready, err := p.nextReadyDir()
	if err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(ready), ".legacy-")
	if err != nil {
		return err
	}
	// Roll back if any move fails; this avoids stranding inputs in a hidden
	// directory that the regular indexing loop cannot discover.
	published := false
	defer func() {
		if published {
			return
		}
		files, readErr := os.ReadDir(staging)
		if readErr != nil {
			bedSet.Logger.Error().Err(readErr).Msg("cannot inspect failed legacy staging batch")
			return
		}
		for _, file := range files {
			if err := os.Rename(filepath.Join(staging, file.Name()), filepath.Join(p.cacheDir(), file.Name())); err != nil {
				bedSet.Logger.Error().Err(err).Msg("cannot restore failed legacy cache batch")
			}
		}
		if err := os.Remove(staging); err != nil {
			bedSet.Logger.Error().Err(err).Msg("failed to remove legacy staging directory")
		}
	}()
	entries, err := os.ReadDir(p.cacheDir())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || (!shaName.MatchString(entry.Name()) && !strings.HasSuffix(entry.Name(), metaSuffix)) {
			continue
		}
		if err := os.Rename(filepath.Join(p.cacheDir(), entry.Name()), filepath.Join(staging, entry.Name())); err != nil {
			return fmt.Errorf("move legacy cache file to %s: %w", staging, err)
		}
	}
	if err := os.Rename(staging, ready); err != nil {
		return fmt.Errorf("publish legacy batch %s: %w", staging, err)
	}
	published = true
	return nil
}

// addSingleBatchDummy satisfies BigGrep's two-file minimum within a partition.
func (p *Pipeline) addSingleBatchDummy(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && shaName.MatchString(entry.Name()) {
			count++
		}
	}
	if count != 1 {
		return nil
	}
	dummy := []byte("dummy-file")
	digest := sha256.Sum256(dummy)
	name := hex.EncodeToString(digest[:])
	dataPath := filepath.Join(dir, name)
	if _, err := os.Stat(dataPath); err == nil {
		dummy = []byte("dummy-file-2")
		digest = sha256.Sum256(dummy)
		name = hex.EncodeToString(digest[:])
		dataPath = filepath.Join(dir, name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(dataPath, dummy, 0664); err != nil {
		return err
	}
	meta, err := json.Marshal(Metadata{StreamLabel: "content", StreamSource: "testing", Synthetic: true})
	if err != nil {
		return err
	}
	return os.WriteFile(dataPath+metaSuffix, meta, 0664)
}

// Flush stages the current cache as an ordinary size-based index (useful for shutdown/manual tests).
func (p *Pipeline) Flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rotateCache()
}

// PeriodicCopy flushes the active cache as an ordinary ready batch.
// The name is retained for compatibility with existing callers. Unlike the
// previous snapshot implementation, this does not duplicate binaries on the PVC
// or leave the same data in the active cache for re-indexing.
func (p *Pipeline) PeriodicCopy() error {
	if p.Config.Periodic <= 0 {
		return nil
	}
	return p.rotateCache()
}

// MaybePeriodic serialises snapshot creation with incoming content writes.
func (p *Pipeline) MaybePeriodic() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Config.Periodic <= 0 || time.Since(p.lastPeriodic) < p.Config.Periodic {
		return nil
	}
	if err := p.PeriodicCopy(); err != nil {
		return err
	}
	p.lastPeriodic = time.Now()
	return nil
}
