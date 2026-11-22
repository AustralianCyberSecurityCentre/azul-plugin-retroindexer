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
}

func (m Metadata) Format() string {
	out := "stream_label=" + m.StreamLabel + ",stream_source=" + m.StreamSource
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
func (p *Pipeline) CacheBytes() (int64, error) {
	entries, err := os.ReadDir(p.cacheDir())
	if err != nil {
		return 0, err
	}
	var sum int64
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), metaSuffix) || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		st, err := e.Info()
		if err != nil {
			return 0, err
		}
		sum += st.Size()
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
	dest := filepath.Join(p.cacheDir(), name)
	if _, err := os.Stat(dest); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	cached, err := p.CacheBytes()
	if err != nil {
		return false, err
	}
	// Rotate the existing batch before admitting a file that would exceed the limit.
	if cached+size > p.Config.MaxBytes && cached > 0 {
		if err := p.rotateCache(); err != nil {
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
	metaTmp, err := os.CreateTemp(p.cacheDir(), ".meta-")
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
	if cachedNow, err := p.CacheBytes(); err != nil {
		return true, err
	} else if cachedNow >= p.Config.MaxBytes {
		if err := p.rotateCache(); err != nil {
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

// rotateCache atomically moves the active cache to a numbered ready directory.
func (p *Pipeline) rotateCache() error {
	bytes, err := p.CacheBytes()
	if err != nil {
		return err
	}
	if bytes == 0 {
		return nil
	}
	// BigGrep needs at least two input entries. Preserve the original
	// periodic behaviour for all single-binary batches (including size-triggered
	// rotations) by adding a synthetic second entry to the batch.
	if err := p.addSingleBatchDummy(); err != nil {
		return err
	}
	ready, err := p.nextReadyDir()
	if err != nil {
		return err
	}
	if err := os.Rename(p.cacheDir(), ready); err != nil {
		return err
	}
	return os.MkdirAll(p.cacheDir(), 02775)
}

// addSingleBatchDummy ensures the BigGrep builder gets two input entries.
// The dummy is deterministic and is never added when two real files are present.
func (p *Pipeline) addSingleBatchDummy() error {
	entries, err := os.ReadDir(p.cacheDir())
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
	dataPath := filepath.Join(p.cacheDir(), name)
	if _, err := os.Stat(dataPath); err == nil {
		// The real content happens to equal the synthetic marker.
		dummy = []byte("dummy-file-2")
		digest = sha256.Sum256(dummy)
		name = hex.EncodeToString(digest[:])
		dataPath = filepath.Join(p.cacheDir(), name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(dataPath, dummy, 0664); err != nil {
		return err
	}
	meta, err := json.Marshal(Metadata{StreamLabel: "content", StreamSource: "testing"})
	if err != nil {
		return err
	}
	return os.WriteFile(dataPath+metaSuffix, meta, 0664)
}

// Flush stages the current cache as an ordinary size-based index (useful for shutdown/manual tests).
func (p *Pipeline) Flush() error { return p.rotateCache() }

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
