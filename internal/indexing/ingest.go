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
	"time"
)

const MinDataSize = 4
const metaSuffix = "-meta"

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
	defer os.Remove(tmpName)
	h := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, p.Config.MaxBytes+1))
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
		os.Remove(dest)
		return false, err
	}
	metaName := metaTmp.Name()
	defer os.Remove(metaName)
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
		os.Remove(dest)
		return false, err
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
func (p *Pipeline) rotateCache() error {
	bytes, err := p.CacheBytes()
	if err != nil {
		return err
	}
	if bytes == 0 {
		return nil
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

// Flush stages the current cache as an ordinary size-based index (useful for shutdown/manual tests).
func (p *Pipeline) Flush() error { return p.rotateCache() }

// PeriodicCopy snapshots the current cache without removing it (the Python behaviour).
func (p *Pipeline) PeriodicCopy() error {
	if p.Config.Periodic <= 0 {
		return nil
	}
	entries, err := os.ReadDir(p.cacheDir())
	if err != nil {
		return err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !strings.HasSuffix(e.Name(), metaSuffix) {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	parent, err := p.nextReadyDir()
	if err != nil {
		return err
	}
	dest := filepath.Join(filepath.Dir(parent), "periodic")
	if _, err := os.Stat(dest); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	staging := filepath.Join(p.stateDir(), "periodic-stash")
	os.RemoveAll(staging)
	if err := os.MkdirAll(staging, 02775); err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		from := filepath.Join(p.cacheDir(), e.Name())
		to := filepath.Join(staging, e.Name())
		if err := copyFile(from, to); err != nil {
			return err
		}
	}
	// Like the Python implementation, add a dummy entry when the periodic
	// snapshot contains exactly one real binary. Keep the active cache intact.
	if n == 1 {
		dummy := []byte("dummy-file")
		hash := sha256.Sum256(dummy)
		stem := hex.EncodeToString(hash[:])
		if err := os.WriteFile(filepath.Join(staging, stem), dummy, 0664); err != nil {
			return err
		}
		meta, err := json.Marshal(Metadata{StreamLabel: "content", StreamSource: "testing"})
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(staging, stem+metaSuffix), meta, 0664); err != nil {
			return err
		}
	}
	return os.Rename(staging, dest)
}
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0664)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if e := out.Close(); err == nil {
		err = e
	}
	return err
}
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
