// Package indexstorage publishes and fetches immutable BigGrep index files.
//
// BigGrep requires a local .bgi file for mmap-based searching. This package
// deliberately keeps object storage and caching outside the BigGrep engine.
package indexstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	bedSet "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/settings"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/store"
)

const (
	// Source and Label form the shared object namespace: retrohunt/indices/.
	defaultSource = "retrohunt"
	defaultLabel  = "indices"
	markerSuffix  = ".ready"
)

var validID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Manager stores content-addressed indexes using Bedrock's FileStorage interface.
// IDs are SHA-256 digests, so publication can be safely retried.
// Source and Label are configurable so the publisher and fetcher can share
// one namespace without assuming the rest of Azul uses the same bucket layout.
type Manager struct {
	Storage store.FileStorage
	Source  string
	Label   string
}

func (m Manager) location() (string, string) {
	source, label := m.Source, m.Label
	if source == "" {
		source = defaultSource
	}
	if label == "" {
		label = defaultLabel
	}
	return source, label
}

func checkID(id string) error {
	if !validID.MatchString(id) {
		return fmt.Errorf("invalid index ID %q: expected 64 lowercase hexadecimal characters", id)
	}
	return nil
}

// HashFile streams the input file. It never reads the whole index into RAM.
func HashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			bedSet.Logger.Error().Err(err).Str("path", path).Msg("failed to close index file after hashing")
		}
	}()
	h := sha256.New()
	n, err := io.Copy(h, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Put publishes an index in two stages: the content object first, then a tiny
// ready marker. List ignores uncommitted content objects. BigGrep can never
// discover an index until its upload has completed successfully.
//
// Index objects are named by their SHA-256 digest rather than a mutable path.
// This protects running hunts from a writer replacing an index underneath them.
//
// Put retains the original index-only API for legacy index producers.
func (m Manager) Put(path string) (string, error) {
	return m.PutWithMetadata(path, "")
}

// PutWithMetadata optionally publishes a JSON summary as <sha256>.meta.json.
// When present, the summary is uploaded after index content and before .ready.
// A repeated publication can repair a missing summary without uploading the index.
// Legacy indexes without
// sidecars remain searchable, and consumers must treat missing metadata as
// unknown rather than as grounds for excluding an index.
func (m Manager) PutWithMetadata(path, summaryPath string) (string, error) {

	source, label := m.location()
	id, size, err := HashFile(path)
	if err != nil {
		return "", fmt.Errorf("hash index: %w", err)
	}
	if size == 0 {
		return "", errors.New("refusing to publish an empty index")
	}
	if !strings.HasSuffix(strings.ToLower(path), ".bgi") {
		return "", errors.New("input must have a .bgi extension")
	}
	object := id + ".bgi"
	ready, err := m.Storage.Exists(source, label, id+markerSuffix)
	if err != nil {
		return "", fmt.Errorf("check publication: %w", err)
	}
	// Optional metadata is bound to the immutable index content hash.
	var sidecar []byte
	if summaryPath != "" {
		if raw, readErr := os.ReadFile(summaryPath); readErr == nil {
			var doc struct {
				SchemaVersion int    `json:"schema_version"`
				FileCount     int64  `json:"file_count"`
				MinFileSize   int64  `json:"min_file_size"`
				MaxFileSize   int64  `json:"max_file_size"`
				IndexSHA256   string `json:"index_sha256"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return "", fmt.Errorf("parse index summary: %w", err)
			}
			if (doc.SchemaVersion != 1 && doc.SchemaVersion != 2) || doc.FileCount <= 0 || doc.MinFileSize < 0 || doc.MaxFileSize < doc.MinFileSize || (doc.IndexSHA256 != "" && doc.IndexSHA256 != id) {
				return "", errors.New("invalid index summary")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				return "", err
			}
			fields["index_sha256"], _ = json.Marshal(id)
			sidecar, err = json.Marshal(fields)
			if err != nil {
				return "", err
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return "", readErr
		}
	}
	if ready {
		if len(sidecar) > 0 {
			// Retry a missing sidecar even if an older upload already has .ready.
			metaReady, err := m.Storage.Exists(source, label, id+".meta.json")
			if err != nil {
				return "", err
			}
			if !metaReady {
				if err := m.Storage.Put(source, label, id+".meta.json", io.NopCloser(strings.NewReader(string(sidecar))), int64(len(sidecar))); err != nil {
					return "", fmt.Errorf("upload index metadata: %w", err)
				}
			}
		}
		return id, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	// Pass the known file size so Bedrock's S3 implementation can use its
	// bounded-memory multipart uploader for large indexes.
	err = m.Storage.Put(source, label, object, file, size)
	closeErr := file.Close()
	if err != nil {
		return "", fmt.Errorf("upload index: %w", err)
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(sidecar) > 0 {
		// Retry a missing sidecar even if an older upload already has .ready.
		metaReady, err := m.Storage.Exists(source, label, id+".meta.json")
		if err != nil {
			return "", err
		}
		if !metaReady {
			if err := m.Storage.Put(source, label, id+".meta.json", io.NopCloser(strings.NewReader(string(sidecar))), int64(len(sidecar))); err != nil {
				return "", fmt.Errorf("upload index metadata: %w", err)
			}
		}
	}
	// The marker is small and only created after the object upload succeeded.
	// Readers additionally verify its content and the complete object digest.
	marker := io.NopCloser(strings.NewReader(id + "\n"))
	if err := m.Storage.Put(source, label, id+markerSuffix, marker, int64(len(id)+1)); err != nil {
		return "", fmt.Errorf("index uploaded but publication marker failed (retry is safe): %w", err)
	}
	return id, nil
}

// List returns published IDs. Object listing can be streamed by providers;
// only the short identifiers are accumulated here, not index contents.
func (m Manager) List(ctx context.Context) ([]string, error) {
	source, label := m.location()
	var result []string
	for entry := range m.Storage.List(ctx, source+"/"+label+"/", "") {
		if entry.Err != nil {
			return nil, entry.Err
		}
		if !strings.HasSuffix(entry.Key, markerSuffix) {
			continue
		}
		id := strings.TrimSuffix(filepath.Base(entry.Key), markerSuffix)
		if checkID(id) == nil {
			result = append(result, id)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Strings(result)
	return result, nil
}

// Fetch atomically ensures a verified local index at output. An advisory
// filesystem lock serializes processes downloading the same index to the same
// path, preventing redundant network transfers and partially visible files.
// The lock file must live on a filesystem supporting flock (Linux pods do).
func (m Manager) Fetch(id, output string) error {
	source, label := m.location()
	if err := checkID(id); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		return err
	}
	lock, err := os.OpenFile(output+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			bedSet.Logger.Error().Err(err).Str("path", output+".lock").Msg("failed to close index cache lock file")
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() {
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
			bedSet.Logger.Error().Err(err).Str("path", output+".lock").Msg("failed to release index cache lock")
		}
	}()

	// Validate the cached copy before making network requests. This costs one
	// sequential disk scan, but avoids trusting a corrupt or truncated cache.
	if digest, size, err := HashFile(output); err == nil && size > 0 && digest == id {
		return nil
	}

	// Reject unpublished objects; a writer may still be uploading their data.
	marker, err := m.Storage.Fetch(source, label, id+markerSuffix)
	if err != nil {
		return fmt.Errorf("index %s is not published: %w", id, err)
	}
	markerBytes, readErr := io.ReadAll(io.LimitReader(marker.DataReader, 128))
	closeErr := marker.DataReader.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if strings.TrimSpace(string(markerBytes)) != id {
		return errors.New("invalid publication marker")
	}

	data, err := m.Storage.Fetch(source, label, id+".bgi")
	if err != nil {
		return fmt.Errorf("fetch index: %w", err)
	}
	defer func() {
		if err := data.DataReader.Close(); err != nil {
			bedSet.Logger.Error().Err(err).Str("index_id", id).Msg("failed to close downloaded index stream")
		}
	}()
	if data.Avail <= 0 {
		return errors.New("empty index object")
	}
	// Write in the destination directory so rename is atomic on the same volume.
	tmp, err := os.CreateTemp(filepath.Dir(output), ".bgi-download-*")
	if err != nil {
		return err
	}
	// Keep cleanup safe on both the error path and the successful rename path.
	// Closing explicitly before rename helps detect buffered filesystem errors.
	tmpPath := tmp.Name()
	tmpClosed := false
	defer func() {
		if !tmpClosed {
			if err := tmp.Close(); err != nil {
				bedSet.Logger.Error().Err(err).Str("path", tmpPath).Msg("failed to close temporary index download")
			}
		}
		if err := os.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			bedSet.Logger.Error().Err(err).Str("path", tmpPath).Msg("failed to remove temporary index download")
		}
	}()
	if err := tmp.Chmod(0640); err != nil {
		return err
	}
	h := sha256.New()
	copied, err := io.Copy(io.MultiWriter(tmp, h), data.DataReader)
	if err != nil {
		return fmt.Errorf("stream index: %w", err)
	}
	if copied != data.Avail {
		return fmt.Errorf("truncated download: got %d bytes, expected %d", copied, data.Avail)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != id {
		return fmt.Errorf("index checksum mismatch: expected %s, got %s", id, got)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	closeErr = tmp.Close()
	tmpClosed = true
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp.Name(), output); err != nil {
		return err
	}
	return nil
}
