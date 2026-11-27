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
	"path"
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

var validFileTypes = map[string]bool{
	"windows": true, "elf": true, "macho": true, "mobile": true,
	"bytecode": true, "document": true, "archive": true, "script": true,
	"image": true, "audio": true, "video": true, "executable-other": true,
	"unknown": true, "other": true, "mixed": true,
}
var validSizeClasses = map[string]bool{
	"lt1m": true, "1m-10m": true, "10m-100m": true, "gte100m": true, "mixed": true,
}

// Entry identifies a committed index and its storage prefix. Use the full
// object key when downloading: IDs alone cannot identify a partition.
type Entry struct {
	ID     string
	Prefix string
}

func (e Entry) key(suffix string) string {
	if e.Prefix == "" {
		return e.ID + suffix
	}
	return e.Prefix + "/" + e.ID + suffix
}

func partitionPrefix(fileType, sizeClass string) (string, error) {
	if !validFileTypes[fileType] || !validSizeClasses[sizeClass] ||
		(fileType == "mixed") != (sizeClass == "mixed") {
		return "", fmt.Errorf("invalid index partition %q/%q", fileType, sizeClass)
	}
	return fileType + "/" + sizeClass, nil
}

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
	entry := Entry{ID: id}
	// Metadata determines the partition; legacy indexes retain their flat layout.
	// Do not advertise a partition without a valid sidecar.
	var sidecar []byte
	if summaryPath != "" {
		raw, readErr := os.ReadFile(summaryPath)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return "", readErr
		}
		if readErr == nil {
			var doc struct {
				SchemaVersion int    `json:"schema_version"`
				FileCount     int64  `json:"file_count"`
				MinFileSize   int64  `json:"min_file_size"`
				MaxFileSize   int64  `json:"max_file_size"`
				IndexSHA256   string `json:"index_sha256"`
				FileTypeGroup string `json:"file_type_group"`
				SizeClass     string `json:"size_class"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return "", fmt.Errorf("parse index summary: %w", err)
			}
			if (doc.SchemaVersion != 1 && doc.SchemaVersion != 2) || doc.FileCount <= 0 || doc.MinFileSize < 0 || doc.MaxFileSize < doc.MinFileSize || (doc.IndexSHA256 != "" && doc.IndexSHA256 != id) {
				return "", errors.New("invalid index summary")
			}
			if doc.SchemaVersion == 2 {
				prefix, err := partitionPrefix(doc.FileTypeGroup, doc.SizeClass)
				if err != nil {
					return "", err
				}
				entry.Prefix = prefix
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
		}
	}
	object := entry.key(".bgi")
	ready, err := m.Storage.Exists(source, label, entry.key(markerSuffix))
	if err != nil {
		return "", fmt.Errorf("check publication: %w", err)
	}
	if ready {
		if len(sidecar) > 0 {
			// Retry a missing sidecar even if an older upload already has .ready.
			metaReady, err := m.Storage.Exists(source, label, entry.key(".meta.json"))
			if err != nil {
				return "", err
			}
			if !metaReady {
				if err := m.Storage.Put(source, label, entry.key(".meta.json"), io.NopCloser(strings.NewReader(string(sidecar))), int64(len(sidecar))); err != nil {
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
		metaReady, err := m.Storage.Exists(source, label, entry.key(".meta.json"))
		if err != nil {
			return "", err
		}
		if !metaReady {
			if err := m.Storage.Put(source, label, entry.key(".meta.json"), io.NopCloser(strings.NewReader(string(sidecar))), int64(len(sidecar))); err != nil {
				return "", fmt.Errorf("upload index metadata: %w", err)
			}
		}
	}
	// The marker is small and only created after the object upload succeeded.
	// Readers additionally verify its content and the complete object digest.
	marker := io.NopCloser(strings.NewReader(id + "\n"))
	if err := m.Storage.Put(source, label, entry.key(markerSuffix), marker, int64(len(id)+1)); err != nil {
		return "", fmt.Errorf("index uploaded but publication marker failed (retry is safe): %w", err)
	}
	return id, nil
}

// ListPartition lists one type/size prefix without requesting index bodies.
// A hunt can call this for only the compatible partitions.
func (m Manager) ListPartition(ctx context.Context, fileType, sizeClass string) ([]Entry, error) {
	prefix, err := partitionPrefix(fileType, sizeClass)
	if err != nil {
		return nil, err
	}
	return m.listAtPrefix(ctx, prefix)
}

// ListEntries finds ready markers across legacy and partitioned locations.
func (m Manager) ListEntries(ctx context.Context) ([]Entry, error) {
	return m.listAtPrefix(ctx, "")
}

// relativeIndexKey handles both cloud object keys and absolute filesystem
// paths returned by Bedrock's local store, without accepting another namespace.
func relativeIndexKey(key, base string) (string, bool) {
	key = filepath.ToSlash(key)
	if strings.HasPrefix(key, base) {
		return strings.TrimPrefix(key, base), true
	}
	boundary := "/" + base
	pos := strings.LastIndex(key, boundary)
	if pos < 0 {
		return "", false
	}
	return key[pos+len(boundary):], true
}

func (m Manager) listAtPrefix(ctx context.Context, filter string) ([]Entry, error) {
	source, label := m.location()
	base := source + "/" + label + "/"
	prefix := base
	if filter != "" {
		prefix += filter + "/"
	}
	var result []Entry
	for object := range m.Storage.List(ctx, prefix, "") {
		if object.Err != nil {
			return nil, object.Err
		}
		if !strings.HasSuffix(object.Key, markerSuffix) {
			continue
		}
		relative, ok := relativeIndexKey(object.Key, base)
		if !ok {
			continue
		}
		key := strings.TrimSuffix(relative, markerSuffix)
		id := path.Base(key)
		if checkID(id) != nil {
			continue
		}
		prefix := path.Dir(key)
		if prefix == "." {
			prefix = ""
		} else {
			pieces := strings.Split(prefix, "/")
			if len(pieces) != 2 {
				continue
			}
			if _, err := partitionPrefix(pieces[0], pieces[1]); err != nil {
				continue
			}
		}
		result = append(result, Entry{ID: id, Prefix: prefix})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Prefix != result[j].Prefix {
			return result[i].Prefix < result[j].Prefix
		}
		return result[i].ID < result[j].ID
	})
	return result, nil
}

// List retains the older ID-only interface. For partition-aware consumers,
// ListEntries and FetchEntry avoid ambiguous IDs and repeated discovery.
func (m Manager) List(ctx context.Context) ([]string, error) {
	entries, err := m.ListEntries(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !seen[entry.ID] {
			ids = append(ids, entry.ID)
			seen[entry.ID] = true
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Fetch resolves a legacy ID across both layouts. New readers should retain
// the Entry returned by ListEntries and call FetchEntry directly.
func (m Manager) Fetch(id, output string) error {
	if err := checkID(id); err != nil {
		return err
	}
	entries, err := m.ListEntries(context.Background())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.ID == id {
			return m.FetchEntry(entry, output)
		}
	}
	return fmt.Errorf("index %s is not published", id)
}

// Fetch atomically ensures a verified local index at output. An advisory
// filesystem lock serializes processes downloading the same index to the same
// path, preventing redundant network transfers and partially visible files.
// The lock file must live on a filesystem supporting flock (Linux pods do).
func (m Manager) FetchEntry(entry Entry, output string) error {
	source, label := m.location()
	id := entry.ID
	if entry.Prefix != "" {
		pieces := strings.Split(entry.Prefix, "/")
		if len(pieces) != 2 {
			return errors.New("invalid index prefix")
		}
		if _, err := partitionPrefix(pieces[0], pieces[1]); err != nil {
			return err
		}
	}
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
	marker, err := m.Storage.Fetch(source, label, entry.key(markerSuffix))
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

	data, err := m.Storage.Fetch(source, label, entry.key(".bgi"))
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
