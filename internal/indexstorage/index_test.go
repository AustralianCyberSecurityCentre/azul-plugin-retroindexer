package indexstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/store"
)

func TestLocalStoreRoundTripAndCacheRepair(t *testing.T) {
	root := t.TempDir()
	storage, err := store.NewLocalStore(filepath.Join(root, "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	m := Manager{Storage: storage}
	input := filepath.Join(root, "test.bgi")
	original := bytes.Repeat([]byte("abcxyz0123456789"), 1024)
	if err := os.WriteFile(input, original, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(original)
	expected := hex.EncodeToString(hash[:])
	id, err := m.Put(input)
	if err != nil {
		t.Fatal(err)
	}
	if id != expected {
		t.Fatalf("ID %s != %s", id, expected)
	}
	// Repeated publication of a content-addressed object is safe.
	if _, err := m.Put(input); err != nil {
		t.Fatal(err)
	}
	ids, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != id {
		t.Fatalf("unexpected published IDs: %v", ids)
	}
	output := filepath.Join(root, "cache", id+".bgi")
	if err := m.Fetch(id, output); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Fetch(id, output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("cache repair did not restore data")
	}
}

func TestUnpublishedIndexCannotBeFetched(t *testing.T) {
	storage, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := Manager{Storage: storage}
	data := []byte("incomplete")
	hash := sha256.Sum256(data)
	id := hex.EncodeToString(hash[:])
	if err := storage.Put(defaultSource, defaultLabel, id+".bgi", ioNopCloser(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	ids, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("unpublished ID visible: %v", ids)
	}
	if err := m.Fetch(id, filepath.Join(t.TempDir(), "output.bgi")); err == nil {
		t.Fatal("unpublished fetch should fail")
	}
}

func TestConcurrentFetchSameDestination(t *testing.T) {
	storage, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := Manager{Storage: storage}
	input := filepath.Join(t.TempDir(), "input.bgi")
	if err := os.WriteFile(input, bytes.Repeat([]byte("z"), 8192), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := m.Put(input)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "index.bgi")
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- m.Fetch(id, output) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if digest, _, err := HashFile(output); err != nil || digest != id {
		t.Fatalf("output corrupted: %s %v", digest, err)
	}
}

func TestRejectPathTraversal(t *testing.T) {
	for _, s := range []string{"../foo", "ABC", strings.Repeat("a", 63)} {
		if checkID(s) == nil {
			t.Fatalf("invalid ID accepted: %s", s)
		}
	}
}

func ioNopCloser(b []byte) *nopCloser { return &nopCloser{bytes.NewReader(b)} }

type nopCloser struct{ *bytes.Reader }

func (*nopCloser) Close() error { return nil }

// TestPartitionedPublication verifies that object prefixes are queryable
// without downloading an index and that legacy indexes remain discoverable.
func TestPartitionedPublication(t *testing.T) {
	backend, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := Manager{Storage: backend}
	input := filepath.Join(t.TempDir(), "pe.bgi")
	if err := os.WriteFile(input, []byte("partitioned index"), 0600); err != nil {
		t.Fatal(err)
	}
	summaryPath := strings.TrimSuffix(input, ".bgi") + ".meta.json"
	summary := `{"schema_version":2,"file_count":1,"min_file_size":1024,"max_file_size":1024,"file_type_group":"windows","size_class":"lt1m"}`
	if err := os.WriteFile(summaryPath, []byte(summary), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := manager.PutWithMetadata(input, summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".bgi", ".meta.json", ".ready"} {
		found, err := backend.Exists(defaultSource, defaultLabel, "windows/lt1m/"+id+suffix)
		if err != nil || !found {
			t.Fatalf("missing partition object %s: %v", suffix, err)
		}
	}
	entries, err := manager.ListEntries(context.Background())
	if err != nil || len(entries) != 1 || entries[0].Prefix != "windows/lt1m" {
		t.Fatalf("unexpected entries: %+v, %v", entries, err)
	}
	if err := manager.FetchEntry(entries[0], filepath.Join(t.TempDir(), "download.bgi")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Fetch(id, filepath.Join(t.TempDir(), "legacy-api.bgi")); err != nil {
		t.Fatal(err)
	}
}

func TestRejectInvalidPartition(t *testing.T) {
	backend, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := Manager{Storage: backend}
	input := filepath.Join(t.TempDir(), "test.bgi")
	if err := os.WriteFile(input, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	meta := strings.TrimSuffix(input, ".bgi") + ".meta.json"
	if err := os.WriteFile(meta, []byte(`{"schema_version":2,"file_count":1,"min_file_size":1,"max_file_size":1,"file_type_group":"../evil","size_class":"lt1m"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PutWithMetadata(input, meta); err == nil {
		t.Fatal("unsafe partition accepted")
	}
}

func TestListPartitionExcludesOtherPrefixes(t *testing.T) {
	backend, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := Manager{Storage: backend}
	for _, part := range []string{"windows/lt1m", "elf/lt1m", "windows/1m-10m"} {
		ready := strings.Repeat("a", 64) + ".ready"
		content := []byte(strings.Repeat("a", 64) + "\n")
		if err := backend.Put(defaultSource, defaultLabel, part+"/"+ready, ioNopCloser(content), int64(len(content))); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := manager.ListPartition(context.Background(), "windows", "lt1m")
	if err != nil || len(entries) != 1 || entries[0].Prefix != "windows/lt1m" {
		t.Fatalf("unexpected partition listing %+v: %v", entries, err)
	}
	if _, err := manager.ListPartition(context.Background(), "../bad", "lt1m"); err == nil {
		t.Fatal("invalid partition accepted")
	}
}

// TestRelativeIndexKey covers both key formats returned by Bedrock backends.
func TestRelativeIndexKey(t *testing.T) {
	const base = "retrohunt/indices/"
	const filename = "windows/lt1m/" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + ".ready"
	for _, tc := range []struct {
		name string
		key  string
		want string
		ok   bool
	}{
		{name: "cloud partition", key: base + filename, want: filename, ok: true},
		{name: "filesystem partition", key: "/tmp/object-store/" + base + filename, want: filename, ok: true},
		{name: "cloud legacy", key: base + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ready", want: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ready", ok: true},
		{name: "filesystem legacy", key: "/tmp/object-store/" + base + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ready", want: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ready", ok: true},
		{name: "wrong namespace", key: "another/indices/" + filename, ok: false},
		{name: "partial namespace", key: "/tmp/notretrohunt/indices/" + filename, ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := relativeIndexKey(tc.key, base)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("relativeIndexKey(%q) = %q, %t; want %q, %t", tc.key, got, ok, tc.want, tc.ok)
			}
		})
	}
}
