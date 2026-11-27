package indexstorage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/store"
)

func TestIndexMetadataPublishedBeforeReady(t *testing.T) {
	backend, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := Manager{Storage: backend}
	dir := t.TempDir()
	path := filepath.Join(dir, "batch.bgi")
	if err := os.WriteFile(path, []byte("example index data"), 0600); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(dir, "batch.meta.json")
	if err := os.WriteFile(meta, []byte(`{"schema_version":1,"file_count":3,"min_file_size":12,"max_file_size":120,"stream_labels":["content"],"stream_sources":["testing"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	id, err := m.PutWithMetadata(path, meta)
	if err != nil {
		t.Fatal(err)
	}
	src, label := m.location()
	exists, err := backend.Exists(src, label, id+".meta.json")
	if err != nil || !exists {
		t.Fatalf("metadata missing: %v", err)
	}
	exists, err = backend.Exists(src, label, id+".ready")
	if err != nil || !exists {
		t.Fatalf("ready marker missing: %v", err)
	}
	reader, err := backend.Fetch(src, label, id+".meta.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.DataReader.Close(); err != nil {
			t.Errorf("failed to close data reader: %v", err)
		}
	}()
	var got struct {
		IndexSHA256 string `json:"index_sha256"`
	}
	if err := json.NewDecoder(reader.DataReader).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.IndexSHA256 != id {
		t.Fatalf("summary not bound to index: %q", got.IndexSHA256)
	}
}
