package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/store"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/indexstorage"
)

func TestStorageDisabledByDefault(t *testing.T) {
	t.Setenv("RETROINDEXER_STORAGE_BACKEND", "none")
	got, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got.Backend != "none" {
		t.Fatalf("backend %q", got.Backend)
	}
	pub, err := New(got)
	if err != nil || pub != nil {
		t.Fatalf("expected disabled publisher, got %v, %v", pub, err)
	}
}

func TestAzureValidation(t *testing.T) {
	t.Setenv("RETROINDEXER_STORAGE_BACKEND", "azure")
	t.Setenv("RETROINDEXER_STORAGE_BUCKET", "retrohunt-indexes")
	t.Setenv("RETROINDEXER_STORAGE_ENDPOINT", "http://example.blob.core.windows.net/")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https validation, got %v", err)
	}
	t.Setenv("RETROINDEXER_STORAGE_ENDPOINT", "https://example.blob.core.windows.net/")
	s, err := FromEnv()
	if err != nil || s.Backend != "azure" {
		t.Fatalf("unexpected %v %+v", err, s)
	}
}

func TestS3Validation(t *testing.T) {
	t.Setenv("RETROINDEXER_STORAGE_BACKEND", "s3")
	t.Setenv("RETROINDEXER_STORAGE_BUCKET", "retrohunt-indexes")
	t.Setenv("RETROINDEXER_S3_ACCESS_KEY", "test")
	t.Setenv("RETROINDEXER_S3_SECRET_KEY", "")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected rejected partial credentials")
	}
	t.Setenv("RETROINDEXER_S3_SECRET_KEY", "test-secret")
	t.Setenv("RETROINDEXER_STORAGE_PREFIX", "../unsafe")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected rejected unsafe prefix")
	}
	t.Setenv("RETROINDEXER_STORAGE_PREFIX", "retrohunt/indices")
	got, err := FromEnv()
	if err != nil || got.Prefix != "retrohunt/indices" {
		t.Fatalf("unexpected %v %+v", err, got)
	}
}

// TestPublisherUsesRetrohuntProtocol guards against accidentally reverting to
// the old timestamp-and-processor naming scheme. Retrohunt must be able to
// discover and fetch every index published by Retroindexer.
func TestPublisherUsesRetrohuntProtocol(t *testing.T) {
	backend, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publisher := &Publisher{backend: backend, prefix: "retrohunt/indices"}
	index := filepath.Join(t.TempDir(), "batch.bgi")
	if err := os.WriteFile(index, []byte("example index bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	object, err := publisher.UploadFile(index, "content")
	if err != nil {
		t.Fatal(err)
	}
	manager := indexstorage.Manager{Storage: backend, Source: "retrohunt", Label: "indices"}
	ids, err := manager.List(context.Background())
	if err != nil || len(ids) != 1 {
		t.Fatalf("published indexes: %v (%v)", ids, err)
	}
	if object != "retrohunt/indices/"+ids[0]+".bgi" {
		t.Fatalf("wrong object key %q", object)
	}
	fetched := filepath.Join(t.TempDir(), "fetched.bgi")
	if err := manager.Fetch(ids[0], fetched); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(index)
	downloaded, _ := os.ReadFile(fetched)
	if !bytes.Equal(original, downloaded) {
		t.Fatal("retrieved bytes differ")
	}
}

func TestParseLocation(t *testing.T) {
	for _, raw := range []string{"../bad/path", "onlyone", "retrohunt//indices", "retrohunt/../indices"} {
		if _, _, err := ParseLocation(raw); err == nil {
			t.Fatalf("expected invalid prefix: %s", raw)
		}
	}
	source, label, err := ParseLocation("retrohunt/indices")
	if err != nil || source != "retrohunt" || label != "indices" {
		t.Fatalf("location: %s/%s %v", source, label, err)
	}
}

func TestPublisherUsesPartitionedPrefix(t *testing.T) {
	backend, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publisher := &Publisher{backend: backend, prefix: "retrohunt/indices"}
	index := filepath.Join(t.TempDir(), "batch.bgi")
	if err := os.WriteFile(index, []byte("example partitioned index"), 0600); err != nil {
		t.Fatal(err)
	}
	metadata := strings.TrimSuffix(index, ".bgi") + ".meta.json"
	raw := `{"schema_version":2,"file_count":1,"min_file_size":10,"max_file_size":10,"file_type_group":"elf","size_class":"lt1m"}`
	if err := os.WriteFile(metadata, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := publisher.UploadFile(index, "content")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "retrohunt/indices/elf/lt1m/") {
		t.Fatalf("unexpected key %s", key)
	}
}
