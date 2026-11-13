package storage

import (
	"strings"
	"testing"
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
