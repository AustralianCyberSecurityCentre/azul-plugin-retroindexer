package indexing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPipeline(t *testing.T, max int64) *Pipeline {
	t.Helper()
	p, err := New(Config{Root: t.TempDir(), Name: "content", StreamLabels: map[string]bool{"content": true}, MaxBytes: max, Timeout: time.Minute, Periodic: time.Hour, Poll: time.Second, Bigindex: "bgindex", SplitOnFailure: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestIngestRotateAndMetadata(t *testing.T) {
	p := testPipeline(t, 10)
	m := Metadata{StreamLabel: "content", StreamSource: "testing"}
	added, err := p.AddStream(strings.NewReader("first!"), m)
	if err != nil || !added {
		t.Fatalf("first: %v %v", added, err)
	}
	added, err = p.AddStream(strings.NewReader("first!"), m)
	if err != nil || added {
		t.Fatalf("duplicate: %v %v", added, err)
	}
	added, err = p.AddStream(strings.NewReader("second"), m)
	if err != nil || !added {
		t.Fatalf("second: %v %v", added, err)
	}
	dirs, err := p.ReadyDirs()
	if err != nil || len(dirs) != 1 {
		t.Fatalf("ready directories: %v %v", dirs, err)
	}
	hash := sha256.Sum256([]byte("first!"))
	meta, err := os.ReadFile(filepath.Join(dirs[0], hex.EncodeToString(hash[:])+"-meta"))
	if err != nil || !bytes.Contains(meta, []byte("stream_source")) {
		t.Fatalf("metadata: %s %v", meta, err)
	}
	if b, _ := p.CacheBytes(); b != 6 {
		t.Fatalf("unexpected cache bytes %d", b)
	}
}
func TestGenerateUsingFakeBigindex(t *testing.T) {
	p := testPipeline(t, 1024)
	m := Metadata{StreamLabel: "content", StreamSource: "testing"}
	for _, s := range []string{"alpha", "beta"} {
		if _, err := p.AddStream(strings.NewReader(s), m); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "bgindex")
	script := `#!/bin/sh
set -eu
[ "$1" = "-p" ] || exit 1
base="$2"
cat > "${base}.bgi"
`
	if err := os.WriteFile(tool, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	p.Config.Bigindex = tool
	n, err := p.IndexReady(context.Background(), nil)
	if err != nil || n != 1 {
		t.Fatalf("indexed %d err %v", n, err)
	}
	files, err := os.ReadDir(p.bgiDir())
	if err != nil || len(files) != 1 {
		t.Fatalf("indexes: %v %v", files, err)
	}
	data, err := os.ReadFile(filepath.Join(p.bgiDir(), files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "stream_label=content,stream_source=testing") || !strings.Contains(string(data), "\n") {
		t.Fatalf("unexpected BigGrep input: %s", data)
	}
	ready, _ := p.ReadyDirs()
	if len(ready) != 0 {
		t.Fatalf("ready directories were not cleaned: %v", ready)
	}
}
func TestFailedBuildRetainsInputs(t *testing.T) {
	p := testPipeline(t, 1024)
	if _, err := p.AddStream(strings.NewReader("hello world"), Metadata{StreamLabel: "content", StreamSource: "testing"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	p.Config.Bigindex = filepath.Join(t.TempDir(), "missing")
	_, err := p.IndexReady(context.Background(), nil)
	if err == nil {
		t.Fatal("expected failure")
	}
	dirs, _ := p.ReadyDirs()
	if len(dirs) != 1 {
		t.Fatalf("indexing failure lost files %v", dirs)
	}
}
func TestPeriodicCopy(t *testing.T) {
	p := testPipeline(t, 1024)
	m := Metadata{StreamLabel: "content", StreamSource: "testing"}
	for _, s := range []string{"abcde", "xyz123"} {
		if _, err := p.AddStream(strings.NewReader(s), m); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.PeriodicCopy(); err != nil {
		t.Fatal(err)
	}
	ready, _ := p.ReadyDirs()
	if len(ready) != 1 || filepath.Base(ready[0]) != "periodic" {
		t.Fatalf("ready: %v", ready)
	}
	if size, _ := p.CacheBytes(); size != 11 {
		t.Fatalf("periodic copy modified live cache: %d", size)
	}
}
func TestSyncUploadsDeletesOnlyAfterSuccess(t *testing.T) {
	p := testPipeline(t, 1024)
	path := filepath.Join(p.bgiDir(), "completed.bgi")
	if err := os.WriteFile(path, []byte("index bytes"), 0664); err != nil {
		t.Fatal(err)
	}
	calls := 0
	uploader := func(string) error {
		calls++
		if calls == 1 {
			return os.ErrPermission
		}
		return nil
	}
	if _, err := p.SyncUploads("s3:test", uploader, false); err == nil {
		t.Fatal("expected failed upload")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("failed upload removed index: %v", err)
	}
	// Simulate a restart: a new Pipeline instance sees and retries the same local file.
	again, err := New(p.Config)
	if err != nil {
		t.Fatal(err)
	}
	n, err := again.SyncUploads("s3:test", uploader, false)
	if err != nil || n != 1 {
		t.Fatalf("publish n=%d err=%v", n, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("uploaded temporary index remains: %v", err)
	}
	n, err = again.SyncUploads("s3:test", uploader, false)
	if err != nil || n != 0 || calls != 2 {
		t.Fatalf("unexpected republish: n=%d err=%v calls=%d", n, err, calls)
	}
}
func TestSyncUploadsKeepLocalForTesting(t *testing.T) {
	p := testPipeline(t, 1024)
	path := filepath.Join(p.bgiDir(), "completed.bgi")
	if err := os.WriteFile(path, []byte("index bytes"), 0664); err != nil {
		t.Fatal(err)
	}
	n, err := p.SyncUploads("azure:test", func(string) error { return nil }, true)
	if err != nil || n != 1 {
		t.Fatalf("publish n=%d err=%v", n, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("testing mode should retain index: %v", err)
	}
	called := false
	n, err = p.SyncUploads("azure:test", func(string) error { called = true; return nil }, true)
	if err != nil || n != 0 || called {
		t.Fatalf("keep-local receipt should avoid repeated upload: n=%d err=%v called=%v", n, err, called)
	}
	if _, err := p.SyncUploads("", nil, false); err == nil {
		t.Fatal("missing cloud backend must fail")
	}
}
func TestPeriodicSingleFileGetsDummy(t *testing.T) {
	p := testPipeline(t, 1024)
	added, err := p.AddStream(strings.NewReader("hello"), Metadata{
		StreamLabel:  "content",
		StreamSource: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("expected stream to be added")
	}
	if err := p.PeriodicCopy(); err != nil {
		t.Fatal(err)
	}
	dirs, err := p.ReadyDirs()
	if err != nil || len(dirs) != 1 {
		t.Fatalf("ready %v %v", dirs, err)
	}
	entries, _ := os.ReadDir(dirs[0])
	if len(entries) != 4 {
		t.Fatalf("want binary+metadata pairs got %d", len(entries))
	}
}

func TestHistoricRequirementIsConfigurable(t *testing.T) {
	t.Setenv("RETROINDEXER_REQUIRE_HISTORIC", "false")
	cfg, err := FromEnv()
	if err != nil || cfg.RequireHistoric {
		t.Fatalf("default/live config: cfg=%+v err=%v", cfg, err)
	}
	t.Setenv("RETROINDEXER_REQUIRE_HISTORIC", "true")
	cfg, err = FromEnv()
	if err != nil || !cfg.RequireHistoric {
		t.Fatalf("historic config: cfg=%+v err=%v", cfg, err)
	}
}

// Periodic snapshots must not overwrite an index still awaiting cloud upload.
func TestPeriodicIndexesUseDistinctNames(t *testing.T) {
	p := testPipeline(t, 1024)
	for _, data := range []string{"alpha", "bravo"} {
		if _, err := p.AddStream(strings.NewReader(data), Metadata{StreamLabel: "content", StreamSource: "testing"}); err != nil {
			t.Fatal(err)
		}
	}
	tool := filepath.Join(t.TempDir(), "bgindex")
	script := "#!/bin/sh\nset -eu\n[ \"$1\" = \"-p\" ] || exit 1\ncat > \"$2.bgi\"\n"
	if err := os.WriteFile(tool, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	p.Config.Bigindex = tool
	for i := 0; i < 2; i++ {
		if err := p.PeriodicCopy(); err != nil {
			t.Fatal(err)
		}
		if n, err := p.IndexReady(context.Background(), nil); err != nil || n != 1 {
			t.Fatalf("periodic index %d: count=%d err=%v", i, n, err)
		}
	}
	entries, err := os.ReadDir(p.bgiDir())
	if err != nil || len(entries) != 2 || entries[0].Name() == entries[1].Name() {
		t.Fatalf("periodic indexes overwritten: entries=%v err=%v", entries, err)
	}
}

// A permanently failing single-binary batch must be preserved but must not
// prevent the indexer from processing the remaining ready directories.
func TestSingleBinaryFailureQuarantinedAfterRetry(t *testing.T) {
	p := testPipeline(t, 1024)
	m := Metadata{StreamLabel: "content", StreamSource: "testing"}
	if _, err := p.AddStream(strings.NewReader("failing binary"), m); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	p.Config.Bigindex = filepath.Join(t.TempDir(), "missing-bgindex")
	if _, err := p.IndexReady(context.Background(), nil); err == nil {
		t.Fatal("first build should fail")
	}
	// Simulates a restart, with the persistent last-attempt marker intact.
	restarted, err := New(p.Config)
	if err != nil {
		t.Fatal(err)
	}
	n, err := restarted.IndexReady(context.Background(), nil)
	if err != nil || n != 0 {
		t.Fatalf("quarantine: count %d error %v", n, err)
	}
	ready, err := restarted.ReadyDirs()
	if err != nil || len(ready) != 0 {
		t.Fatalf("quarantined batch still blocks indexing: %v %v", ready, err)
	}
	quarantined, err := os.ReadDir(filepath.Join(restarted.stateDir(), "quarantine"))
	if err != nil || len(quarantined) != 1 {
		t.Fatalf("missing quarantined batch: %v %v", quarantined, err)
	}
	files, err := os.ReadDir(filepath.Join(restarted.stateDir(), "quarantine", quarantined[0].Name()))
	if err != nil || len(files) != 2 {
		t.Fatalf("binary or metadata lost: %v %v", files, err)
	}
	if _, err := os.Stat(restarted.lastAttempt()); !os.IsNotExist(err) {
		t.Fatalf("stale last attempt marker: %v", err)
	}
}
