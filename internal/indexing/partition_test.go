package indexing

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalFileTypeGroups(t *testing.T) {
	cases := map[string]string{
		"executable/windows/pe32": "windows", "executable/windows/dll64": "windows", "executable/dll32": "windows",
		"executable/linux/elf64": "elf", "executable/linux/so32": "elf",
		"executable/mach-o": "macho", "android/apk": "mobile", "java/jar": "bytecode", "document/pdf": "document",
		"archive/zip": "archive", "script/python": "script", "": "unknown",
		"unrecognised/weird": "other",
	}
	for format, want := range cases {
		if got := fileTypeGroup(format); got != want {
			t.Errorf("%q: got %q, want %q", format, got, want)
		}
	}
}

func TestSizeClassBoundaries(t *testing.T) {
	cases := []struct {
		bytes int64
		want  string
	}{
		{0, "lt1m"}, {(1 << 20) - 1, "lt1m"}, {1 << 20, "1m-10m"},
		{(10 << 20) - 1, "1m-10m"}, {10 << 20, "10m-100m"},
		{100 << 20, "gte100m"},
	}
	for _, tc := range cases {
		if got := sizeClass(tc.bytes); got != tc.want {
			t.Errorf("%d: got %s want %s", tc.bytes, got, tc.want)
		}
	}
}

func TestPartitionedIngestFlushAndSummary(t *testing.T) {
	p := testPipeline(t, 10<<20)
	inputs := []struct{ content, format, group string }{
		{"pe-binary", "executable/windows/pe64", "windows"},
		{"elf-binary", "executable/linux/elf64", "elf"},
		{"unknown", "", "unknown"},
	}
	for _, item := range inputs {
		added, err := p.AddStream(strings.NewReader(item.content), Metadata{StreamLabel: "content", StreamSource: "testing", FileFormat: item.format})
		if err != nil || !added {
			t.Fatalf("ingest %s: added=%t err=%v", item.group, added, err)
		}
		if b, err := cacheBytesIn(filepath.Join(p.cacheDir(), item.group, "lt1m")); err != nil || b != int64(len(item.content)) {
			t.Fatalf("cache %s %d %v", item.group, b, err)
		}
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	dirs, err := p.ReadyDirs()
	if err != nil || len(dirs) != 3 {
		t.Fatalf("ready %v %v", dirs, err)
	}
	seen := map[string]bool{}
	for _, dir := range dirs {
		input := new(bytes.Buffer)
		count, err := collectInput(dir, input)
		if err != nil || count != 2 {
			t.Fatalf("batch %s count %d err %v", dir, count, err)
		}
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, input.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		summary, err := summarizeInput(path)
		if err != nil {
			t.Fatal(err)
		}
		if summary.FileCount != 1 || summary.SizeClass != "lt1m" {
			t.Fatalf("bad summary %+v", summary)
		}
		seen[summary.FileTypeGroup] = true
	}
	for _, item := range inputs {
		if !seen[item.group] {
			t.Errorf("missing %s partition", item.group)
		}
	}
}

func TestSameFileTypeDifferentSizesStaySeparate(t *testing.T) {
	p := testPipeline(t, 20<<20)
	meta := Metadata{StreamLabel: "content", StreamSource: "testing", FileFormat: "executable/windows/pe64"}
	if _, err := p.AddStream(strings.NewReader("small"), meta); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AddStream(bytes.NewReader(bytes.Repeat([]byte{42}, 1<<20)), meta); err != nil {
		t.Fatal(err)
	}
	if a, err := cacheBytesIn(filepath.Join(p.cacheDir(), "windows", "lt1m")); err != nil || a != 5 {
		t.Fatalf("small index partition bytes %d %v", a, err)
	}
	if b, err := cacheBytesIn(filepath.Join(p.cacheDir(), "windows", "1m-10m")); err != nil || b != 1<<20 {
		t.Fatalf("larger index partition bytes %d %v", b, err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	dirs, err := p.ReadyDirs()
	if err != nil || len(dirs) != 2 {
		t.Fatalf("two homogeneous ready batches expected: %v %v", dirs, err)
	}
}

func TestFileTypeFamiliesDoNotOvermatch(t *testing.T) {
	cases := map[string]string{
		"executable/compressed": "executable-other",
		"executable/peanut":     "executable-other",
		"executable/elfish":     "executable-other",
		"executable/com":        "windows",
		"executable/pe32":       "windows",
		"executable/elf64":      "elf",
	}
	for format, want := range cases {
		if got := fileTypeGroup(format); got != want {
			t.Errorf("format %q: got %s want %s", format, got, want)
		}
	}
}

func TestLegacyCacheFlushDoesNotPublishEmptyBatch(t *testing.T) {
	p := testPipeline(t, 1024)
	legacy := []byte("legacy binary")
	name := fmt.Sprintf("%x", sha256.Sum256(legacy))
	if err := os.WriteFile(filepath.Join(p.cacheDir(), name), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(Metadata{StreamLabel: "content", StreamSource: "testing"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.cacheDir(), name+metaSuffix), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	dirs, err := p.ReadyDirs()
	if err != nil || len(dirs) != 1 {
		t.Fatalf("expected one legacy batch: %v %v", dirs, err)
	}
	var input bytes.Buffer
	count, err := collectInput(dirs[0], &input)
	if err != nil || count != 2 {
		t.Fatalf("legacy batch count = %d: %v", count, err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	dirs, err = p.ReadyDirs()
	if err != nil || len(dirs) != 1 {
		t.Fatalf("empty flush exposed extra batch: %v %v", dirs, err)
	}
}

func TestFlushSerializesWithIngestion(t *testing.T) {
	p := testPipeline(t, 1024)
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := p.AddStream(&blockingReader{entered: entered, release: release}, Metadata{StreamLabel: "content", StreamSource: "testing"})
		result <- err
	}()
	<-entered
	flushed := make(chan error, 1)
	go func() { flushed <- p.Flush() }()
	select {
	case err := <-flushed:
		t.Fatalf("flush finished while ingestion held the lock: %v", err)
	case <-time.After(15 * time.Millisecond):
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	dirs, err := p.ReadyDirs()
	if err != nil || len(dirs) != 1 {
		t.Fatalf("expected completed batch: %v %v", dirs, err)
	}
}

type blockingReader struct {
	entered chan struct{}
	release chan struct{}
	done    bool
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	close(r.entered)
	<-r.release
	r.done = true
	return copy(p, "blocking content"), nil
}
