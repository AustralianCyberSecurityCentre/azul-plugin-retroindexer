package indexing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSummarizeInputUsesExactIndexedFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "small")
	b := filepath.Join(dir, "large")
	if err := os.WriteFile(a, make([]byte, 200), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, make([]byte, 2<<20), 0600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "input.txt")
	body := a + ",stream_label=content,stream_source=virustotal,file_size=200\n" + b + ",stream_label=content,stream_source=testing,file_size=2097152\n"
	if err := os.WriteFile(input, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := summarizeInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if s.FileCount != 2 || s.MinFileSize != 200 || s.MaxFileSize != 2<<20 || s.TotalFileBytes != 200+(2<<20) {
		t.Fatalf("wrong bounds: %+v", s)
	}
	if len(s.SizeBuckets) != 4 || s.SizeBuckets[0].FileCount != 1 || s.SizeBuckets[1].FileCount != 1 {
		t.Fatalf("wrong size buckets: %+v", s.SizeBuckets)
	}
	if len(s.StreamSources) != 2 || s.StreamSources[0] != "testing" || s.StreamSources[1] != "virustotal" {
		t.Fatalf("wrong sources: %v", s.StreamSources)
	}
}

func TestSummarizeInputFailsWhenFileDisappears(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(input, []byte(filepath.Join(dir, "gone")+",stream_label=content,stream_source=testing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := summarizeInput(input); err == nil {
		t.Fatal("missing binary should reject summary")
	}
}

func TestSummaryExcludesSyntheticPlaceholder(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real")
	fakePath := filepath.Join(dir, "dummy")
	if err := os.WriteFile(realPath, make([]byte, 2048), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakePath, []byte("dummy-file"), 0600); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(dir, "input")
	body := realPath + ",stream_label=content,stream_source=vt,file_format=executable/windows/pe64,file_size=2048\n" +
		fakePath + ",stream_label=content,stream_source=testing,synthetic=true,file_size=10\n"
	if err := os.WriteFile(list, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	summary, err := summarizeInput(list)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SchemaVersion != 2 || summary.FileCount != 1 || summary.MinFileSize != 2048 ||
		summary.FileTypeGroup != "windows" || summary.SizeClass != "lt1m" || len(summary.FileFormats) != 1 {
		t.Fatalf("unexpected partition summary: %+v", summary)
	}
}
