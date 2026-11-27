package indexing

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// IndexSummary describes the exact BigGrep input set. These are conservative
// bounds: a future search may skip an index only when a rule cannot match ANY
// file in the recorded range. Missing sidecars must always fail open.
type IndexSummary struct {
	SchemaVersion  int      `json:"schema_version"`
	FileCount      int64    `json:"file_count"`
	MinFileSize    int64    `json:"min_file_size"`
	MaxFileSize    int64    `json:"max_file_size"`
	TotalFileBytes int64    `json:"total_file_bytes"`
	StreamLabels   []string `json:"stream_labels"`
	StreamSources  []string `json:"stream_sources"`
	FileTypeGroup  string   `json:"file_type_group,omitempty"`
	SizeClass      string   `json:"size_class,omitempty"`
	FileFormats    []string `json:"file_formats,omitempty"`
	// Size buckets are descriptive, not exclusive index partitions.
	SizeBuckets []SizeBucket `json:"size_buckets"`
}

// SizeBucket uses a half-open range [MinBytes, MaxBytes); a nil maximum is unbounded.
type SizeBucket struct {
	MinBytes   int64  `json:"min_bytes"`
	MaxBytes   *int64 `json:"max_bytes"`
	FileCount  int64  `json:"file_count"`
	TotalBytes int64  `json:"total_bytes"`
}

// summarizeInput reads the same comma-separated input that bgindex consumes.
// Reading the input list, rather than the whole staging directory, prevents
// skipped/invalid metadata entries from polluting future pruning decisions.
func summarizeInput(inputPath string) (IndexSummary, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return IndexSummary{}, err
	}
	defer func() {
		_ = f.Close() // Read-only input; no buffered writes to flush.
	}()
	bounds := []int64{0, 1 << 20, 10 << 20, 100 << 20}
	summary := IndexSummary{SchemaVersion: 2}
	for i, min := range bounds {
		bucket := SizeBucket{MinBytes: min}
		if i+1 < len(bounds) {
			next := bounds[i+1]
			bucket.MaxBytes = &next
		}
		summary.SizeBuckets = append(summary.SizeBuckets, bucket)
	}
	labels, sources, formats := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var expected Partition
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ",", 2)
		if len(parts) != 2 {
			return IndexSummary{}, fmt.Errorf("invalid BigGrep input line")
		}
		info, err := os.Stat(parts[0])
		if err != nil {
			return IndexSummary{}, err
		}
		if !info.Mode().IsRegular() {
			return IndexSummary{}, fmt.Errorf("not a regular file: %s", filepath.Base(parts[0]))
		}
		// Synthetic BigGrep placeholders must not influence pruning bounds.
		synthetic := false
		fileFormat := ""
		for _, pair := range strings.Split(parts[1], ",") {
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				return IndexSummary{}, fmt.Errorf("invalid BigGrep metadata pair")
			}
			switch key {
			case "synthetic":
				synthetic = value == "true"
			case "file_format":
				fileFormat = value
			}
		}
		if synthetic {
			continue
		}
		size := info.Size()
		partition := Partition{FileType: fileTypeGroup(fileFormat), SizeClass: sizeClass(size)}
		if summary.FileCount == 0 {
			expected = partition
		} else if expected != partition {
			// Legacy mixed batches remain searchable but cannot claim one partition.
			expected = Partition{FileType: "mixed", SizeClass: "mixed"}
		}
		if fileFormat != "" {
			formats[fileFormat] = true
		}
		if summary.FileCount == 0 || size < summary.MinFileSize {
			summary.MinFileSize = size
		}
		if size > summary.MaxFileSize {
			summary.MaxFileSize = size
		}
		summary.FileCount++
		summary.TotalFileBytes += size
		for i := range summary.SizeBuckets {
			bucket := &summary.SizeBuckets[i]
			if size >= bucket.MinBytes && (bucket.MaxBytes == nil || size < *bucket.MaxBytes) {
				bucket.FileCount++
				bucket.TotalBytes += size
				break
			}
		}
		for _, pair := range strings.Split(parts[1], ",") {
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				return IndexSummary{}, fmt.Errorf("invalid BigGrep metadata pair")
			}
			switch key {
			case "stream_label":
				labels[value] = true
			case "stream_source":
				sources[value] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return IndexSummary{}, err
	}
	if summary.FileCount == 0 {
		return IndexSummary{}, fmt.Errorf("empty BigGrep input list")
	}
	summary.FileTypeGroup = expected.FileType
	summary.SizeClass = expected.SizeClass
	for v := range formats {
		summary.FileFormats = append(summary.FileFormats, v)
	}
	sort.Strings(summary.FileFormats)
	for v := range labels {
		summary.StreamLabels = append(summary.StreamLabels, v)
	}
	for v := range sources {
		summary.StreamSources = append(summary.StreamSources, v)
	}
	sort.Strings(summary.StreamLabels)
	sort.Strings(summary.StreamSources)
	return summary, nil
}

// ValidateIndexSummary keeps malformed sidecars out of object storage. A reader
// still needs to validate the index hash and schema before trusting any bounds.
func ValidateIndexSummary(raw []byte) error {
	var s IndexSummary
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	if (s.SchemaVersion != 1 && s.SchemaVersion != 2) || s.FileCount <= 0 || s.MinFileSize < 0 || s.MaxFileSize < s.MinFileSize || len(s.StreamLabels) == 0 || len(s.StreamSources) == 0 {
		return fmt.Errorf("invalid index summary")
	}
	if s.SchemaVersion == 2 {
		if s.FileTypeGroup == "" || s.SizeClass == "" {
			return fmt.Errorf("missing partition identity")
		}
	}
	return nil
}
