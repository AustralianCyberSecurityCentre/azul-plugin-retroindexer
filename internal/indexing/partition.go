package indexing

import (
	"path/filepath"
	"strings"
)

// Partition separates BigGrep indexes by Azul's file format and original stream size.
// Unknown formats stay searchable and must never be silently treated as PE/ELF.
type Partition struct {
	FileType  string
	SizeClass string
}

// Size classes are half-open; a 1 MiB file belongs to 1m-10m.
func sizeClass(size int64) string {
	switch {
	case size < 1<<20:
		return "lt1m"
	case size < 10<<20:
		return "1m-10m"
	case size < 100<<20:
		return "10m-100m"
	default:
		return "gte100m"
	}
}

// fileTypeGroup follows Azul's canonical file_format taxonomy, not file extensions.
// Unrecognised formats use broad stable categories, with 'unknown' as the fallback.
func fileTypeGroup(format string) string {
	f := strings.ToLower(strings.TrimSpace(format))
	switch {
	case strings.HasPrefix(f, "executable/windows/"), hasFormatFamily(f, "executable/pe"), hasFormatFamily(f, "executable/dll"), hasFormatFamily(f, "executable/dos"), hasFormatFamily(f, "executable/com"), strings.HasPrefix(f, "installer/windows/"), f == "installer/windows", strings.HasPrefix(f, "document/installer/windows/"):
		return "windows"
	case strings.HasPrefix(f, "executable/linux/"), hasFormatFamily(f, "executable/elf"), strings.Contains(f, "/elf/") || strings.HasSuffix(f, "/elf"):
		return "elf"
	case strings.HasPrefix(f, "executable/mach-o"), strings.HasPrefix(f, "executable/macho"):
		return "macho"
	case strings.HasPrefix(f, "android/"), strings.HasPrefix(f, "ios/"):
		return "mobile"
	case strings.HasPrefix(f, "java/"), strings.HasPrefix(f, "python/bytecode"), f == "code/class":
		return "bytecode"
	case strings.HasPrefix(f, "document/"):
		return "document"
	case strings.HasPrefix(f, "archive/"):
		return "archive"
	case strings.HasPrefix(f, "script/"), strings.HasPrefix(f, "code/"):
		return "script"
	case strings.HasPrefix(f, "image/"):
		return "image"
	case strings.HasPrefix(f, "audio/"):
		return "audio"
	case strings.HasPrefix(f, "video/"):
		return "video"
	case strings.HasPrefix(f, "executable/"):
		return "executable-other"
	case f == "", f == "unknown", f == "data", f == "other":
		return "unknown"
	default:
		return "other"
	}
}

func partitionFor(m Metadata, bytes int64) Partition {
	return Partition{FileType: fileTypeGroup(m.FileFormat), SizeClass: sizeClass(bytes)}
}

func (p *Pipeline) partitionCacheDir(part Partition) string {
	return filepath.Join(p.cacheDir(), part.FileType, part.SizeClass)
}

// Match a taxonomy family without treating unrelated similarly named formats
// (for example, executable/compressed) as Windows COM binaries.
func hasFormatFamily(format, family string) bool {
	if format == family || strings.HasPrefix(format, family+"/") {
		return true
	}
	// Azul also uses numeric PE/DLL/ELF suffixes such as pe32 and elf64.
	suffix := strings.TrimPrefix(format, family)
	if suffix == format || suffix == "" {
		return false
	}
	for _, char := range suffix {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
