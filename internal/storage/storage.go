// Package storage publishes completed immutable Retrohunt indexes using the
// same azul-bedrock FileStorage implementations used by Azul Backup.
package storage

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/store"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/indexstorage"
)

// Settings selects S3 or Azure Blob using the same logical bucket/prefix layout.
type Settings struct {
	Backend        string
	Bucket         string // S3 bucket or Azure Blob container
	Prefix         string
	Endpoint       string
	Region         string
	AccessKey      string
	SecretKey      string
	AzureAccount   string
	AzureAccessKey string
	Secure         bool
	KeepLocal      bool // Preserve local indexes after upload for debugging only
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// FromEnv validates cloud configuration without establishing a connection.
func FromEnv() (Settings, error) {
	s := Settings{
		Backend:        strings.ToLower(env("RETROINDEXER_STORAGE_BACKEND", "none")),
		Bucket:         os.Getenv("RETROINDEXER_STORAGE_BUCKET"),
		Prefix:         strings.Trim(os.Getenv("RETROINDEXER_STORAGE_PREFIX"), "/"),
		Endpoint:       env("RETROINDEXER_STORAGE_ENDPOINT", os.Getenv("RETROINDEXER_S3_ENDPOINT")),
		Region:         env("RETROINDEXER_S3_REGION", "us-east-1"),
		AccessKey:      os.Getenv("RETROINDEXER_S3_ACCESS_KEY"),
		SecretKey:      os.Getenv("RETROINDEXER_S3_SECRET_KEY"),
		AzureAccount:   os.Getenv("RETROINDEXER_AZURE_ACCOUNT"),
		AzureAccessKey: os.Getenv("RETROINDEXER_AZURE_ACCESS_KEY"),
		Secure:         strings.EqualFold(env("RETROINDEXER_S3_SECURE", "true"), "true"),
		KeepLocal:      strings.EqualFold(env("RETROINDEXER_KEEP_LOCAL_INDEXES", "false"), "true"),
	}
	if s.Backend != "none" && s.Backend != "s3" && s.Backend != "azure" {
		return s, fmt.Errorf("unsupported storage backend %q (expected none, s3, azure)", s.Backend)
	}
	if s.Backend == "none" {
		return s, nil
	}
	if s.Bucket == "" {
		return s, errors.New("RETROINDEXER_STORAGE_BUCKET is required")
	}
	if s.Prefix != "" {
		for _, component := range strings.Split(s.Prefix, "/") {
			if component == "" || component == "." || component == ".." || strings.ContainsAny(component, "\\\r\n") {
				return s, errors.New("RETROINDEXER_STORAGE_PREFIX contains an unsafe path component")
			}
		}
	}
	if s.Backend == "azure" {
		if s.Endpoint == "" {
			return s, errors.New("RETROINDEXER_STORAGE_ENDPOINT must be the Azure Blob account URL")
		}
		u, err := url.Parse(s.Endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return s, errors.New("azure blob endpoint must be an https URL")
		}
	}
	if s.Backend == "s3" && (s.AccessKey == "") != (s.SecretKey == "") {
		return s, errors.New("both RETROINDEXER_S3_ACCESS_KEY and RETROINDEXER_S3_SECRET_KEY must be set together")
	}
	return s, nil
}

// Publisher uses the real Bedrock interface; no parallel Python/Go cloud SDK
// implementation is needed. Backend selection happens once during startup.
type Publisher struct {
	backend store.FileStorage
	prefix  string
	target  string
}

// New adapts the selected backend to Bedrock store.FileStorage. Both Azure
// Blob containers and S3 buckets are written through the same Put method.
func New(s Settings) (*Publisher, error) {
	if s.Backend == "none" {
		return nil, nil
	}
	var backend store.FileStorage
	var err error
	switch s.Backend {
	case "azure":
		// Bedrock handles Azure Blob authentication and the blob upload.
		backend, err = store.NewAzureStore(s.Endpoint, s.Bucket, s.AzureAccount, s.AzureAccessKey, nil)
	case "s3":
		if s.AccessKey == "" {
			// Use workload/instance IAM credentials when explicit keys are absent.
			backend, err = store.NewS3StoreIAM(s.Endpoint, s.Secure, s.Bucket, s.Region, nil, store.AutomaticAgeOffSettings{})
		} else {
			// Explicit keys also support S3-compatible services.
			backend, err = store.NewS3Store(s.Endpoint, s.AccessKey, s.SecretKey, s.Secure, s.Bucket, s.Region, nil, store.AutomaticAgeOffSettings{})
		}
	default:
		return nil, fmt.Errorf("unrecognised backend %q", s.Backend)
	}
	if err != nil {
		return nil, err
	}
	return &Publisher{
		backend: backend,
		prefix:  s.Prefix,
		target:  fmt.Sprintf("%s:%s:%s:%s:%s", s.Backend, s.Endpoint, s.Bucket, s.Prefix, s.Region),
	}, nil
}

// ParseLocation converts a logical prefix to the two components expected by
// Bedrock's FileStorage interface. The writer and CLI MUST use the same value.
// The default is retrohunt/indices for compatibility with Retrohunt's reader.
func ParseLocation(prefix string) (string, string, error) {
	if prefix == "" {
		prefix = "retrohunt/indices"
	}
	parts := strings.SplitN(prefix, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("index prefix %q must contain source/label", prefix)
	}
	for _, component := range strings.Split(prefix, "/") {
		if component == "" || component == "." || component == ".." || strings.ContainsAny(component, "\\\r\n") {
			return "", "", fmt.Errorf("unsafe index prefix %q", prefix)
		}
	}
	return parts[0], parts[1], nil
}

// UploadFile publishes an immutable, content-addressed index followed by a
// ready marker. Retrohunt lists only ready markers and verifies SHA-256 on fetch.
// Both the automatic publisher and azul-index CLI use the same protocol.
func (p *Publisher) UploadFile(path, processor string) (string, error) {
	if !strings.HasSuffix(strings.ToLower(path), ".bgi") {
		return "", fmt.Errorf("not a .bgi index: %s", path)
	}
	source, label, err := ParseLocation(p.prefix)
	if err != nil {
		return "", err
	}
	manager := indexstorage.Manager{Storage: p.backend, Source: source, Label: label}
	id, err := manager.Put(path)
	if err != nil {
		return "", err
	}
	return source + "/" + label + "/" + id + ".bgi", nil
}

func (p *Publisher) Target() string { return p.target }
