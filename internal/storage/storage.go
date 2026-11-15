// Package storage publishes completed immutable Retrohunt indexes using the
// same azul-bedrock FileStorage implementations used by Azul Backup.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	bedSet "github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/settings"
	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/store"
)

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

func New(s Settings) (*Publisher, error) {
	if s.Backend == "none" {
		return nil, nil
	}
	var backend store.FileStorage
	var err error
	switch s.Backend {
	case "azure":
		backend, err = store.NewAzureStore(s.Endpoint, s.Bucket, s.AzureAccount, s.AzureAccessKey, nil)
	case "s3":
		if s.AccessKey == "" {
			backend, err = store.NewS3StoreIAM(s.Endpoint, s.Secure, s.Bucket, s.Region, nil, store.AutomaticAgeOffSettings{})
		} else {
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

// UploadFile streams a completed .bgi into Bedrock. Its SHA256 forms an immutable
// object name, so periodic indexes can be replaced locally without overwriting
// the last cloud version. The caller removes the temporary .bgi only after Put succeeds.
func (p *Publisher) UploadFile(path, processor string) (string, error) {
	if !strings.HasSuffix(path, ".bgi") {
		return "", fmt.Errorf("not a .bgi index: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			bedSet.Logger.Error().
				Err(err).
				Msg("failed to close index file")
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	checksum := hex.EncodeToString(h.Sum(nil))
	name := strings.TrimSuffix(filepath.Base(path), ".bgi") + "-" + checksum + ".bgi"
	source := "retrohunt"
	if p.prefix != "" {
		source = p.prefix
	}
	label := processor + "/bgi"
	if err = p.backend.Put(source, label, name, f, st.Size()); err != nil {
		return "", err
	}
	return source + "/" + label + "/" + name, nil
}

func (p *Publisher) Target() string { return p.target }
