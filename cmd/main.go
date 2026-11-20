// azul-index bridges BigGrep's local .bgi files and Bedrock's object stores.
// The underlying index format and search engine remain unchanged.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/AustralianCyberSecurityCentre/azul-bedrock/v13/gosrc/store"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/indexstorage"
	"github.com/AustralianCyberSecurityCentre/azul-plugin-retroindexer/internal/storage"
)

// The index namespace defaults to retrohunt/indices, matching the
// Retroindexer writer. Override AZUL_INDEX_PREFIX only when both sides
// intentionally use a different prefix.
func storageLocation() (string, string, error) {
	prefix := os.Getenv("AZUL_INDEX_PREFIX")
	if prefix == "" {
		prefix = "retrohunt/indices"
	}
	return storage.ParseLocation(prefix)
}

func requiredEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("missing required environment variable %s", name)
	}
	return value, nil
}

// NewStorage deliberately reuses Bedrock's production S3 and Azure clients.
// Credentials are supplied by environment/identity, never CLI flags or logs.
func newStorage() (store.FileStorage, error) {
	backend, err := requiredEnv("AZUL_INDEX_BACKEND")
	if err != nil {
		return nil, err
	}
	switch backend {
	case "s3":
		bucket, err := requiredEnv("AZUL_INDEX_S3_BUCKET")
		if err != nil {
			return nil, err
		}
		endpoint := os.Getenv("AZUL_INDEX_S3_ENDPOINT") // Empty is valid for AWS default endpoint.
		region := os.Getenv("AZUL_INDEX_S3_REGION")
		if region == "" {
			region = "us-east-1"
		}
		secure := strings.ToLower(os.Getenv("AZUL_INDEX_S3_SECURE")) != "false"
		access, secret := os.Getenv("AZUL_INDEX_S3_ACCESS_KEY"), os.Getenv("AZUL_INDEX_S3_SECRET_KEY")
		if (access == "") != (secret == "") {
			return nil, errors.New("provide both S3 access and secret keys, or neither for IAM")
		}
		if access == "" {
			return store.NewS3StoreIAM(endpoint, secure, bucket, region, nil, store.AutomaticAgeOffSettings{})
		}
		return store.NewS3Store(endpoint, access, secret, secure, bucket, region, nil, store.AutomaticAgeOffSettings{})
	case "azure":
		endpoint, err := requiredEnv("AZUL_INDEX_AZURE_ENDPOINT")
		if err != nil {
			return nil, err
		}
		container, err := requiredEnv("AZUL_INDEX_AZURE_CONTAINER")
		if err != nil {
			return nil, err
		}
		return store.NewAzureStore(endpoint, container, os.Getenv("AZUL_INDEX_AZURE_ACCOUNT"), os.Getenv("AZUL_INDEX_AZURE_KEY"), nil)
	case "local": // Useful for smoke tests without cloud services.
		root, err := requiredEnv("AZUL_INDEX_LOCAL_ROOT")
		if err != nil {
			return nil, err
		}
		return store.NewLocalStore(root)
	default:
		return nil, fmt.Errorf("unknown backend %q: choose s3, azure or local", backend)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: azul-index put --file PATH | fetch --id SHA256 --output PATH | list")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	file := flags.String("file", "", "local .bgi to publish")
	id := flags.String("id", "", "SHA-256 index ID")
	output := flags.String("output", "", "local output path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if command != "put" && command != "fetch" && command != "list" {
		return fmt.Errorf("unknown command %q", command)
	}
	if command == "put" && *file == "" {
		return errors.New("put requires --file")
	}
	if command == "fetch" && (*id == "" || *output == "") {
		return errors.New("fetch requires --id and --output")
	}
	storage, err := newStorage()
	if err != nil {
		return err
	}
	// Match the same source/label namespace used by Retroindexer's writer.
	source, label, err := storageLocation()
	if err != nil {
		return err
	}
	manager := indexstorage.Manager{Storage: storage, Source: source, Label: label}
	switch command {
	case "put":
		id, err := manager.Put(*file)
		if err != nil {
			return err
		}
		fmt.Println(id)
	case "fetch":
		if err := manager.Fetch(*id, *output); err != nil {
			return err
		}
		fmt.Println(*output)
	case "list":
		ids, err := manager.List(context.Background())
		if err != nil {
			return err
		}
		for _, id := range ids {
			fmt.Println(id)
		}
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "azul-index:", err)
		os.Exit(1)
	}
}
