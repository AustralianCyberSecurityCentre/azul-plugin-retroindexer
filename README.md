# Azul Plugin Retroindexer

Go-Based Retrohunt Ingestion And Biggrep Indexing Plugin.

## Local Build

`go build -v -tags netgo -ldflags '-w -extldflags "-static"' -o bin/azul-plugin-retroindexer *.go`

## Docker Builds

The project is typically built into a docker image, the standard way to build the docker image is with:

```bash
docker build .
```

## Object-storage index CLI

This repository builds the standalone `azul-index` CLI as well as the
Retroindexer plugin. It reuses the existing Bedrock storage package; no Bedrock
source changes are required. See [docs/index-cli.md](docs/index-cli.md) for
commands, credentials, image packaging, and the migration warning about old
`.bgi` object keys.
