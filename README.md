# Azul Plugin Retroindexer

Go-Based Retrohunt Ingestion And Biggrep Indexing Plugin.

## Local Build

`go build -v -tags netgo -ldflags '-w -extldflags "-static"' -o bin/azul-plugin-retroindexer *.go`

## Docker Builds

The project is typically built into a docker image, the standard way to build the docker image is with:

```bash
docker build .
```
