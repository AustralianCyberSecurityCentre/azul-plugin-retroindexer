
# Build BigGrep exactly as in Retrohunt (autogen/configure/make),
# using the source archive committed under third_party/.

ARG REGISTRY="docker.io/library"
ARG BASE_IMAGE=golang
ARG BASE_TAG=1.27-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80

FROM ${REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=on

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        autoconf automake libtool make g++ pkg-config unzip \
        libboost-all-dev zlib1g-dev python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Compile BigGrep's indexing tools from the vendored source.
RUN make biggrep

# Build only the Retroindexer service. Retrohunt reads cloud indexes via Python.
RUN mkdir -p /out && \
    go build -trimpath -tags netgo -ldflags='-s -w' \
        -o /out/azul-plugin-retroindexer .

RUN install -Dm755 .build/bin/bgindex /go/bin/bgindex

# BigGrep is dynamically linked, so the runtime needs its shared libraries.
# Keep the existing mirrored Go image until a smaller Debian runtime
# image is approved.
FROM ${REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        zlib1g \
        libboost-thread-dev \
        libboost-system-dev \
        libboost-iostreams-dev \
        libboost-date-time-dev \
        libboost-chrono-dev \
        libboost-timer-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/azul-plugin-retroindexer /usr/local/bin/azul-plugin-retroindexer
COPY --from=builder /go/bin/bgindex /usr/local/bin/bgindex

ARG UID=21000
ARG GID=21000

RUN groupadd -g "$GID" azul && \
    useradd -u "$UID" -g "$GID" -M azul

USER azul

ENTRYPOINT ["/usr/local/bin/azul-plugin-retroindexer"]
