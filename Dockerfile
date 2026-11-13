# Build BigGrep exactly as in Retrohunt (autogen/configure/make),
# using the source archive committed under third_party/.
ARG REGISTRY=docker.io/library
ARG GO_IMAGE=golang
ARG GO_TAG=1.27-trixie

FROM ${REGISTRY}/${GO_IMAGE}:${GO_TAG} AS builder
ENV DEBIAN_FRONTEND=noninteractive
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
ENV GOPRIVATE=github.com/AustralianCyberSecurityCentre/*
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool make g++ pkg-config unzip \
    libboost-all-dev zlib1g-dev python3 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Uses the existing BigGrep archive; no network download for the C++ source.
RUN make biggrep
RUN --mount=type=ssh go build -trimpath -tags netgo -ldflags='-s -w' \
    -o /out/azul-plugin-retroindexer .
RUN install -Dm755 .build/bin/bgindex /out/bgindex

# BigGrep is a dynamically linked C++ executable, so scratch/alpine will not work.
FROM ${REGISTRY}/debian:trixie-slim AS release
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libstdc++6 zlib1g \
    libboost-thread-dev libboost-system-dev libboost-iostreams-dev \
    libboost-date-time-dev libboost-chrono-dev libboost-timer-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/azul-plugin-retroindexer /usr/local/bin/azul-plugin-retroindexer
COPY --from=builder /out/bgindex /usr/local/bin/bgindex
ARG UID=21000
ARG GID=21000
RUN groupadd -g "$GID" azul && useradd -u "$UID" -g "$GID" -M azul
USER azul
ENTRYPOINT ["/usr/local/bin/azul-plugin-retroindexer"]
