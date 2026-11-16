# Build BigGrep exactly as in Retrohunt (autogen/configure/make),
# using the source archive committed under third_party/.

ARG REGISTRY="docker.io/library"
ARG BASE_IMAGE=golang
ARG BASE_TAG=1.27-trixie

FROM ${REGISTRY}/${BASE_IMAGE}:${BASE_TAG} AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=on
#ENV GOPRIVATE=github.com/AustralianCyberSecurityCentre/*

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        autoconf automake libtool make g++ pkg-config unzip \
        libboost-all-dev zlib1g-dev python3

#RUN git config --global url."git@github.com:AustralianCyberSecurityCentre/".insteadOf "https://github.com/AustralianCyberSecurityCentre/"

RUN git config --list

RUN go env GOPRIVATE
RUN go env GOPROXY
RUN go env GONOSUMDB

RUN git ls-remote https://github.com/AustralianCyberSecurityCentre/azul-bedrock

WORKDIR /src
COPY . .

RUN make biggrep

RUN go build -trimpath -tags netgo -ldflags='-s -w' \
    -o /out/azul-plugin-retroindexer .

RUN install -Dm755 .build/bin/bgindex /go/bin/bgindex

# BigGrep is dynamically linked so we need a Debian runtime image.
FROM ${REGISTRY}/debian:trixie

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