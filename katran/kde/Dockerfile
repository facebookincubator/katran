FROM ubuntu:24.04

LABEL org.opencontainers.image.source="https://github.com/facebookincubator/katran"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libatomic1 \
        libcurl4t64 \
        libelf1t64 \
        libevent-2.1-7t64 \
        libgflags2.2 \
        liblz4-1 \
        libmnl0 \
        libprotobuf32t64 \
        libsodium23 \
        libssl3t64 \
        libstdc++6 \
        libxxhash0 \
        libzstd1 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Build context: the Ubuntu getdeps artifact, staged for /usr/local.
COPY . /usr/local/
RUN chmod 0755 /usr/local/bin/katran_de_ctl \
    && /usr/local/bin/katran_de_ctl --help

ENTRYPOINT ["/usr/local/bin/katran_de_ctl"]
CMD ["--help"]
