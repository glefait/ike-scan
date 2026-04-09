# ike-scan - IKEv1/IKEv2 VPN discovery and enumeration tool
# Includes modern algorithm support: AES-GCM, ChaCha20-Poly1305, ECP groups, SHA-2
#
# Build:  docker build -t ike-scan .
# Run:    docker run --rm --net=host ike-scan --ikev2 -M TARGET_IP
#         docker run --rm --net=host ike-scan -M TARGET_IP           # IKEv1
#         docker run --rm --net=host ike-scan --help

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        libssl-dev \
        perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN autoreconf -fi \
    && ./configure \
    && make -j"$(nproc)" \
    && make check 2>&1 | tee /build/test-results.txt || true \
    && strip ike-scan psk-crack

# ---- Runtime image ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/ike-scan    /usr/local/bin/ike-scan
COPY --from=builder /build/psk-crack   /usr/local/bin/psk-crack
COPY ikev2_enum.py                     /usr/local/bin/ikev2-enum.py
COPY --from=builder /build/ike-vendor-ids       /usr/local/share/ike-scan/
COPY --from=builder /build/ike-backoff-patterns /usr/local/share/ike-scan/
COPY --from=builder /build/psk-crack-dictionary /usr/local/share/ike-scan/

# Keep test results in image for reference
COPY --from=builder /build/test-results.txt /usr/local/share/ike-scan/build-test-results.txt

# ike-scan looks for vendor-ids and backoff-patterns relative to cwd or
# at hardcoded paths; point it to the share directory via env
ENV IKE_VENDOR_IDS=/usr/local/share/ike-scan/ike-vendor-ids
ENV IKE_BACKOFF_PATTERNS=/usr/local/share/ike-scan/ike-backoff-patterns

LABEL org.opencontainers.image.title="ike-scan"
LABEL org.opencontainers.image.description="IKEv1/IKEv2 VPN scanner with modern algorithm support (AES-GCM, ChaCha20, ECP groups, SHA-2)"
LABEL org.opencontainers.image.source="https://github.com/royhills/ike-scan"

# Needs CAP_NET_RAW to send raw UDP on port 500
# Run with: docker run --rm --net=host ike-scan [options] TARGET
ENTRYPOINT ["/usr/local/bin/ike-scan"]
CMD ["--help"]
