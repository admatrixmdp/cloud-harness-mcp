# Go network-guard image for the opt-in compose.go.yaml overlay.
# TypeScript docker/network-guard.Dockerfile remains the shipped
# NETWORK_GUARD_IMAGE until Compose switches. Must not publish a host
# port, receive docker.sock, or carry secrets. iptables-save stays in
# the image because attestation reads the host netns via NET_ADMIN.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/network-guard ./cmd/network-guard

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/network-guard /network-guard
USER root
WORKDIR /
ENTRYPOINT ["/network-guard"]
