# Go network-guard image shipped by compose.yaml as NETWORK_GUARD_IMAGE.
# TypeScript docker/network-guard.Dockerfile remains in-tree. Must not
# publish a host port, receive docker.sock, or carry secrets. iptables-save
# stays in the image because attestation reads the host netns via NET_ADMIN.
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
