# Optional Go worker binary layered onto the existing executor image policy.
# The TypeScript worker remains the image entry until Compose switches.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/harness-worker ./cmd/harness-worker

FROM node:24.11.0-bookworm-slim
COPY --from=build /out/harness-worker /opt/harness/harness-worker
RUN chmod 0555 /opt/harness/harness-worker
USER 10001:10001
