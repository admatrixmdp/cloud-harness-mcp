# Go agent-runtime image shipped by compose.yaml as AGENT_IMAGE.
# TypeScript docker/agent.Dockerfile remains in-tree.
# Must not publish a host port, receive docker.sock, or carry provider credentials.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/agent-runtime ./cmd/agent-runtime

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent-runtime /agent-runtime
USER nonroot:nonroot
WORKDIR /
ENTRYPOINT ["/agent-runtime"]
