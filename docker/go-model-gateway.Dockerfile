# Go model-gateway. Must not receive Docker, jobs, state, or control mounts.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/model-gateway ./cmd/model-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/model-gateway /model-gateway
USER nonroot:nonroot
EXPOSE 3210
ENTRYPOINT ["/model-gateway"]
