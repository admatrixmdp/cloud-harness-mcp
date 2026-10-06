# Go runner binary. Docker socket belongs only on this image at Compose time.
# Not distroless: production talks to the host daemon via the docker CLI
# (same as docker/runner.Dockerfile). The API/ingress images stay distroless.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/runner ./cmd/runner

FROM alpine:3.22
RUN apk add --no-cache docker-cli tini
COPY --from=build /out/runner /runner
EXPOSE 3001
ENTRYPOINT ["/sbin/tini", "--", "/runner"]
