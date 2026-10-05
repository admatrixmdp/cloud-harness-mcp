# Go runner binary. Docker socket belongs only on this image at Compose time.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/runner ./cmd/runner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/runner /runner
USER nonroot:nonroot
EXPOSE 3001
ENTRYPOINT ["/runner"]
