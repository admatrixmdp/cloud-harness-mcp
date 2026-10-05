# Go API binary. TypeScript docker/api.Dockerfile remains the shipped image
# until Compose is switched. This file must not publish a host port.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 go build -o /out/cloud-harness-mcp ./cmd/cloud-harness-mcp \
 && CGO_ENABLED=0 go build -o /out/ingress-proxy ./cmd/ingress-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cloud-harness-mcp /cloud-harness-mcp
COPY --from=build /out/ingress-proxy /ingress-proxy
USER nonroot:nonroot
EXPOSE 3000
ENTRYPOINT ["/cloud-harness-mcp"]
