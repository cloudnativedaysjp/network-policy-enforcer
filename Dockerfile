FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/enforcer ./cmd/enforcer

FROM alpine:3.20
RUN apk add --no-cache nftables ca-certificates

COPY --from=builder /out/enforcer /usr/local/bin/enforcer

ENTRYPOINT ["/usr/local/bin/enforcer"]
