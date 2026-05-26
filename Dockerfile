# Stage 1: Build Go binary
FROM golang:1.25-alpine AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# LICENSE_PUBKEY_B64 — base64-encoded Ed25519 public key for AI-license
# verification. When non-empty, injected via -ldflags into
# internal/ai/license.PinnedPublicKeyB64. When empty (default), the
# binary keeps the placeholder sentinel and license.IsPlaceholder() is
# true at runtime — main.go logs a loud WARN at startup and any AI-
# licensed feature fails closed. This intentional split keeps local
# `docker build` (and PR CI) working without secrets, while the tagged-
# release workflow validates the secret is set and refuses to build
# without it (see .github/workflows/release.yml).
ARG LICENSE_PUBKEY_B64=
RUN LDFLAGS="-s -w" && \
    if [ -n "$LICENSE_PUBKEY_B64" ]; then \
      LDFLAGS="$LDFLAGS -X github.com/net4n6-dev/cipherflag/internal/ai/license.PinnedPublicKeyB64=$LICENSE_PUBKEY_B64"; \
    fi && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="$LDFLAGS" -o cipherflag ./cmd/cipherflag/

# Stage 2: Build frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /build
# Copy install-time inputs BEFORE `npm ci`. Three files the install needs:
#   - package.json / package-lock.json: deterministic dep resolution
#   - .npmrc: minimal install config (engine-strict)
# CE does not vendor Histoire or use patch-package (EE-only stack);
# accordingly there is no frontend/patches/ directory in CE.
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 3: Runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=go-builder /build/cipherflag .
COPY --from=frontend-builder /build/build ./frontend/build
COPY config/cipherflag.toml ./config/
COPY internal/store/migrations ./internal/store/migrations
EXPOSE 8443
ENTRYPOINT ["./cipherflag"]
CMD ["serve"]
