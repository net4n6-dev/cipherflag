# Stage 1: Build frontend (static SPA)
FROM node:22-alpine AS frontend-builder
WORKDIR /build
# Copy install-time inputs BEFORE `npm ci`:
#   - package.json / package-lock.json: deterministic dep resolution
#   - .npmrc: minimal install config (engine-strict)
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Build Go binary (embeds the frontend)
FROM golang:1.25-alpine AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Place the static frontend build where //go:embed all:dist expects it.
# This overlays the committed placeholder internal/web/dist/index.html.
COPY --from=frontend-builder /build/build ./internal/web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cipherflag ./cmd/cipherflag/

# Stage 3: Runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=go-builder /build/cipherflag .
COPY config/cipherflag.toml ./config/
COPY internal/store/migrations ./internal/store/migrations
EXPOSE 8443
ENTRYPOINT ["./cipherflag"]
CMD ["serve"]
