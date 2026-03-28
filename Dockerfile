# Stage 1: Build Go binary
FROM golang:1.25-alpine AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o cipherflag ./cmd/cipherflag/

# Stage 2: Build frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
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
EXPOSE 8443
ENTRYPOINT ["./cipherflag"]
CMD ["serve"]
