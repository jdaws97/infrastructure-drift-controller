# Build stage
FROM golang:1.20-alpine AS builder

# Install build tools
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary with version information
ARG VERSION=dev
ARG BUILD_TIME=unknown
ARG GIT_COMMIT=unknown

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" -o /app/bin/infrastructure-drift-controller ./cmd/infrastructure-drift-controller

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata bash curl jq

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -u 1000 -G appuser -h /app -D appuser

# Create working directories
RUN mkdir -p /app/config /app/data /app/logs && \
    chown -R appuser:appuser /app

# Copy binary from builder
COPY --from=builder /app/bin/drift-detector /usr/local/bin/

# Set working directory
WORKDIR /app

# Set user
USER appuser

# Copy default config
COPY --chown=appuser:appuser config/config.yaml /app/config/

# Expose port for metrics/API (if needed)
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["drift-detector"]

# Set default CMD
CMD ["--config", "/app/config/config.yaml"]