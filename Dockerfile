# Multi-stage Dockerfile for gRPC Encryption Service
# Default configuration: Development mode with token authentication
# Override environment variables at runtime for different configurations

# Stage 1: Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd/server

# Stage 2: Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS (needed for OAuth2/JWKS)
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 grpc && \
    adduser -D -u 1000 -G grpc grpc

WORKDIR /home/grpc

# Copy binary from builder
COPY --from=builder /app/server .

# Change ownership
RUN chown -R grpc:grpc /home/grpc

# Switch to non-root user
USER grpc

# Default environment variables (Development mode)
# Override these at runtime with docker run -e VAR=value

# Server port
ENV PORT=50051

# Authentication configuration (default: dev mode - token only)
ENV ENABLE_TOKEN_AUTH=true \
    ENABLE_TLS_AUTH=false \
    ENABLE_OAUTH2_AUTH=false \
    DEFAULT_AUTH_TYPE=token \
    REQUIRE_AUTH_TYPE=false

# Token authentication (default tokens for development)
ENV AUTH_TOKENS="dev-token-123,test-token-456"

# TLS authentication (uncomment and set for TLS mode)
# ENV AUTH_ALLOWED_CNS="client.example.com,localhost"

# OAuth2 authentication (set for production mode)
# ENV OAUTH2_ALLOWED_ISSUERS="https://keycloak.example.com/realms/myrealm"

# Expose gRPC port
EXPOSE 50051

# Run the server
CMD ["./server"]
