# gRPC Encryption Service

A production-ready gRPC service for streaming encryption/decryption operations with flexible runtime authentication using **Ports and Adapters (Hexagonal Architecture)**.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Authentication](#authentication)
- [Encryption Streams](#encryption-streams)
- [Architecture](#architecture)
- [Configuration Reference](#configuration-reference)
- [Development](#development)

---

## Overview

### Features

- ✅ **Bidirectional streaming** encryption/decryption
- ✅ **Runtime authentication selection** - choose auth method per request
- ✅ **Three authentication methods**: Token, TLS/mTLS, OAuth2/JWKS
- ✅ **Metadata-based configuration** - key-ref and algorithm in headers, not message body
- ✅ **Clean architecture** - Ports and Adapters pattern
- ✅ **Production ready** - comprehensive error handling and validation

### Protocol

- **Streaming RPCs**: Metadata carries `key-ref` and `algorithm`; message body contains only data chunks
- **Non-streaming RPCs**: Key generation and rotation operations
- **Authentication**: Specified via `auth-type` metadata per request

---

## Quick Start

### Prerequisites

- Go 1.24+
- buf (optional) or protoc + plugins

### Installation

```bash
# Clone the repository
git clone https://github.com/Marcio-Tiene/grpc-encryption.git
cd grpc-encryption-service

# Generate protobuf code
buf generate

# Build
go build ./...
```

### Local Development Setup

**1. Create your environment file:**

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration (optional - defaults work for dev)
# vim .env
```

**2. Run the server:**

```bash
# The server automatically loads .env file
go run cmd/server/server.go
```

That's it! The server will start with your configuration from `.env`.

Default development tokens: `dev-token-123`, `test-token-456`

### Alternative: Using Docker

```bash
# Build and run
docker build -t grpc-encryption:latest .
docker run -p 50051:50051 grpc-encryption:latest
```

### Test with grpcurl

```bash
grpcurl \
  -H "auth-type: token" \
  -H "authorization: Bearer dev-token-123" \
  -plaintext localhost:50051 \
  encryption.v1.EncryptionService/GenerateKeyPair
```

---

## Docker Deployment

### Quick Start with Docker

**Build and run with default configuration (development mode):**

```bash
docker build -t grpc-encryption:latest .
docker run -p 50051:50051 grpc-encryption:latest
```

The image comes with **development defaults**:
- ✅ Token authentication enabled
- ✅ Default tokens: `dev-token-123`, `test-token-456`
- ❌ TLS authentication disabled
- ❌ OAuth2 authentication disabled

### Configuration Modes

Configure the service by setting environment variables at runtime. No rebuild needed!

#### 1. Development Mode (Default)

Uses image defaults - no configuration needed:

```bash
docker run -p 50051:50051 grpc-encryption:latest
```

**Default environment:**
- `ENABLE_TOKEN_AUTH=true`
- `ENABLE_TLS_AUTH=false`
- `ENABLE_OAUTH2_AUTH=false`
- `AUTH_TOKENS=dev-token-123,test-token-456`
- `DEFAULT_AUTH_TYPE=token`

#### 2. Production Mode (Token + OAuth2)

```bash
docker run -p 50051:50051 \
  -e ENABLE_OAUTH2_AUTH=true \
  -e OAUTH2_ALLOWED_ISSUERS="https://keycloak.example.com/realms/production" \
  -e DEFAULT_AUTH_TYPE=oauth2 \
  -e REQUIRE_AUTH_TYPE=true \
  -e AUTH_TOKENS="prod-secret-token-xyz" \
  grpc-encryption:latest
```

**Environment overrides:**
- `ENABLE_OAUTH2_AUTH=true` - Enable OAuth2/JWKS validation
- `OAUTH2_ALLOWED_ISSUERS` - Comma-separated list of allowed JWT issuers
- `DEFAULT_AUTH_TYPE=oauth2` - Use OAuth2 by default
- `REQUIRE_AUTH_TYPE=true` - Force clients to specify auth-type
- `AUTH_TOKENS` - Override default tokens

#### 3. TLS/mTLS Mode

```bash
docker run -p 50051:50051 \
  -e ENABLE_TOKEN_AUTH=false \
  -e ENABLE_TLS_AUTH=true \
  -e DEFAULT_AUTH_TYPE=tls \
  -e AUTH_ALLOWED_CNS="client1.example.com,client2.example.com" \
  -v ./certs:/certs:ro \
  grpc-encryption:latest
```

**Environment overrides:**
- `ENABLE_TOKEN_AUTH=false` - Disable token auth
- `ENABLE_TLS_AUTH=true` - Enable TLS/mTLS
- `DEFAULT_AUTH_TYPE=tls` - Use TLS by default
- `AUTH_ALLOWED_CNS` - Comma-separated allowed certificate CNs

#### 4. All Methods Enabled

```bash
docker run -p 50051:50051 \
  -e ENABLE_TOKEN_AUTH=true \
  -e ENABLE_TLS_AUTH=true \
  -e ENABLE_OAUTH2_AUTH=true \
  -e OAUTH2_ALLOWED_ISSUERS="https://auth.example.com/realms/prod" \
  -e AUTH_TOKENS="multi-mode-token" \
  -e AUTH_ALLOWED_CNS="trusted-client.com" \
  -e DEFAULT_AUTH_TYPE=token \
  grpc-encryption:latest
```

### Using Docker Compose

**Development mode:**

```bash
docker-compose up
```

### Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `50051` | gRPC server port |
| `ENABLE_TOKEN_AUTH` | `true` | Enable token authentication |
| `ENABLE_TLS_AUTH` | `false` | Enable TLS/mTLS authentication |
| `ENABLE_OAUTH2_AUTH` | `false` | Enable OAuth2/JWKS authentication |
| `DEFAULT_AUTH_TYPE` | `token` | Default auth if client doesn't specify |
| `REQUIRE_AUTH_TYPE` | `false` | Force clients to specify auth-type |
| `AUTH_TOKENS` | `dev-token-123,test-token-456` | Comma-separated valid tokens |
| `AUTH_ALLOWED_CNS` | - | Comma-separated allowed certificate CNs |
| `OAUTH2_ALLOWED_ISSUERS` | - | Comma-separated allowed JWT issuers |

### Kubernetes/Cloud Deployment

**Using environment variables from ConfigMap/Secrets:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grpc-encryption-config
data:
  ENABLE_TOKEN_AUTH: "true"
  ENABLE_OAUTH2_AUTH: "true"
  DEFAULT_AUTH_TYPE: "oauth2"
  OAUTH2_ALLOWED_ISSUERS: "https://keycloak.example.com/realms/production"
---
apiVersion: v1
kind: Secret
metadata:
  name: grpc-encryption-secrets
stringData:
  AUTH_TOKENS: "super-secret-production-token"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grpc-encryption
spec:
  replicas: 3
  selector:
    matchLabels:
      app: grpc-encryption
  template:
    metadata:
      labels:
        app: grpc-encryption
    spec:
      containers:
      - name: grpc-encryption
        image: grpc-encryption:latest
        ports:
        - containerPort: 50051
        envFrom:
        - configMapRef:
            name: grpc-encryption-config
        - secretRef:
            name: grpc-encryption-secrets
```

### Docker Image Details

**Multi-stage build benefits:**
- 🚀 **Small size**: Final image ~20MB (Alpine-based)
- 🔒 **Secure**: Runs as non-root user `grpc` (UID/GID 1000)
- 📦 **Minimal**: Only runtime dependencies included
- ✅ **CA Certificates**: Included for OAuth2/JWKS HTTPS validation

**Image structure:**
- Base: `alpine:latest` (~5MB)
- Go binary: ~15MB (statically compiled)
- CA certificates: For HTTPS connections
- User: `grpc:grpc` (non-root)

### Testing the Docker Image

```bash
# Build
docker build -t grpc-encryption:latest .

# Run in background
docker run -d -p 50051:50051 --name grpc-test grpc-encryption:latest

# Test with grpcurl
grpcurl \
  -H "auth-type: token" \
  -H "authorization: Bearer dev-token-123" \
  -plaintext localhost:50051 \
  encryption.v1.EncryptionService/GenerateKeyPair

# View logs
docker logs grpc-test

# Stop and remove
docker stop grpc-test && docker rm grpc-test
```

### Production Best Practices

1. **Use specific image tags**: `grpc-encryption:v1.0.0` instead of `:latest`
2. **Set secrets via environment**: Never hardcode tokens in images
3. **Use health checks**: Implement gRPC health check service
4. **Resource limits**: Set CPU/memory limits in production
5. **TLS in production**: Always use TLS for external traffic
6. **Log aggregation**: Ship logs to centralized logging system
7. **Monitor metrics**: Export metrics for monitoring

**Example production docker run:**

```bash
docker run -d \
  --name grpc-encryption-prod \
  -p 50051:50051 \
  --memory="256m" \
  --cpus="0.5" \
  --restart=unless-stopped \
  -e ENABLE_TOKEN_AUTH=true \
  -e ENABLE_OAUTH2_AUTH=true \
  -e OAUTH2_ALLOWED_ISSUERS="${OAUTH2_ISSUERS}" \
  -e AUTH_TOKENS="${SECRET_TOKEN}" \
  -e DEFAULT_AUTH_TYPE=oauth2 \
  -e REQUIRE_AUTH_TYPE=true \
  grpc-encryption:v1.0.0
```

---

## Authentication

### Authentication Overview

The service uses **runtime authentication selection** - clients choose the auth method via metadata:

```go
ctx := metadata.AppendToOutgoingContext(
    context.Background(),
    "auth-type", "token",
    "authorization", "Bearer your-token",
)
```

### Supported Methods

| Method | Description | When to Use |
|--------|-------------|-------------|
| **Token** | API keys, Bearer tokens | Development, service-to-service |
| **TLS/mTLS** | Client certificates | High security, internal services |
| **OAuth2/JWKS** | JWT validation | User authentication, multi-tenant |

### Architecture

```
┌─────────────────────────────────────────┐
│         gRPC Client Request              │
│  metadata: auth-type = "token|tls|oauth2"│
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│       Authentication Manager             │
│       (routes based on metadata)         │
└────────────────┬────────────────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
    ▼            ▼            ▼
┌────────┐  ┌────────┐  ┌────────────┐
│ Token  │  │  TLS   │  │  OAuth2    │
│Adapter │  │Adapter │  │  Adapter   │
└────────┘  └────────┘  └────────────┘
```

### 1. Token Authentication

**Configuration:**

```bash
export ENABLE_TOKEN_AUTH=true
export AUTH_TOKENS="secret-token-123,another-token"
```

**Client Usage:**

```go
ctx := metadata.AppendToOutgoingContext(
    context.Background(),
    "auth-type", "token",
    "authorization", "Bearer secret-token-123",
)
```

**grpcurl:**

```bash
grpcurl \
  -H "auth-type: token" \
  -H "authorization: Bearer secret-token-123" \
  -plaintext localhost:50051 \
  encryption.v1.EncryptionService/GenerateKeyPair
```

### 2. TLS/mTLS Authentication

**Configuration:**

```bash
export ENABLE_TLS_AUTH=true
export AUTH_ALLOWED_CNS="client.example.com,trusted-client.example.com"
```

**Client Usage:**

```go
// Configure TLS credentials
creds, _ := credentials.NewClientTLSFromFile("client-cert.pem", "")
conn, _ := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))

ctx := metadata.AppendToOutgoingContext(
    context.Background(),
    "auth-type", "tls",
)
```

**grpcurl:**

```bash
grpcurl \
  -H "auth-type: tls" \
  -cert client-cert.pem \
  -key client-key.pem \
  -cacert ca-cert.pem \
  localhost:50051 \
  encryption.v1.EncryptionService/GenerateKeyPair
```

### 3. OAuth2/JWKS Authentication

**How It Works:**

1. Client sends JWT token in `Authorization: Bearer <token>` header
2. Server extracts `iss` (issuer) from JWT claims
3. Server validates issuer is in `OAUTH2_ALLOWED_ISSUERS`
4. Server fetches JWKS from `{issuer}/protocol/openid-connect/certs`
5. Server verifies JWT signature using public key from JWKS
6. Server validates claims (exp, nbf, iss)

**Configuration:**

```bash
export ENABLE_OAUTH2_AUTH=true
export OAUTH2_ALLOWED_ISSUERS="https://keycloak.example.com/realms/myrealm,https://auth.example.com/realms/prod"
```

**Supported Providers:**

| Provider | Issuer Format |
|----------|--------------|
| Keycloak | `https://keycloak.example.com/realms/{realm-name}` |
| Auth0 | `https://{tenant}.auth0.com/` |
| Okta | `https://{org}.okta.com/oauth2/default` |
| Azure AD | `https://login.microsoftonline.com/{tenant-id}/v2.0` |

**Client Usage:**

```go
ctx := metadata.AppendToOutgoingContext(
    context.Background(),
    "auth-type", "oauth2",
    "authorization", "Bearer eyJhbGci...",  // JWT token
)
```

**Benefits of JWKS:**

- ⚡ **Fast** - No network call per request (keys cached 1 hour)
- 🔒 **Secure** - Validates issuer domain/realm before accepting tokens
- 📦 **Self-contained** - Works offline with cached keys
- 🎭 **Privacy** - Token never sent to OAuth2 provider

---

## Encryption Streams

### Protocol Design

**Metadata** carries configuration, **message body** carries only data:

```go
ctx := metadata.AppendToOutgoingContext(
    context.Background(),
    "auth-type", "token",
    "authorization", "Bearer dev-token-123",
    "key-ref", "my-encryption-key-123",    // Key reference
    "algorithm", "AES-256-GCM",            // Algorithm
)

stream, err := client.Encrypt(ctx)

// Send only data in message body
req := &pb.EncryptRequest{
    Plaintext: []byte("Hello, World!"),
    Seq: 1,
}
stream.Send(req)
```

### Complete Example

```go
package main

import (
    "context"
    "io"
    "log"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
    pb "grpc-encryption-service/internal/encryption/v1"
)

func main() {
    conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
    defer conn.Close()
    client := pb.NewEncryptionServiceClient(conn)

    // Configure via metadata
    ctx := metadata.AppendToOutgoingContext(
        context.Background(),
        "auth-type", "token",
        "authorization", "Bearer dev-token-123",
        "key-ref", "my-key-123",
        "algorithm", "AES-256-GCM",
    )

    // Open encrypt stream
    stream, err := client.Encrypt(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Send data chunks
    data := []byte("Sensitive data to encrypt")
    if err := stream.Send(&pb.EncryptRequest{
        Plaintext: data,
        Seq: 1,
    }); err != nil {
        log.Fatal(err)
    }

    // Close send
    if err := stream.CloseSend(); err != nil {
        log.Fatal(err)
    }

    // Receive encrypted chunks
    for {
        resp, err := stream.Recv()
        if err == io.EOF {
            break
        }
        if err != nil {
            log.Fatal(err)
        }
        log.Printf("Encrypted chunk %d: %x", resp.Seq, resp.Ciphertext)
    }
}
```

See `examples/client_encryption.go` for more examples.

---

## Architecture

### Ports and Adapters Pattern

The service implements **Hexagonal Architecture** for authentication:

**Core Components:**

1. **Port Interface** (`internal/auth/port.go`) - Defines authentication contract
2. **Manager** (`internal/auth/manager.go`) - Routes requests to adapters
3. **Adapters** - Token, TLS, OAuth2 implementations

**File Structure:**

```
internal/
├── auth/
│   ├── port.go              # Port interface
│   ├── manager.go           # Auth router
│   ├── adapter_token.go     # Token auth
│   ├── adapter_tls.go       # TLS/mTLS auth
│   ├── adapter_oauth2.go    # OAuth2/JWKS auth
│   └── manager_test.go      # Tests
├── config/
│   ├── env.go               # Environment utilities
│   └── env_test.go
├── helper/
│   ├── string.go            # String utilities
│   └── string_test.go
├── infra/
│   └── auth.go              # Auth bootstrapping
└── encryption/
    └── v1/
        ├── encryption_server.go  # Encryption implementation
        └── encryption.pb.go      # Generated protobuf

cmd/
└── server/
    └── server.go            # Application entry point

examples/
└── client_encryption.go     # Example client
```

### Benefits

- ✅ **Flexibility** - Single deployment, multiple auth methods
- ✅ **Clean Separation** - Business logic independent of auth
- ✅ **Easy Testing** - Switch auth per request
- ✅ **Production Ready** - Gradual migration between auth methods

---

## Configuration Reference

### Environment Variables

#### Authentication Control

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_TOKEN_AUTH` | `true` | Enable token authentication |
| `ENABLE_TLS_AUTH` | `false` | Enable TLS/mTLS authentication |
| `ENABLE_OAUTH2_AUTH` | `false` | Enable OAuth2 authentication |
| `DEFAULT_AUTH_TYPE` | `token` | Default if client doesn't specify |
| `REQUIRE_AUTH_TYPE` | `false` | Force clients to specify auth-type |

#### Token Configuration

| Variable | Example | Description |
|----------|---------|-------------|
| `AUTH_TOKENS` | `secret-123,token-456` | Comma-separated valid tokens |

#### TLS Configuration

| Variable | Example | Description |
|----------|---------|-------------|
| `AUTH_ALLOWED_CNS` | `client.example.com` | Comma-separated allowed CNs |

#### OAuth2 Configuration

| Variable | Example | Description |
|----------|---------|-------------|
| `OAUTH2_ALLOWED_ISSUERS` | `https://keycloak.example.com/realms/prod` | Comma-separated JWT issuers |

### Common Scenarios

**Development:**

```bash
# Using Docker
docker run -p 50051:50051 grpc-encryption:latest

# Or directly
export ENABLE_TOKEN_AUTH=true
export AUTH_TOKENS="dev-token"
go run cmd/server/server.go
```

**Production Multi-tenant:**

```bash
ENABLE_TOKEN_AUTH=true      # Service-to-service
ENABLE_OAUTH2_AUTH=true     # User requests
DEFAULT_AUTH_TYPE=oauth2
```

**High Security:**

```bash
ENABLE_TLS_AUTH=true
DEFAULT_AUTH_TYPE=tls
REQUIRE_AUTH_TYPE=true
```

**Migration:**

```bash
ENABLE_TOKEN_AUTH=true      # Old clients
ENABLE_OAUTH2_AUTH=true     # New clients
DEFAULT_AUTH_TYPE=token     # Backward compatibility
```

---

## Development

### Build

```bash
go build ./...
```

### Generate Protobufs

```bash
buf generate
```

Or with protoc:

```bash
protoc --go_out=. --go-grpc_out=. proto/encryption/v1/encryption.proto
```

### Run Tests

```bash
go test ./...
```

### Lint

```bash
buf lint proto
```

### Adding a New Auth Method

1. Create `internal/auth/adapter_newauth.go` implementing `Port` interface
2. Register in `internal/infra/auth.go`
3. Add environment variables
4. Update documentation

Example:

```go
// adapter_basic.go
type BasicAuthAdapter struct {
    config *Config
    users  map[string]string
}

func (a *BasicAuthAdapter) ValidateCredentials(ctx context.Context) error {
    // Implementation
}

// In infra/auth.go
if config.GetEnv("ENABLE_BASIC_AUTH", "false") == "true" {
    adapter := auth.NewBasicAuthAdapter(auth.DefaultConfig(), users)
    manager.RegisterAdapter("basic", adapter)
}
```

---

## Troubleshooting

### Authentication Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `no authentication method specified` | Missing `auth-type` when `REQUIRE_AUTH_TYPE=true` | Add `auth-type` metadata |
| `invalid authentication type` | Auth type not enabled | Check `ENABLE_*_AUTH` variables |
| `invalid or expired token` | Wrong credential | Verify token value |
| `issuer not allowed` | JWT issuer not in whitelist | Add issuer to `OAUTH2_ALLOWED_ISSUERS` |
| `signing key not found` | JWT `kid` not in JWKS | Check token and JWKS endpoint |

### OAuth2/JWKS Troubleshooting

**Error: "issuer not allowed"**

1. Decode JWT at jwt.io to see `iss` claim
2. Add exact issuer to `OAUTH2_ALLOWED_ISSUERS`
3. Remove trailing slashes

**Error: "invalid token signature"**

1. Verify JWKS URL is accessible: `curl https://your-issuer/protocol/openid-connect/certs`
2. Check token not tampered
3. Verify issuer URL is correct

---

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

---

**Architecture**: Ports and Adapters (Hexagonal)  
**Auth Selection**: Runtime via gRPC metadata  
**Status**: Production Ready ✅

