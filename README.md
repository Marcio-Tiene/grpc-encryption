# gRPC Encryption Service

Small gRPC service for streaming encrypt/decrypt operations and key management.

## Overview
- Streaming RPCs carry raw byte frames. The client must supply a key reference in gRPC metadata (header) named `x-key-ref` before opening the stream.
- Non-stream RPCs are provided for key generation/rotation.

## Prerequisites
- Go 1.24+
- buf (optional) or protoc + plugins (protoc-gen-go, protoc-gen-go-grpc)

## Generate protobufs
If you use `buf` (recommended):

```bash
# gRPC Encryption Service

Small gRPC service for streaming encrypt/decrypt operations and key management.

## Overview

- Streaming RPCs carry raw byte frames. The `key_ref` is sent inside each stream request message (the `EncryptRequest` / `DecryptRequest` messages include a `key_ref` field).
- Non-stream RPCs are provided for key generation/rotation.

## Prerequisites

- Go 1.24+
- buf (optional) or protoc + plugins (protoc-gen-go, protoc-gen-go-grpc)

## Generate protobufs

If you use `buf` (recommended):

```bash
buf generate
```

Or with `protoc` (example):

```bash
protoc --go_out=. --go-grpc_out=. proto/encryption/v1/encryption.proto
```

## Build

```bash
go build ./...
```

## Run the server

```bash
go run cmd/server/server.go
```

## Passing key_ref in the stream body

The `EncryptRequest` and `DecryptRequest` messages include a `key_ref` field. Clients should include the key reference in each streamed message (or the first message and reuse it server-side).

Client example (Go):

```go
ctx := context.Background()
stream, err := client.Encrypt(ctx)
if err != nil { /* handle */ }

req := &pb.EncryptRequest{
    KeyRef:  "my-key-ref-123",
    Plaintext: []byte("..."),
    Seq: 1,
}
if err := stream.Send(req); err != nil { /* handle */ }
// receive responses
resp, err := stream.Recv()
_ = resp
```

Server example (Go):

```go
for {
    req, err := stream.Recv()
    if err == io.EOF { return nil }
    if err != nil { return err }

    keyRef := req.KeyRef
    data := req.Plaintext
    // process data with keyRef

    if err := stream.Send(&pb.EncryptResponse{KeyRef: keyRef, Ciphertext: cipherBytes, Seq: req.Seq}); err != nil { return err }
}
```

## Linting / validation

If you use `buf`:

```bash
buf lint proto
```

## Notes

- Keep generated protobuf files under version control or add them to `.gitignore` and regenerate during CI.

