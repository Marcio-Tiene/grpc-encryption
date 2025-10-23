package encryptionv1

import (
	context "context"
	"fmt"
	"io"
	"time"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type encryptionServiceServer struct {
	UnimplementedEncryptionServiceServer
}

func NewEncryptionServiceServer() EncryptionServiceServer {
	return &encryptionServiceServer{}
}

func (s *encryptionServiceServer) GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	// Implement key pair generation logic here
	return &GenerateKeyPairResponse{
		Id: "12345",
	}, nil
}

func (s *encryptionServiceServer) Encrypt(stream grpc.BidiStreamingServer[EncryptRequest, EncryptResponse]) error {
	// Extract key_ref and algorithm from metadata
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Error(codes.InvalidArgument, "missing metadata")
	}

	keyRefValues := md.Get("key-ref")
	if len(keyRefValues) == 0 {
		return status.Error(codes.InvalidArgument, "key-ref metadata is required")
	}
	keyRef := keyRefValues[0]

	algorithmValues := md.Get("algorithm")
	algorithm := "AES-256-GCM" // default
	if len(algorithmValues) > 0 {
		algorithm = algorithmValues[0]
	}

	// Log the metadata values (for debugging)
	fmt.Printf("Encrypt stream started - key-ref: %s, algorithm: %s\n", keyRef, algorithm)

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		r, w := io.Pipe()
		go func() {
			defer w.Close()
			// placeholder: echo plaintext as ciphertext
			// TODO: Use keyRef and algorithm for actual encryption
			w.Write(req.Plaintext)
		}()

		defer r.Close()
		time.Sleep(1 * time.Second)
		// simulate processing delay

		// placeholder: echo plaintext as ciphertext
		for {
			buf := make([]byte, 1024)
			n, err := r.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			if err := stream.Send(&EncryptResponse{Ciphertext: buf[:n], Seq: uint64(n)}); err != nil {
				return err
			}
		}
	}
}

func (s *encryptionServiceServer) Decrypt(stream grpc.BidiStreamingServer[DecryptRequest, DecryptResponse]) error {
	// Extract key_ref from metadata
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return status.Error(codes.InvalidArgument, "missing metadata")
	}

	keyRefValues := md.Get("key-ref")
	if len(keyRefValues) == 0 {
		return status.Error(codes.InvalidArgument, "key-ref metadata is required")
	}
	keyRef := keyRefValues[0]

	// Log the metadata values (for debugging)
	fmt.Printf("Decrypt stream started - key-ref: %s\n", keyRef)

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		// placeholder: echo ciphertext as plaintext
		// TODO: Use keyRef for actual decryption
		plaintext := req.Ciphertext
		time.Sleep(1 * time.Second) // simulate processing delay
		if err := stream.Send(&DecryptResponse{Plaintext: plaintext, Seq: req.Seq}); err != nil {
			return err
		}
	}
}
func (s *encryptionServiceServer) RotateKeyPair(context.Context, *RotateKeyPairRequest) (*RotateKeyPairResponse, error) {
	// Implement key pair rotation logic here
	return &RotateKeyPairResponse{
		Id: "12345",
	}, nil
}
