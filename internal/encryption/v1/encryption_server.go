package encryptionv1

import (
	context "context"
	"io"
	"time"

	grpc "google.golang.org/grpc"
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
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		ciphertext := req.Plaintext
		if err := stream.Send(&EncryptResponse{Ciphertext: ciphertext, Seq: req.Seq}); err != nil {
			return err
		}
	}
}

func (s *encryptionServiceServer) Decrypt(stream grpc.BidiStreamingServer[DecryptRequest, DecryptResponse]) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		// placeholder: echo ciphertext as plaintext
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
