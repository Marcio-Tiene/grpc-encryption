package examples

import (
	"context"
	"io"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "grpc-encryption-service/internal/encryption/v1"
)

func main() {
	conn, err := grpc.NewClient(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewEncryptionServiceClient(conn)

	// Example 1: Encrypt stream with metadata
	log.Println("\n=== Encrypt Example ===")
	if err := encryptExample(client); err != nil {
		log.Printf("Encrypt failed: %v", err)
	}

	// Example 2: Decrypt stream with metadata
	log.Println("\n=== Decrypt Example ===")
	if err := decryptExample(client); err != nil {
		log.Printf("Decrypt failed: %v", err)
	}
}

func encryptExample(client pb.EncryptionServiceClient) error {
	// Create context with metadata for key-ref and algorithm
	ctx := metadata.AppendToOutgoingContext(
		context.Background(),
		"auth-type", "token",
		"authorization", "Bearer dev-token-123",
		"key-ref", "my-encryption-key-123",
		"algorithm", "AES-256-GCM",
	)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Open bidirectional stream
	stream, err := client.Encrypt(ctx)
	if err != nil {
		return err
	}

	// Send data chunks (only data, no key_ref in body)
	chunks := [][]byte{
		[]byte("Hello, "),
		[]byte("this is "),
		[]byte("encrypted data!"),
	}

	// Goroutine to send chunks
	go func() {
		for i, chunk := range chunks {
			req := &pb.EncryptRequest{
				Plaintext: chunk,
				Seq:       uint64(i + 1),
			}
			if err := stream.Send(req); err != nil {
				log.Printf("Failed to send chunk: %v", err)
				return
			}
			log.Printf("Sent chunk %d: %s", i+1, string(chunk))
		}
		stream.CloseSend()
	}()

	// Receive encrypted chunks
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if resp.Error != "" {
			log.Printf("Error in response: %s", resp.Error)
		}
		log.Printf("Received encrypted chunk (seq %d): %d bytes", resp.Seq, len(resp.Ciphertext))
	}

	log.Println("✅ Encryption completed")
	return nil
}

func decryptExample(client pb.EncryptionServiceClient) error {
	// Create context with metadata for key-ref
	ctx := metadata.AppendToOutgoingContext(
		context.Background(),
		"auth-type", "token",
		"authorization", "Bearer dev-token-123",
		"key-ref", "my-encryption-key-123",
	)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Open bidirectional stream
	stream, err := client.Decrypt(ctx)
	if err != nil {
		return err
	}

	// Send encrypted data chunks (only data, no key_ref in body)
	encryptedChunks := [][]byte{
		[]byte("encrypted_chunk_1"),
		[]byte("encrypted_chunk_2"),
		[]byte("encrypted_chunk_3"),
	}

	// Goroutine to send chunks
	go func() {
		for i, chunk := range encryptedChunks {
			req := &pb.DecryptRequest{
				Ciphertext: chunk,
				Seq:        uint64(i + 1),
			}
			if err := stream.Send(req); err != nil {
				log.Printf("Failed to send chunk: %v", err)
				return
			}
			log.Printf("Sent encrypted chunk %d: %d bytes", i+1, len(chunk))
		}
		stream.CloseSend()
	}()

	// Receive decrypted chunks
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if resp.Error != "" {
			log.Printf("Error in response: %s", resp.Error)
		}
		log.Printf("Received decrypted chunk (seq %d): %s", resp.Seq, string(resp.Plaintext))
	}

	log.Println("✅ Decryption completed")
	return nil
}
