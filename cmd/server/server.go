package main

import (
	"fmt"
	encryptionv1 "grpc-encryption-service/internal/encryption/v1"
	"grpc-encryption-service/internal/infra"

	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func main() {
	fmt.Println("Starting gRPC Encryption Service...")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Initialize authentication manager
	authManager := infra.InitializeAuthManager()

	// Create gRPC server with authentication interceptors
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			authManager.GetUnaryInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			authManager.GetStreamInterceptor(),
		),
	)
	healthServer := health.NewServer()
	fmt.Println(encryptionv1.EncryptionService_ServiceDesc.ServiceName)

	go func() {
		status := healthpb.HealthCheckResponse_SERVING
		healthServer.SetServingStatus(encryptionv1.EncryptionService_ServiceDesc.ServiceName, status)
		healthServer.SetServingStatus("", status)

	}()
	healthpb.RegisterHealthServer(srv, healthServer)
	encryptionServer := encryptionv1.NewEncryptionServiceServer()
	encryptionv1.RegisterEncryptionServiceServer(srv, encryptionServer)
	reflection.Register(srv)

	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	log.Printf("gRPC server listening on %s", lis.Addr().String())

	// Wait for shutdown signal (Ctrl+C)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down gRPC server...")
	srv.Stop()
	log.Println("Server stopped")
}
