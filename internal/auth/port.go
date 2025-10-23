package auth

import (
	"context"

	"google.golang.org/grpc"
)

// Port defines the authentication interface (hexagonal architecture port)
type Port interface {
	// GetUnaryInterceptor returns the unary server interceptor for authentication
	GetUnaryInterceptor() grpc.UnaryServerInterceptor

	// GetStreamInterceptor returns the stream server interceptor for authentication
	GetStreamInterceptor() grpc.StreamServerInterceptor

	// ValidateCredentials validates credentials from the context
	ValidateCredentials(ctx context.Context) error

	// Name returns the name of the authentication adapter
	Name() string
}

// Config holds common configuration for all auth adapters
type Config struct {
	// SkipHealthCheck if true, skips authentication for health check endpoints
	SkipHealthCheck bool

	// AllowedMethods is a list of gRPC method names that bypass authentication
	AllowedMethods []string
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		SkipHealthCheck: true,
		AllowedMethods:  []string{},
	}
}
