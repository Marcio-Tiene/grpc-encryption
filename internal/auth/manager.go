package auth

import (
	"context"
	"errors"
	"slices"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	ErrNoAuthMethod     = errors.New("no authentication method specified")
	ErrInvalidAuthType  = errors.New("invalid authentication type")
	ErrNoAdapterEnabled = errors.New("no authentication adapters enabled")
)

// Manager manages multiple authentication adapters and routes requests to the appropriate one
type Manager struct {
	adapters        map[string]Port
	defaultAdapter  string
	config          *Config
	requireAuthType bool // If true, clients must specify auth-type in metadata
}

// ManagerConfig holds configuration for the authentication manager
type ManagerConfig struct {
	DefaultAdapter  string // Default auth type if not specified in metadata
	RequireAuthType bool   // If true, auth-type metadata is required
	Config          *Config
}

// NewManager creates a new authentication manager
func NewManager(config *ManagerConfig) *Manager {
	if config == nil {
		config = &ManagerConfig{
			DefaultAdapter:  "token",
			RequireAuthType: false,
			Config:          DefaultConfig(),
		}
	}
	if config.Config == nil {
		config.Config = DefaultConfig()
	}

	return &Manager{
		adapters:        make(map[string]Port),
		defaultAdapter:  config.DefaultAdapter,
		config:          config.Config,
		requireAuthType: config.RequireAuthType,
	}
}

// RegisterAdapter registers an authentication adapter with a given name
func (m *Manager) RegisterAdapter(name string, adapter Port) {
	m.adapters[name] = adapter
}

// GetUnaryInterceptor returns a unary interceptor that routes to the appropriate adapter
func (m *Manager) GetUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if m.shouldSkipAuth(info.FullMethod) {
			return handler(ctx, req)
		}

		adapter, err := m.getAdapterFromContext(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		if err := adapter.ValidateCredentials(ctx); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// GetStreamInterceptor returns a stream interceptor that routes to the appropriate adapter
func (m *Manager) GetStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if m.shouldSkipAuth(info.FullMethod) {
			return handler(srv, ss)
		}

		adapter, err := m.getAdapterFromContext(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}

		if err := adapter.ValidateCredentials(ss.Context()); err != nil {
			return err
		}

		return handler(srv, ss)
	}
}

// getAdapterFromContext extracts the auth type from metadata and returns the appropriate adapter
func (m *Manager) getAdapterFromContext(ctx context.Context) (Port, error) {
	if len(m.adapters) == 0 {
		return nil, ErrNoAdapterEnabled
	}

	md, ok := metadata.FromIncomingContext(ctx)
	var authType string

	if ok {
		values := md.Get("auth-type")
		if len(values) > 0 {
			authType = values[0]
		}
	}

	// If no auth-type specified, use default
	if authType == "" {
		if m.requireAuthType {
			return nil, ErrNoAuthMethod
		}
		authType = m.defaultAdapter
	}

	adapter, exists := m.adapters[authType]
	if !exists {
		return nil, ErrInvalidAuthType
	}

	return adapter, nil
}

func (m *Manager) shouldSkipAuth(method string) bool {
	if m.config.SkipHealthCheck && (strings.HasSuffix(method, "/Check") || strings.HasSuffix(method, "/Watch")) {
		return true
	}

	return slices.Contains(m.config.AllowedMethods, method)
}

// GetRegisteredAdapters returns the names of all registered adapters
func (m *Manager) GetRegisteredAdapters() []string {
	names := make([]string, 0, len(m.adapters))
	for name := range m.adapters {
		names = append(names, name)
	}
	return names
}
