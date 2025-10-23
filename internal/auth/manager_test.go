package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestManager_GetAdapterFromContext(t *testing.T) {
	// Setup manager with token adapter
	manager := NewManager(&ManagerConfig{
		DefaultAdapter:  "token",
		RequireAuthType: false,
		Config:          DefaultConfig(),
	})

	tokenAdapter := NewTokenAdapter(DefaultConfig(), NewSimpleTokenValidator([]string{"test-token"}))
	manager.RegisterAdapter("token", tokenAdapter)

	tests := []struct {
		name        string
		ctx         context.Context
		wantAdapter string
		wantErr     bool
	}{
		{
			name: "explicit token auth",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("auth-type", "token"),
			),
			wantAdapter: "token",
			wantErr:     false,
		},
		{
			name:        "default auth (no metadata)",
			ctx:         context.Background(),
			wantAdapter: "token",
			wantErr:     false,
		},
		{
			name: "invalid auth type",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs("auth-type", "invalid"),
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := manager.getAdapterFromContext(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAdapterFromContext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && adapter.Name() != "TokenAdapter" {
				t.Errorf("getAdapterFromContext() got adapter %v, want TokenAdapter", adapter.Name())
			}
		})
	}
}

func TestManager_RequireAuthType(t *testing.T) {
	// Setup manager that requires auth-type
	manager := NewManager(&ManagerConfig{
		DefaultAdapter:  "token",
		RequireAuthType: true,
		Config:          DefaultConfig(),
	})

	tokenAdapter := NewTokenAdapter(DefaultConfig(), NewSimpleTokenValidator([]string{"test-token"}))
	manager.RegisterAdapter("token", tokenAdapter)

	// Test without auth-type metadata
	ctx := context.Background()
	_, err := manager.getAdapterFromContext(ctx)
	if err != ErrNoAuthMethod {
		t.Errorf("Expected ErrNoAuthMethod when auth-type is required but not provided, got %v", err)
	}

	// Test with auth-type metadata
	ctx = metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("auth-type", "token"),
	)
	adapter, err := manager.getAdapterFromContext(ctx)
	if err != nil {
		t.Errorf("Unexpected error with auth-type metadata: %v", err)
	}
	if adapter == nil {
		t.Error("Expected adapter to be returned")
	}
}

func TestManager_MultipleAdapters(t *testing.T) {
	manager := NewManager(&ManagerConfig{
		DefaultAdapter:  "token",
		RequireAuthType: false,
		Config:          DefaultConfig(),
	})

	// Register multiple adapters
	tokenAdapter := NewTokenAdapter(DefaultConfig(), NewSimpleTokenValidator([]string{"test-token"}))
	tlsAdapter := NewTLSAdapter(DefaultConfig(), NewSimpleCertVerifier([]string{"test-cn"}))

	manager.RegisterAdapter("token", tokenAdapter)
	manager.RegisterAdapter("tls", tlsAdapter)

	adapters := manager.GetRegisteredAdapters()
	if len(adapters) != 2 {
		t.Errorf("Expected 2 registered adapters, got %d", len(adapters))
	}

	// Test token adapter
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("auth-type", "token"),
	)
	adapter, err := manager.getAdapterFromContext(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if adapter.Name() != "TokenAdapter" {
		t.Errorf("Expected TokenAdapter, got %s", adapter.Name())
	}

	// Test TLS adapter
	ctx = metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("auth-type", "tls"),
	)
	adapter, err = manager.getAdapterFromContext(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if adapter.Name() != "TLSAdapter" {
		t.Errorf("Expected TLSAdapter, got %s", adapter.Name())
	}
}
