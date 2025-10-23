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
	ErrMissingMetadata      = errors.New("missing metadata")
	ErrInvalidToken         = errors.New("invalid token")
	ErrMissingAuthorization = errors.New("missing authorization header")
)

// TokenAdapter implements token-based authentication (API keys, JWT, etc.)
type TokenAdapter struct {
	config         *Config
	validTokens    map[string]bool
	tokenValidator TokenValidator
}

// TokenValidator defines the interface for custom token validation
type TokenValidator interface {
	ValidateToken(token string) (bool, error)
}

// SimpleTokenValidator is a basic token validator using a map
type SimpleTokenValidator struct {
	tokens map[string]bool
}

func NewSimpleTokenValidator(tokens []string) *SimpleTokenValidator {
	validTokens := make(map[string]bool)
	for _, token := range tokens {
		validTokens[token] = true
	}
	return &SimpleTokenValidator{tokens: validTokens}
}

func (v *SimpleTokenValidator) ValidateToken(token string) (bool, error) {
	if v.tokens[token] {
		return true, nil
	}
	return false, ErrInvalidToken
}

// NewTokenAdapter creates a new token-based authentication adapter
func NewTokenAdapter(config *Config, validator TokenValidator) Port {
	if config == nil {
		config = DefaultConfig()
	}
	return &TokenAdapter{
		config:         config,
		tokenValidator: validator,
	}
}

func (a *TokenAdapter) Name() string {
	return "TokenAdapter"
}

func (a *TokenAdapter) GetUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if a.shouldSkipAuth(info.FullMethod) {
			return handler(ctx, req)
		}

		if err := a.ValidateCredentials(ctx); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func (a *TokenAdapter) GetStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if a.shouldSkipAuth(info.FullMethod) {
			return handler(srv, ss)
		}

		if err := a.ValidateCredentials(ss.Context()); err != nil {
			return err
		}

		return handler(srv, ss)
	}
}

func (a *TokenAdapter) ValidateCredentials(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, ErrMissingMetadata.Error())
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, ErrMissingAuthorization.Error())
	}

	token, found := strings.CutPrefix(values[0], "Bearer ")
	if !found {
		return status.Error(codes.Unauthenticated, ErrMissingAuthorization.Error())
	}

	valid, err := a.tokenValidator.ValidateToken(token)
	if err != nil || !valid {
		return status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	return nil
}

func (a *TokenAdapter) shouldSkipAuth(method string) bool {
	if a.config.SkipHealthCheck && (strings.HasSuffix(method, "/Check") || strings.HasSuffix(method, "/Watch")) {
		return true
	}

	return slices.Contains(a.config.AllowedMethods, method)
}

var _ Port = (*TokenAdapter)(nil)
