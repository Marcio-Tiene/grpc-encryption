package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	ErrInvalidOAuth2Token = errors.New("invalid OAuth2 token")
	ErrExpiredToken       = errors.New("token expired")
	ErrInvalidIssuer      = errors.New("issuer not allowed")
	ErrInvalidSignature   = errors.New("invalid token signature")
	ErrMissingKid         = errors.New("missing key ID in token header")
	ErrKeyNotFound        = errors.New("signing key not found in JWKS")
	ErrInvalidTokenFormat = errors.New("invalid token format")
)

// OAuth2Adapter implements OAuth2 JWT authentication with JWKS
type OAuth2Adapter struct {
	config         *Config
	allowedIssuers []string
	httpClient     *http.Client
	jwksCache      map[string]*JWKSKeys // Cache JWKS by issuer
	cacheMutex     sync.RWMutex
	cacheExpiry    time.Duration
}

// JWKSKeys holds JWKS response and cache info
type JWKSKeys struct {
	Keys      []JWK
	FetchedAt time.Time
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWTHeader represents JWT header
type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// JWTClaims represents JWT claims
type JWTClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud any    `json:"aud"` // Can be string or []string
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

// OAuth2Config holds OAuth2-specific configuration
type OAuth2Config struct {
	AllowedIssuers []string // List of allowed issuer URLs (domain/realm)
	HTTPTimeout    time.Duration
	CacheExpiry    time.Duration // How long to cache JWKS keys
}

// NewOAuth2Adapter creates a new OAuth2 JWT authentication adapter with JWKS
func NewOAuth2Adapter(config *Config, oauth2Config *OAuth2Config) Port {
	if config == nil {
		config = DefaultConfig()
	}

	timeout := oauth2Config.HTTPTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	cacheExpiry := oauth2Config.CacheExpiry
	if cacheExpiry == 0 {
		cacheExpiry = 1 * time.Hour
	}

	return &OAuth2Adapter{
		config:         config,
		allowedIssuers: oauth2Config.AllowedIssuers,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		jwksCache:   make(map[string]*JWKSKeys),
		cacheExpiry: cacheExpiry,
	}
}

func (a *OAuth2Adapter) Name() string {
	return "OAuth2Adapter"
}

func (a *OAuth2Adapter) GetUnaryInterceptor() grpc.UnaryServerInterceptor {
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

func (a *OAuth2Adapter) GetStreamInterceptor() grpc.StreamServerInterceptor {
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

func (a *OAuth2Adapter) ValidateCredentials(ctx context.Context) error {
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

	// Validate JWT token using JWKS
	if err := a.validateJWT(ctx, token); err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	return nil
}

// validateJWT validates the JWT token using JWKS
func (a *OAuth2Adapter) validateJWT(ctx context.Context, token string) error {
	// Parse JWT (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidTokenFormat
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid token header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid token header JSON: %w", err)
	}

	if header.Kid == "" {
		return ErrMissingKid
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid token claims: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return fmt.Errorf("invalid token claims JSON: %w", err)
	}

	// Verify issuer is allowed
	if !a.isIssuerAllowed(claims.Iss) {
		return fmt.Errorf("%w: %s", ErrInvalidIssuer, claims.Iss)
	}

	// Verify token timing
	now := time.Now().Unix()
	if claims.Exp > 0 && now > claims.Exp {
		return ErrExpiredToken
	}
	if claims.Nbf > 0 && now < claims.Nbf {
		return errors.New("token not yet valid")
	}

	// Get JWKS keys for this issuer
	jwks, err := a.getJWKS(ctx, claims.Iss)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Find the key by kid
	var jwk *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == header.Kid {
			jwk = &jwks.Keys[i]
			break
		}
	}
	if jwk == nil {
		return ErrKeyNotFound
	}

	// Verify signature
	signedContent := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	publicKey, err := a.jwkToPublicKey(jwk)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	if err := a.verifySignature(publicKey, signedContent, signature, header.Alg); err != nil {
		return ErrInvalidSignature
	}

	return nil
}

// isIssuerAllowed checks if the issuer is in the allowed list
func (a *OAuth2Adapter) isIssuerAllowed(issuer string) bool {
	// Normalize issuer (remove trailing slash)
	issuer = strings.TrimSuffix(issuer, "/")

	for _, allowed := range a.allowedIssuers {
		allowed = strings.TrimSuffix(allowed, "/")
		if issuer == allowed {
			return true
		}
	}
	return false
}

// getJWKS fetches or retrieves from cache the JWKS for an issuer
func (a *OAuth2Adapter) getJWKS(ctx context.Context, issuer string) (*JWKSKeys, error) {
	// Check cache first
	a.cacheMutex.RLock()
	cached, found := a.jwksCache[issuer]
	a.cacheMutex.RUnlock()

	if found && time.Since(cached.FetchedAt) < a.cacheExpiry {
		return cached, nil
	}

	// Fetch from JWKS endpoint
	jwksURL, err := a.buildJWKSURL(issuer)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status: %d", resp.StatusCode)
	}

	var jwksResponse struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwksResponse); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	jwks := &JWKSKeys{
		Keys:      jwksResponse.Keys,
		FetchedAt: time.Now(),
	}

	// Update cache
	a.cacheMutex.Lock()
	a.jwksCache[issuer] = jwks
	a.cacheMutex.Unlock()

	return jwks, nil
}

// buildJWKSURL constructs the JWKS URL from the issuer
func (a *OAuth2Adapter) buildJWKSURL(issuer string) (string, error) {
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL: %w", err)
	}

	// Standard JWKS endpoint
	issuerURL.Path = strings.TrimSuffix(issuerURL.Path, "/") + "/protocol/openid-connect/certs"
	return issuerURL.String(), nil
}

// jwkToPublicKey converts a JWK to an RSA public key
func (a *OAuth2Adapter) jwkToPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}

	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// verifySignature verifies the JWT signature
func (a *OAuth2Adapter) verifySignature(publicKey *rsa.PublicKey, signedContent string, signature []byte, alg string) error {
	// Only support RS256 for now
	if alg != "RS256" {
		return fmt.Errorf("unsupported signing algorithm: %s", alg)
	}

	// Hash the signed content
	hash := sha256.Sum256([]byte(signedContent))

	// Verify the signature
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func (a *OAuth2Adapter) shouldSkipAuth(method string) bool {
	if a.config.SkipHealthCheck && (strings.HasSuffix(method, "/Check") || strings.HasSuffix(method, "/Watch")) {
		return true
	}

	return slices.Contains(a.config.AllowedMethods, method)
}

var _ Port = (*OAuth2Adapter)(nil)
