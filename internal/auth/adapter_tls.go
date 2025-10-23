package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	ErrNoPeerInfo         = errors.New("no peer info")
	ErrNoTLSInfo          = errors.New("no TLS info")
	ErrNoPeerCertificates = errors.New("no peer certificates")
	ErrInvalidCertificate = errors.New("invalid certificate")
)

// TLSAdapter implements mTLS (mutual TLS) authentication
type TLSAdapter struct {
	config       *Config
	allowedCNs   map[string]bool
	certVerifier CertificateVerifier
}

// CertificateVerifier defines the interface for custom certificate validation
type CertificateVerifier interface {
	VerifyCertificate(cert *x509.Certificate) error
}

// SimpleCertVerifier validates certificates based on Common Names
type SimpleCertVerifier struct {
	allowedCNs map[string]bool
}

func NewSimpleCertVerifier(allowedCNs []string) *SimpleCertVerifier {
	cns := make(map[string]bool)
	for _, cn := range allowedCNs {
		cns[cn] = true
	}
	return &SimpleCertVerifier{allowedCNs: cns}
}

func (v *SimpleCertVerifier) VerifyCertificate(cert *x509.Certificate) error {
	if v.allowedCNs[cert.Subject.CommonName] {
		return nil
	}
	return ErrInvalidCertificate
}

// NewTLSAdapter creates a new mTLS authentication adapter
func NewTLSAdapter(config *Config, verifier CertificateVerifier) Port {
	if config == nil {
		config = DefaultConfig()
	}
	return &TLSAdapter{
		config:       config,
		certVerifier: verifier,
	}
}

func (a *TLSAdapter) Name() string {
	return "TLSAdapter"
}

func (a *TLSAdapter) GetUnaryInterceptor() grpc.UnaryServerInterceptor {
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

func (a *TLSAdapter) GetStreamInterceptor() grpc.StreamServerInterceptor {
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

func (a *TLSAdapter) ValidateCredentials(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, ErrNoPeerInfo.Error())
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, ErrNoTLSInfo.Error())
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, ErrNoPeerCertificates.Error())
	}

	// Verify the client certificate
	cert := tlsInfo.State.PeerCertificates[0]
	if err := a.certVerifier.VerifyCertificate(cert); err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	return nil
}

func (a *TLSAdapter) shouldSkipAuth(method string) bool {
	if a.config.SkipHealthCheck && (strings.HasSuffix(method, "/Check") || strings.HasSuffix(method, "/Watch")) {
		return true
	}

	return slices.Contains(a.config.AllowedMethods, method)
}

// GetTLSConfig returns a TLS configuration for the gRPC server
func GetTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	ca, err := x509.SystemCertPool()
	if err != nil {
		ca = x509.NewCertPool()
	}

	if caFile != "" {
		caBytes, err := tls.LoadX509KeyPair(caFile, "")
		if err != nil {
			return nil, err
		}
		ca.AppendCertsFromPEM(caBytes.Certificate[0])
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca,
	}, nil
}

var _ Port = (*TLSAdapter)(nil)
