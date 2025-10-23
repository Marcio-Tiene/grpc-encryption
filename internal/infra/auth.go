package infra

import (
	"log"

	"grpc-encryption-service/internal/auth"
	"grpc-encryption-service/internal/config"
	"grpc-encryption-service/internal/helper"
)

// InitializeAuthManager sets up all authentication adapters
func InitializeAuthManager() *auth.Manager {
	managerConfig := &auth.ManagerConfig{
		DefaultAdapter:  config.GetEnv("DEFAULT_AUTH_TYPE", "token"),
		RequireAuthType: config.GetEnv("REQUIRE_AUTH_TYPE", "false") == "true",
		Config:          auth.DefaultConfig(),
	}

	manager := auth.NewManager(managerConfig)

	// Register Token adapter
	if config.GetEnv("ENABLE_TOKEN_AUTH", "true") == "true" {
		tokensEnv := config.GetEnv("AUTH_TOKENS", "secret-token-123,another-valid-token")
		tokens := helper.SplitAndTrim(tokensEnv, ",")
		validator := auth.NewSimpleTokenValidator(tokens)
		tokenAdapter := auth.NewTokenAdapter(auth.DefaultConfig(), validator)
		manager.RegisterAdapter("token", tokenAdapter)
		log.Println("✅ Token authentication enabled")
	}

	// Register TLS adapter
	if config.GetEnv("ENABLE_TLS_AUTH", "false") == "true" {
		cnsEnv := config.GetEnv("AUTH_ALLOWED_CNS", "client.example.com,trusted-client.example.com")
		allowedCNs := helper.SplitAndTrim(cnsEnv, ",")
		verifier := auth.NewSimpleCertVerifier(allowedCNs)
		tlsAdapter := auth.NewTLSAdapter(auth.DefaultConfig(), verifier)
		manager.RegisterAdapter("tls", tlsAdapter)
		log.Println("✅ TLS/mTLS authentication enabled")
	}

	// Register OAuth2 adapter (JWKS-based)
	if config.GetEnv("ENABLE_OAUTH2_AUTH", "false") == "true" {
		issuersEnv := config.GetEnv("OAUTH2_ALLOWED_ISSUERS", "https://keycloak.example.com/realms/myrealm")
		allowedIssuers := helper.SplitAndTrim(issuersEnv, ",")

		oauth2Config := &auth.OAuth2Config{
			AllowedIssuers: allowedIssuers,
		}
		oauth2Adapter := auth.NewOAuth2Adapter(auth.DefaultConfig(), oauth2Config)
		manager.RegisterAdapter("oauth2", oauth2Adapter)
		log.Printf("✅ OAuth2/JWKS authentication enabled (allowed issuers: %v)", allowedIssuers)
	}

	adapters := manager.GetRegisteredAdapters()
	if len(adapters) == 0 {
		log.Fatal("No authentication adapters enabled! Set ENABLE_*_AUTH environment variables.")
	}

	log.Printf("Registered authentication adapters: %v", adapters)
	log.Printf("Default authentication type: %s", managerConfig.DefaultAdapter)

	return manager
}
