package glance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// OIDCProvider holds the configuration for a single OIDC/OAuth2 provider.
type OIDCProvider struct {
	Name         string `yaml:"name"`
	ClientID     string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
	IssuerURL    string `yaml:"issuer-url"`
	RedirectURL  string `yaml:"redirect-url"`

	// Cached provider metadata
	oauth2Config *oauth2.Config
	endpointData *oidcProviderMetadata
	mu           sync.RWMutex
}

// oidcProviderMetadata is the subset of OpenID Connect Discovery metadata we need.
type oidcProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// oidcStateCookieValue holds the data we store in the state cookie.
type oidcStateCookieValue struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	ProviderName string `json:"provider_name"`
	RedirectTo   string `json:"redirect_to"`
}

const (
	OIDC_STATE_COOKIE_NAME = "oidc_state"
	OIDC_STATE_COOKIE_TTL  = 10 * time.Minute
)

// initOIDCProvider discovers the OIDC provider metadata and configures the oauth2 client.
func (p *OIDCProvider) initOIDCProvider() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.IssuerURL == "" {
		return fmt.Errorf("oidc provider %q: issuer-url is required", p.Name)
	}
	if p.ClientID == "" {
		return fmt.Errorf("oidc provider %q: client-id is required", p.Name)
	}

	p.IssuerURL = strings.TrimRight(p.IssuerURL, "/")

	// Discover provider metadata
	metadata, err := discoverOIDCProvider(p.IssuerURL)
	if err != nil {
		return fmt.Errorf("oidc provider %q: %w", p.Name, err)
	}
	p.endpointData = metadata

	// Build the oauth2 config
	redirectURL := p.RedirectURL
	if redirectURL == "" {
		// Will be set at runtime using the application's base URL
		redirectURL = "__DYNAMIC__"
	}

	p.oauth2Config = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  metadata.AuthorizationEndpoint,
			TokenURL: metadata.TokenEndpoint,
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"openid", "profile", "email"},
	}

	return nil
}

// setRedirectURL sets the redirect URL dynamically based on the application's base URL.
func (p *OIDCProvider) setRedirectURL(baseURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.oauth2Config != nil && p.oauth2Config.RedirectURL == "__DYNAMIC__" {
		p.oauth2Config.RedirectURL = baseURL + "/api/oidc/callback/" + url.PathEscape(p.Name)
	}
}

// getOAuth2Config returns a copy of the oauth2 config (thread-safe).
func (p *OIDCProvider) getOAuth2Config() *oauth2.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.oauth2Config == nil {
		return nil
	}
	cfg := *p.oauth2Config
	return &cfg
}

// discoverOIDCProvider fetches the OpenID Connect Discovery metadata.
func discoverOIDCProvider(issuerURL string) (*oidcProviderMetadata, error) {
	wellKnownURL := issuerURL + "/.well-known/openid-configuration"

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("fetching openid-configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching openid-configuration returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("reading openid-configuration: %w", err)
	}

	var metadata oidcProviderMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("parsing openid-configuration: %w", err)
	}

	if metadata.Issuer == "" {
		return nil, fmt.Errorf("openid-configuration missing issuer")
	}
	if metadata.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("openid-configuration missing authorization_endpoint")
	}
	if metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("openid-configuration missing token_endpoint")
	}

	return &metadata, nil
}

// oidcLoginURL generates the authorization URL for a provider.
func (p *OIDCProvider) oidcLoginURL(redirectTo string) (string, *oidcStateCookieValue, error) {
	cfg := p.getOAuth2Config()
	if cfg == nil {
		return "", nil, fmt.Errorf("OIDC provider %q not initialized", p.Name)
	}

	// Generate state, nonce, and PKCE code verifier
	state, err := generateRandomString(32)
	if err != nil {
		return "", nil, fmt.Errorf("generating state: %w", err)
	}

	nonce, err := generateRandomString(32)
	if err != nil {
		return "", nil, fmt.Errorf("generating nonce: %w", err)
	}

	codeVerifier, err := generateRandomString(64)
	if err != nil {
		return "", nil, fmt.Errorf("generating code verifier: %w", err)
	}

	stateValue := &oidcStateCookieValue{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		ProviderName: p.Name,
		RedirectTo:   redirectTo,
	}

	// Build the authorization URL with PKCE
	codeChallenge := computeS256CodeChallenge(codeVerifier)

	authURL := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return authURL, stateValue, nil
}

// handleOIDCLogin initiates the OIDC login flow.
func (a *application) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	provider := a.getOIDCProvider(providerName)
	if provider == nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("OIDC provider not found"))
		return
	}

	// Parse redirect_to from query params
	redirectTo := r.URL.Query().Get("redirect_to")
	if redirectTo == "" {
		redirectTo = a.Config.Server.BaseURL + "/"
	}

	authURL, stateValue, err := provider.oidcLoginURL(redirectTo)
	if err != nil {
		log.Printf("Error generating OIDC login URL: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
		return
	}

	// Store state in a cookie
	stateJSON, err := json.Marshal(stateValue)
	if err != nil {
		log.Printf("Error marshaling OIDC state: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	encodedState := base64.StdEncoding.EncodeToString(stateJSON)
	http.SetCookie(w, &http.Cookie{
		Name:     OIDC_STATE_COOKIE_NAME,
		Value:    encodedState,
		Expires:  time.Now().Add(OIDC_STATE_COOKIE_TTL),
		Secure:   strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https",
		Path:     a.Config.Server.BaseURL + "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})

	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// handleOIDCCallback handles the OIDC provider callback after authentication.
func (a *application) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	// Read and validate the state cookie
	cookie, err := r.Cookie(OIDC_STATE_COOKIE_NAME)
	if err != nil {
		log.Printf("OIDC callback missing state cookie: %v", err)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=invalid_state", http.StatusSeeOther)
		return
	}

	stateJSON, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		log.Printf("OIDC callback invalid state cookie encoding: %v", err)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=invalid_state", http.StatusSeeOther)
		return
	}

	var stateValue oidcStateCookieValue
	if err := json.Unmarshal(stateJSON, &stateValue); err != nil {
		log.Printf("OIDC callback invalid state cookie JSON: %v", err)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=invalid_state", http.StatusSeeOther)
		return
	}

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     OIDC_STATE_COOKIE_NAME,
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     a.Config.Server.BaseURL + "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})

	// Verify the state parameter matches
	queryState := r.URL.Query().Get("state")
	if queryState == "" || queryState != stateValue.State {
		log.Printf("OIDC callback state mismatch")
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=state_mismatch", http.StatusSeeOther)
		return
	}

	// Check for errors from the provider
	if errorParam := r.URL.Query().Get("error"); errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("OIDC provider returned error: %s - %s", errorParam, errorDesc)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=provider_error", http.StatusSeeOther)
		return
	}

	// Get the authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Printf("OIDC callback missing authorization code")
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=missing_code", http.StatusSeeOther)
		return
	}

	provider := a.getOIDCProvider(stateValue.ProviderName)
	if provider == nil {
		log.Printf("OIDC callback unknown provider: %s", stateValue.ProviderName)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=unknown_provider", http.StatusSeeOther)
		return
	}

	// Exchange the authorization code for tokens
	cfg := provider.getOAuth2Config()
	if cfg == nil {
		log.Printf("OIDC provider %q not initialized", stateValue.ProviderName)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=provider_error", http.StatusSeeOther)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	token, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", stateValue.CodeVerifier),
	)
	if err != nil {
		log.Printf("OIDC token exchange failed for provider %q: %v", stateValue.ProviderName, err)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=token_exchange_failed", http.StatusSeeOther)
		return
	}

	// Extract the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		log.Printf("OIDC callback missing id_token for provider %q", stateValue.ProviderName)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=missing_id_token", http.StatusSeeOther)
		return
	}

	// Verify the ID token and extract claims
	claims, err := verifyAndParseIDToken(rawIDToken, provider, stateValue.Nonce, cfg.ClientID)
	if err != nil {
		log.Printf("OIDC id_token verification failed for provider %q: %v", stateValue.ProviderName, err)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=invalid_id_token", http.StatusSeeOther)
		return
	}

	// Determine the username from claims (prefer email, fallback to subject)
	username := claims.Email
	if username == "" {
		username = claims.Subject
	}
	if username == "" {
		log.Printf("OIDC callback could not determine username from claims")
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=no_identity", http.StatusSeeOther)
		return
	}

	// Ensure the user exists in our user store (auto-create if OIDC-only)
	a.ensureOIDCUser(username)

	// Create a session token and set cookie
	sessionToken, err := generateSessionToken(username, a.authSecretKey, time.Now())
	if err != nil {
		log.Printf("Could not compute session token for OIDC user: %v", err)
		http.Redirect(w, r, a.Config.Server.BaseURL+"/login?error=session_error", http.StatusSeeOther)
		return
	}

	a.setAuthSessionCookie(w, r, sessionToken, time.Now().Add(AUTH_TOKEN_VALID_PERIOD))

	// Redirect to the originally requested page or home
	redirectTo := stateValue.RedirectTo
	if redirectTo == "" {
		redirectTo = a.Config.Server.BaseURL + "/"
	}

	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

// getOIDCProvider looks up an OIDC provider by name.
func (a *application) getOIDCProvider(name string) *OIDCProvider {
	for i := range a.oidcProviders {
		if a.oidcProviders[i].Name == name {
			return &a.oidcProviders[i]
		}
	}
	return nil
}

// ensureOIDCUser ensures a user exists in the auth config for the given username.
// If the user doesn't exist, they are auto-created as an OIDC-only user.
func (a *application) ensureOIDCUser(username string) {
	a.authAttemptsMu.Lock()
	defer a.authAttemptsMu.Unlock()

	if _, exists := a.Config.Auth.Users[username]; exists {
		return
	}

	// Auto-create the user (OIDC-only, no password)
	a.Config.Auth.Users[username] = &user{}

	// Update the username hash mapping
	usernameHash, err := computeUsernameHash(username, a.authSecretKey)
	if err != nil {
		log.Printf("Error computing username hash for OIDC user %q: %v", username, err)
		return
	}
	a.usernameHashToUsername[string(usernameHash)] = username

	log.Printf("Auto-created OIDC user: %q", username)
}

// oidcIDTokenClaims holds the claims we extract from the ID token.
type oidcIDTokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	Nonce    string `json:"nonce"`
	Email    string `json:"email"`
}

// verifyAndParseIDToken validates a raw JWT ID token and returns its claims.
// This implements basic OIDC ID token validation without external JWT libraries.
func verifyAndParseIDToken(rawToken string, provider *OIDCProvider, expectedNonce, clientID string) (*oidcIDTokenClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode the header and payload (skip signature verification for now;
	// the token was received directly from the provider's token endpoint over TLS).
	// For a more complete implementation, verify the signature using the provider's JWKS.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims oidcIDTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	//
	// Validate claims per OIDC spec
	//

	// 1. iss must match the provider's issuer
	provider.mu.RLock()
	expectedIssuer := provider.IssuerURL
	if provider.endpointData != nil {
		expectedIssuer = provider.endpointData.Issuer
	}
	provider.mu.RUnlock()

	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("issuer mismatch: got %q, expected %q", claims.Issuer, expectedIssuer)
	}

	// 2. aud must include our client_id
	if claims.Audience != clientID {
		return nil, fmt.Errorf("audience mismatch: got %q, expected %q", claims.Audience, clientID)
	}

	// 3. exp must be in the future
	now := time.Now().Unix()
	if claims.Expires != 0 && claims.Expires < now {
		return nil, fmt.Errorf("token expired at %d (now: %d)", claims.Expires, now)
	}

	// 4. iat should not be too far in the future (with 5 minute leeway)
	if claims.IssuedAt != 0 && claims.IssuedAt > now+300 {
		return nil, fmt.Errorf("token issued too far in the future: %d", claims.IssuedAt)
	}

	// 5. nonce must match what we sent
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	return &claims, nil
}

// generateRandomString creates a cryptographically random string of the given byte length,
// encoded as base64 URL-safe without padding.
func generateRandomString(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// computeS256CodeChallenge computes the PKCE S256 code challenge from a verifier.
func computeS256CodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
