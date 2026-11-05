package domain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type ClientAuthMethod string

const (
	ClientAuthMethodSecret        ClientAuthMethod = "client_secret_basic"
	ClientAuthMethodSecretPost    ClientAuthMethod = "client_secret_post"
	ClientAuthMethodPrivateKeyJWT ClientAuthMethod = "private_key_jwt"
	ClientAuthMethodTLSClientAuth ClientAuthMethod = "tls_client_auth"
	ClientAuthMethodNone          ClientAuthMethod = "none"
)

var (
	ErrInvalidClientAssertion = errors.New("invalid client assertion")
	ErrInvalidJWTClientCreds  = errors.New("invalid jwt client credentials")
)

type ClientAssertionClaims struct {
	jwt.RegisteredClaims
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
}

type ClientAuthenticator interface {
	Authenticate(ctx context.Context, client *Client, clientID string, params map[string][]string) (*Client, error)
}

type SecretAuthenticator struct {
	clientRepo ClientRepository
}

func NewSecretAuthenticator(clientRepo ClientRepository) *SecretAuthenticator {
	return &SecretAuthenticator{clientRepo: clientRepo}
}

func (a *SecretAuthenticator) Authenticate(ctx context.Context, client *Client, clientID string, params map[string][]string) (*Client, error) {
	clientSecret := getFirstParam(params, "client_secret")
	if clientSecret == "" {
		return nil, NewInvalidClient("client_secret required")
	}
	return a.clientRepo.ValidateClient(ctx, clientID, clientSecret)
}

// ClientAssertionTypeJWTBearer is the client_assertion_type required by RFC 7523 §2.2.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// maxClientAssertionLifetime bounds how far in the future an assertion may expire.
const maxClientAssertionLifetime = 5 * time.Minute

// ClientAssertionAlgs are the asymmetric algorithms accepted for private_key_jwt.
var ClientAssertionAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

// assertionReplayCache remembers (client, jti) pairs until the assertion expires.
type assertionReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var defaultAssertionReplayCache = &assertionReplayCache{seen: map[string]time.Time{}}

// claim returns false when the key was already used and has not expired.
func (c *assertionReplayCache) claim(key string, expires, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.seen {
		if !exp.After(now) {
			delete(c.seen, k)
		}
	}
	if _, used := c.seen[key]; used {
		return false
	}
	c.seen[key] = expires
	return true
}

// ClientJWTAuthenticator verifies private_key_jwt client assertions (RFC 7523)
// against the public keys registered in the client's JWKS.
type ClientJWTAuthenticator struct {
	client *Client
	// audiences lists the values accepted in the assertion's aud claim
	// (the issuer and the endpoint URL).
	audiences []string
}

func NewClientJWTAuthenticator(client *Client, audiences ...string) *ClientJWTAuthenticator {
	return &ClientJWTAuthenticator{client: client, audiences: audiences}
}

func (a *ClientJWTAuthenticator) Authenticate(ctx context.Context, client *Client, clientID string, params map[string][]string) (*Client, error) {
	assertion := getFirstParam(params, "client_assertion")
	assertionType := getFirstParam(params, "client_assertion_type")

	if assertion == "" {
		return nil, NewInvalidClient("client_assertion required")
	}
	if assertionType != ClientAssertionTypeJWTBearer {
		return nil, NewInvalidClient("invalid client_assertion_type")
	}
	if a.client == nil || a.client.ID != clientID {
		return nil, NewInvalidClient("unknown client")
	}
	if a.client.JWKS == nil || len(a.client.JWKS.Keys) == 0 {
		return nil, NewInvalidClient("client has no JWKS configured")
	}

	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(assertion, &claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		var candidate *JSONWebKey
		for i := range a.client.JWKS.Keys {
			key := &a.client.JWKS.Keys[i]
			if key.Use != "" && key.Use != "sig" {
				continue
			}
			if kid != "" && key.Kid != kid {
				continue
			}
			if candidate != nil {
				return nil, ErrInvalidClientAssertion // ambiguous without kid
			}
			candidate = key
		}
		if candidate == nil {
			return nil, ErrInvalidClientAssertion
		}
		return candidate.ToRSAPublicKey()
	}, jwt.WithValidMethods(ClientAssertionAlgs), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil || !token.Valid {
		return nil, ErrInvalidClientAssertion
	}

	if claims.Issuer != clientID || claims.Subject != clientID {
		return nil, NewInvalidClient("client_assertion iss and sub must equal client_id")
	}

	audOK := false
	for _, aud := range claims.Audience {
		for _, want := range a.audiences {
			if aud == want {
				audOK = true
			}
		}
	}
	if !audOK {
		return nil, NewInvalidClient("client_assertion aud does not match this server")
	}

	now := time.Now()
	if claims.ExpiresAt.Time.After(now.Add(maxClientAssertionLifetime)) {
		return nil, NewInvalidClient("client_assertion lifetime too long")
	}
	if claims.ID == "" {
		return nil, NewInvalidClient("client_assertion jti required")
	}
	if !defaultAssertionReplayCache.claim(clientID+"\x00"+claims.ID, claims.ExpiresAt.Time.Add(30*time.Second), now) {
		return nil, NewInvalidClient("client_assertion replayed")
	}

	return a.client, nil
}

type MTLSAuthenticator struct{}

func NewMTLSAuthenticator() *MTLSAuthenticator {
	return &MTLSAuthenticator{}
}

func (a *MTLSAuthenticator) Authenticate(ctx context.Context, client *Client, clientID string, params map[string][]string) (*Client, error) {
	certSubject := getFirstParam(params, "tls_client_auth_cert_subject")
	if certSubject == "" {
		return nil, NewInvalidClient("TLS certificate required for MTLS authentication")
	}

	return client, nil
}

func getFirstParam(params map[string][]string, key string) string {
	if v, ok := params[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func CreateClientAssertion(clientID, issuer, audience string, privateKey *rsa.PrivateKey, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := ClientAssertionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    issuer,
			ID:        uuid.New().String(),
		},
		Iss: issuer,
		Sub: clientID,
		Aud: audience,
		Jti: uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = privateKey.PublicKey.N.String()[:32]

	return token.SignedString(privateKey)
}

type ClientKeyGenerator struct{}

func NewClientKeyGenerator() *ClientKeyGenerator {
	return &ClientKeyGenerator{}
}

func (g *ClientKeyGenerator) GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		bits = 2048
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

func (g *ClientKeyGenerator) GenerateJWKS(key *rsa.PrivateKey, kid string) *JWKS {
	if kid == "" {
		kid = uuid.New().String()
	}

	return &JWKS{
		Keys: []JSONWebKey{
			{
				Kid: kid,
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   key.PublicKey.N.String(),
				E:   fmt.Sprintf("%d", key.PublicKey.E),
				D:   key.D.String(),
				P:   key.Primes[0].String(),
				Q:   key.Primes[1].String(),
			},
		},
	}
}
