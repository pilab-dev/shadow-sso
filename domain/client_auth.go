package domain

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type ClientAuthMethod string

const (
	ClientAuthMethodSecret          ClientAuthMethod = "client_secret_basic"
	ClientAuthMethodSecretPost      ClientAuthMethod = "client_secret_post"
	ClientAuthMethodPrivateKeyJWT   ClientAuthMethod = "private_key_jwt"
	ClientAuthMethodTLSClientAuth   ClientAuthMethod = "tls_client_auth"
	ClientAuthMethodNone            ClientAuthMethod = "none"
)

var (
	ErrInvalidClientAssertion = errors.New("invalid client assertion")
	ErrInvalidJWTClientCreds   = errors.New("invalid jwt client credentials")
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

type JWTAssertionAuthenticator struct {
	realmKeys []*RealmKey
}

func NewJWTAssertionAuthenticator(realmKeys []*RealmKey) *JWTAssertionAuthenticator {
	return &JWTAssertionAuthenticator{realmKeys: realmKeys}
}

func (a *JWTAssertionAuthenticator) Authenticate(ctx context.Context, client *Client, clientID string, params map[string][]string) (*Client, error) {
	assertion := getFirstParam(params, "client_assertion")
	assertionType := getFirstParam(params, "client_assertion_type")

	if assertion == "" {
		return nil, NewInvalidClient("client_assertion required")
	}

	if !strings.Contains(assertionType, "jwt") {
		return nil, NewInvalidClient("invalid client_assertion_type")
	}

	token, err := jwt.ParseWithClaims(assertion, &ClientAssertionClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, ErrInvalidClientAssertion
		}

		for _, key := range a.realmKeys {
			if key.ID == kid && key.PrivateKey != "" {
				return a.parsePrivateKey(key.PrivateKey)
			}
		}

		return nil, ErrInvalidClientAssertion
	})
	if err != nil {
		return nil, ErrInvalidClientAssertion
	}

	claims, ok := token.Claims.(*ClientAssertionClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClientAssertion
	}

	if claims.Sub != clientID {
		return nil, NewInvalidClient("client_assertion sub does not match client_id")
	}

	if (claims.RegisteredClaims).ExpiresAt == nil || (claims.RegisteredClaims).ExpiresAt.Time.Before(time.Now()) {
		return nil, NewInvalidClient("client_assertion expired")
	}

	if claims.Aud == "" {
		claims.Aud = clientID
	}

	return client, nil
}

func (a *JWTAssertionAuthenticator) parsePrivateKey(pk string) (*rsa.PrivateKey, error) {
	var key rsa.PrivateKey
	if err := json.Unmarshal([]byte(pk), &key); err != nil {
		return nil, err
	}
	return &key, nil
}

type ClientJWTAuthenticator struct {
	client *Client
}

func NewClientJWTAuthenticator(client *Client) *ClientJWTAuthenticator {
	return &ClientJWTAuthenticator{client: client}
}

func (a *ClientJWTAuthenticator) Authenticate(ctx context.Context, client *Client, clientID string, params map[string][]string) (*Client, error) {
	assertion := getFirstParam(params, "client_assertion")
	assertionType := getFirstParam(params, "client_assertion_type")

	if assertion == "" {
		return nil, NewInvalidClient("client_assertion required")
	}

	if !strings.Contains(assertionType, "jwt") {
		return nil, NewInvalidClient("invalid client_assertion_type")
	}

	if a.client.JWKS == nil || len(a.client.JWKS.Keys) == 0 {
		return nil, NewInvalidClient("client has no JWKS configured")
	}

	token, err := jwt.ParseWithClaims(assertion, &ClientAssertionClaims{}, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, ErrInvalidClientAssertion
		}

		for _, key := range a.client.JWKS.Keys {
			if key.Kid == kid {
				return key.ToRSAKey()
			}
		}

		return nil, ErrInvalidClientAssertion
	})
	if err != nil {
		return nil, ErrInvalidClientAssertion
	}

	claims, ok := token.Claims.(*ClientAssertionClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClientAssertion
	}

	if claims.Sub != clientID {
		return nil, NewInvalidClient("client_assertion sub does not match client_id")
	}

	if (claims.RegisteredClaims).ExpiresAt == nil || (claims.RegisteredClaims).ExpiresAt.Time.Before(time.Now()) {
		return nil, NewInvalidClient("client_assertion expired")
	}

	return client, nil
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