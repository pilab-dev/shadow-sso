package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"
)

type Config struct {
	Issuer   string
	ClientID string
	Scopes   []string
}

type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"-"`
}

type IntrospectionResult struct {
	Active     bool     `json:"active"`
	Sub        string   `json:"sub"`
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	Roles      []string `json:"roles"`
	RealmRoles []string `json:"realm_access.roles"`
}

type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) scopes() string {
	out := ""
	for i, s := range c.cfg.Scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

func (c *Client) issuer() string {
	return strings.TrimRight(c.cfg.Issuer, "/")
}

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (c *Client) StartDeviceFlow(ctx context.Context) (*DeviceCodeResponse, error) {
	resp, err := c.http.PostForm(c.issuer()+"/oauth2/device_authorization", url.Values{
		"client_id": {c.cfg.ClientID},
		"scope":     {c.scopes()},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var dev DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		return nil, err
	}
	if dev.DeviceCode == "" {
		return nil, fmt.Errorf("device authorization failed")
	}
	return &dev, nil
}

func (c *Client) PollDeviceToken(ctx context.Context, dev *DeviceCodeResponse) (*Token, error) {
	interval := time.Duration(dev.Interval) * time.Second
	if interval < 2*time.Second {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dev.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		resp, err := c.http.PostForm(c.issuer()+"/oauth2/token", url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dev.DeviceCode},
			"client_id":   {c.cfg.ClientID},
		})
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var tok struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IDToken      string `json:"id_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
			Error        string `json:"error"`
		}
		json.Unmarshal(body, &tok)
		if tok.Error == "authorization_pending" {
			continue
		}
		if tok.Error != "" {
			return nil, fmt.Errorf("token error: %s", tok.Error)
		}
		if tok.AccessToken == "" {
			continue
		}
		tok2 := &Token{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			IDToken:      tok.IDToken,
			TokenType:    tok.TokenType,
			ExpiresIn:    tok.ExpiresIn,
		}
		if tok.ExpiresIn > 0 {
			tok2.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		}
		return tok2, nil
	}
	return nil, fmt.Errorf("device code flow timed out")
}

func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResult, error) {
	resp, err := c.http.PostForm(c.issuer()+"/oauth2/introspect", url.Values{
		"token": {token},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var res IntrospectionResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	if !res.Active {
		return nil, fmt.Errorf("token is not active")
	}
	return &res, nil
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	resp, err := c.http.PostForm(c.issuer()+"/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.cfg.ClientID},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var tok Token
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("refresh failed")
	}
	if tok.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return &tok, nil
}

func GRPCCredentials(token string) credentials.PerRPCCredentials {
	return &tokenCreds{token: token}
}

type tokenCreds struct {
	token string
}

func (t *tokenCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + t.token}, nil
}

func (t *tokenCreds) RequireTransportSecurity() bool {
	return false
}
