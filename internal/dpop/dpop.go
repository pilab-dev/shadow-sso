package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ProofLifetime is how long a proof is accepted around its iat and how long a
// seen jti is remembered for replay rejection (RFC 9449 §11.1).
const ProofLifetime = 5 * time.Minute

// maxReplayEntries bounds the in-process replay cache so a burst of distinct
// proofs cannot grow it without limit.
const maxReplayEntries = 100_000

// Claims are the DPoP proof claims (RFC 9449).
type Claims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"`
	jwt.RegisteredClaims
}

// replayCache remembers recently seen (jkt, jti) pairs.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[string]time.Time)}
}

// claim records key and reports false when it was already seen and has not yet
// expired. Expired entries are pruned on write.
func (c *replayCache) claim(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[key]; ok && now.Before(exp) {
		return false
	}
	if len(c.seen) >= maxReplayEntries {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= maxReplayEntries {
			// Still saturated by live entries: forget the oldest half rather
			// than grow without bound. This only weakens replay rejection for
			// proofs that are already close to expiry.
			for k := range c.seen {
				delete(c.seen, k)
				if len(c.seen) < maxReplayEntries/2 {
					break
				}
			}
		}
	}
	c.seen[key] = now.Add(ProofLifetime)
	return true
}

var defaultReplayCache = newReplayCache()

// VerifyProof validates a DPoP proof and returns the JWK thumbprint (jkt) of
// the proof key. now is used for iat window checks.
//
// Callers handling live requests should use VerifyProofOnce, which also
// rejects replayed jti values.
func VerifyProof(proof, htm, htu, ath string, now time.Time) (string, error) {
	jkt, _, err := verifyProof(proof, htm, htu, ath, now)
	return jkt, err
}

// VerifyProofOnce validates a DPoP proof and rejects a (key, jti) pair that has
// already been accepted within ProofLifetime.
func VerifyProofOnce(proof, htm, htu, ath string, now time.Time) (string, error) {
	jkt, jti, err := verifyProof(proof, htm, htu, ath, now)
	if err != nil {
		return "", err
	}
	if !defaultReplayCache.claim(jkt+"\x00"+jti, now) {
		return "", fmt.Errorf("DPoP proof replayed")
	}
	return jkt, nil
}

func verifyProof(proof, htm, htu, ath string, now time.Time) (string, string, error) {
	if proof == "" {
		return "", "", fmt.Errorf("missing DPoP proof")
	}
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(proof, &Claims{})
	if err != nil {
		return "", "", fmt.Errorf("invalid DPoP proof: %w", err)
	}
	header := unverified.Header
	jwkMap, ok := header["jwk"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("missing jwk in DPoP proof header")
	}
	alg, _ := header["alg"].(string)
	if alg == "" {
		return "", "", fmt.Errorf("missing alg in DPoP proof header")
	}
	pub, err := publicKeyFromJWK(jwkMap, alg)
	if err != nil {
		return "", "", err
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(proof, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != alg {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return pub, nil
	}, jwt.WithLeeway(ProofLifetime))
	if err != nil {
		return "", "", fmt.Errorf("DPoP proof signature invalid: %w", err)
	}
	if !token.Valid {
		return "", "", fmt.Errorf("DPoP proof invalid")
	}
	if claims.JTI == "" {
		return "", "", fmt.Errorf("missing jti")
	}
	if !strings.EqualFold(claims.HTM, htm) {
		return "", "", fmt.Errorf("htm mismatch")
	}
	if normalizeHTU(claims.HTU) != normalizeHTU(htu) {
		return "", "", fmt.Errorf("htu mismatch")
	}
	iat := time.Unix(claims.IAT, 0)
	if now.Sub(iat) > ProofLifetime || iat.Sub(now) > ProofLifetime {
		return "", "", fmt.Errorf("iat out of range")
	}
	if typ, _ := header["typ"].(string); typ != "dpop+jwt" {
		return "", "", fmt.Errorf("invalid typ")
	}
	if ath != "" {
		if claims.ATH != ath {
			return "", "", fmt.Errorf("ath mismatch")
		}
	}
	return thumbprint(jwkMap), claims.JTI, nil
}

func normalizeHTU(v string) string {
	u, err := url.Parse(v)
	if err != nil {
		return strings.TrimRight(v, "/")
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func publicKeyFromJWK(jwk map[string]interface{}, alg string) (interface{}, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "RSA":
		nStr, _ := jwk["n"].(string)
		eStr, _ := jwk["e"].(string)
		nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e*256 + int(b)
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		crv, _ := jwk["crv"].(string)
		xStr, _ := jwk["x"].(string)
		yStr, _ := jwk["y"].(string)
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve")
		}
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported kty")
	}
}

func thumbprint(jwk map[string]interface{}) string {
	kty, _ := jwk["kty"].(string)
	var canonical string
	switch kty {
	case "RSA":
		canonical = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk["e"], jwk["n"])
	case "EC":
		canonical = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, jwk["crv"], jwk["x"], jwk["y"])
	default:
		b, _ := json.Marshal(jwk)
		canonical = string(b)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AccessTokenHash returns the base64url-encoded SHA-256 digest of an access
// token, used as the `ath` claim in DPoP proofs for resource requests.
func AccessTokenHash(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
