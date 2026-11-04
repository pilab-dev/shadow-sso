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
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the DPoP proof claims (RFC 9449).
type Claims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"`
	jwt.RegisteredClaims
}

// VerifyProof validates a DPoP proof and returns the JWK thumbprint (jkt) of
// the proof key. now is used for iat window checks.
func VerifyProof(proof, htm, htu, ath string, now time.Time) (string, error) {
	if proof == "" {
		return "", fmt.Errorf("missing DPoP proof")
	}
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(proof, &Claims{})
	if err != nil {
		return "", fmt.Errorf("invalid DPoP proof: %w", err)
	}
	header := unverified.Header
	jwkMap, ok := header["jwk"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing jwk in DPoP proof header")
	}
	alg, _ := header["alg"].(string)
	if alg == "" {
		return "", fmt.Errorf("missing alg in DPoP proof header")
	}
	pub, err := publicKeyFromJWK(jwkMap, alg)
	if err != nil {
		return "", err
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(proof, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != alg {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return pub, nil
	}, jwt.WithLeeway(5*time.Minute))
	if err != nil {
		return "", fmt.Errorf("DPoP proof signature invalid: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("DPoP proof invalid")
	}
	if claims.JTI == "" {
		return "", fmt.Errorf("missing jti")
	}
	if !strings.EqualFold(claims.HTM, htm) {
		return "", fmt.Errorf("htm mismatch")
	}
	if normalizeHTU(claims.HTU) != normalizeHTU(htu) {
		return "", fmt.Errorf("htu mismatch")
	}
	iat := time.Unix(claims.IAT, 0)
	if now.Sub(iat) > 5*time.Minute || iat.Sub(now) > 5*time.Minute {
		return "", fmt.Errorf("iat out of range")
	}
	if typ, _ := header["typ"].(string); typ != "dpop+jwt" {
		return "", fmt.Errorf("invalid typ")
	}
	if ath != "" {
		if claims.ATH != ath {
			return "", fmt.Errorf("ath mismatch")
		}
	}
	return thumbprint(jwkMap), nil
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
	sum := sha256Sum(canonical)
	return base64.RawURLEncoding.EncodeToString(sum)
}

// AccessTokenHash returns the base64url-encoded SHA-256 digest of an access
// token, used as the `ath` claim in DPoP proofs for resource requests.
func AccessTokenHash(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func sha256Sum(s string) []byte {
	// avoid import cycle? use crypto/sha256
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}
