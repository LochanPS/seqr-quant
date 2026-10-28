package pqcmap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PQCToken — a PQC-signed JWT (ML-DSA instead of RS256). Port of the Python/JS pqcmap
// PQCToken. Compact JOSE: base64url(header).base64url(payload).base64url(signature), with
// canonical sorted-key JSON, so a token signed by one SDK verifies in the others.
//
//	token, _ := pqcmap.EncodeToken(map[string]any{"sub": "123"}, secretKey, "ML-DSA-65")
//	claims, _ := pqcmap.DecodeToken(token, publicKey, true)
const tokenTyp = "PQC-JWT"

// canonicalJSON marshals v with sorted map keys, no HTML escaping, no trailing newline —
// byte-identical to Python's json.dumps(sort_keys=True, separators=(",", ":")) for ASCII.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func b64u(b []byte) string       { return base64.RawURLEncoding.EncodeToString(b) }
func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// EncodeToken signs payload and returns a compact token string (empty algorithm == ML-DSA-65).
func EncodeToken(payload map[string]any, secretKey []byte, algorithm string) (string, error) {
	if algorithm == "" {
		algorithm = DefaultSign
	}
	sig, err := NewSignature(algorithm)
	if err != nil {
		return "", err
	}
	header := map[string]any{"alg": algorithm, "typ": tokenTyp}
	hb, err := canonicalJSON(header)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	pb, err := canonicalJSON(payload)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	signingInput := b64u(hb) + "." + b64u(pb)
	signature, err := sig.Sign([]byte(signingInput), secretKey)
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64u(signature), nil
}

// DecodeToken verifies token against publicKey and returns its claims. When verifyExp is
// true a present, passed "exp" claim yields ErrTokenExpired.
func DecodeToken(token string, publicKey []byte, verifyExp bool) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: token must have three segments", ErrTokenInvalid)
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	hb, err := b64uDecode(headerB64)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed header: %v", ErrTokenInvalid, err)
	}
	pb, err := b64uDecode(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed payload: %v", ErrTokenInvalid, err)
	}
	signature, err := b64uDecode(sigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed signature: %v", ErrTokenInvalid, err)
	}

	var header map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	alg, _ := header["alg"].(string)
	if _, ok := signSchemes[alg]; !ok {
		return nil, fmt.Errorf("%w: unsupported token alg %q", ErrTokenInvalid, alg)
	}

	sig, err := NewSignature(alg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	signingInput := []byte(headerB64 + "." + payloadB64)
	ok, err := sig.Verify(signingInput, signature, publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: signature verification failed", ErrTokenInvalid)
	}

	var payload map[string]any
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if verifyExp {
		if raw, present := payload["exp"]; present {
			exp, ok := raw.(float64)
			if !ok {
				return nil, fmt.Errorf("%w: invalid 'exp' claim", ErrTokenInvalid)
			}
			if float64(time.Now().Unix()) > exp {
				return nil, ErrTokenExpired
			}
		}
	}
	return payload, nil
}
