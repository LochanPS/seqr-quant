package pqcmap

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestHybridRoundTrip(t *testing.T) {
	h, err := NewHybridKEM("")
	if err != nil {
		t.Fatal(err)
	}
	pk, sk, err := h.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != 32+1184 || len(sk) != 32+2400 {
		t.Fatalf("hybrid key sizes wrong: pk=%d sk=%d", len(pk), len(sk))
	}
	ct, ss, err := h.Encapsulate(pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 32+1088 {
		t.Fatalf("hybrid ct size wrong: %d", len(ct))
	}
	ss2, err := h.Decapsulate(sk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss, ss2) || len(ss) != 32 {
		t.Fatal("hybrid shared secrets differ")
	}
}

func TestCombineSecretsParityVector(t *testing.T) {
	classical := make([]byte, 32)
	pqc := make([]byte, 32)
	for i := 0; i < 32; i++ {
		classical[i] = byte(i)
		pqc[i] = byte(100 + i)
	}
	out, err := CombineSecrets(classical, pqc)
	if err != nil {
		t.Fatal(err)
	}
	// Same vector as the Python and JS SDKs (cross-language interop).
	const want = "11b9f197bb60fe68e66aeb5986a8f9df5fe9dfdf318a41f23366334429b5e4d1"
	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("KDF vector mismatch:\n got  %s\n want %s", got, want)
	}
}

func TestJWTRoundTrip(t *testing.T) {
	sig, _ := NewSignature("ML-DSA-65")
	pk, sk, _ := sig.GenerateKeypair()
	token, err := EncodeToken(map[string]any{"sub": "123", "role": "admin"}, sk, "ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := DecodeToken(token, pk, true)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "123" || claims["role"] != "admin" {
		t.Fatalf("claims wrong: %+v", claims)
	}
	// wrong key -> invalid
	other, _ := NewSignature("ML-DSA-65")
	_, opk, _ := other.GenerateKeypair()
	if _, err := DecodeToken(token, opk, true); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestJWTExpiry(t *testing.T) {
	sig, _ := NewSignature("ML-DSA-65")
	pk, sk, _ := sig.GenerateKeypair()
	expired, _ := EncodeToken(map[string]any{"sub": "x", "exp": float64(time.Now().Unix() - 10)}, sk, "")
	if _, err := DecodeToken(expired, pk, true); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	if _, err := DecodeToken(expired, pk, false); err != nil {
		t.Fatalf("exp ignored should decode: %v", err)
	}
}

func TestJWTCanonicalJSON(t *testing.T) {
	// sorted keys, no spaces — must match Python json.dumps(sort_keys=True, separators=(",",":"))
	out, err := canonicalJSON(map[string]any{"b": float64(1), "a": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":"x","b":1}` {
		t.Fatalf("canonical JSON = %s", out)
	}
}

func TestPolicyDefault(t *testing.T) {
	if err := AssertCompliant("ML-KEM-768", "kem"); err != nil {
		t.Fatalf("ML-KEM-768 should be allowed: %v", err)
	}
	if err := AssertCompliant("ML-DSA-65", "sign"); err != nil {
		t.Fatalf("ML-DSA-65 should be allowed: %v", err)
	}
	if err := AssertCompliant("RSA-2048", ""); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("RSA-2048 should be forbidden, got %v", err)
	}
	if err := AssertCompliant("ML-KEM-512", "kem"); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("ML-KEM-512 below L3 should fail, got %v", err)
	}
}

func TestCompliantConstructors(t *testing.T) {
	if _, err := NewCompliantKeyEncapsulation(""); err != nil {
		t.Fatalf("default KEM should be allowed: %v", err)
	}
	if _, err := NewCompliantKeyEncapsulation("ML-KEM-512"); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("ML-KEM-512 should be refused, got %v", err)
	}
	if _, err := NewCompliantSignature("ML-DSA-44"); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("ML-DSA-44 should be refused, got %v", err)
	}
}

func TestPolicyCustomBodyAndActiveSwap(t *testing.T) {
	strict := map[string]any{
		"name": "strict L5",
		"rules": []any{
			map[string]any{"key": "l5", "type": "min_nist_level", "min": float64(5), "severity": "urgent", "target": "Level 5"},
		},
	}
	p, err := NewCryptoPolicy(strict)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Evaluate("ML-KEM-768", "kem")) == 0 {
		t.Fatal("ML-KEM-768 should violate an L5 policy")
	}
	if len(p.Evaluate("ML-KEM-1024", "kem")) != 0 {
		t.Fatal("ML-KEM-1024 should satisfy an L5 policy")
	}

	SetActivePolicy(p)
	defer SetActivePolicy(nil)
	if IsCompliant("ML-KEM-768", "kem") {
		t.Fatal("active L5 policy should reject ML-KEM-768")
	}
}
