package pqcmap

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tmpStorePath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "keys.enc")
}

func TestLocalKeyStoreSignVerify(t *testing.T) {
	ks, err := NewLocalKeyStore("secret", tmpStorePath(t), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := ks.GenerateAndStore("ML-DSA-65", map[string]any{"purpose": "jwt"})
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ks.GetPrivateKey(kid, true)
	pub, _ := ks.GetPublicKey(kid)
	sig, _ := NewSignature("ML-DSA-65")
	msg := []byte("hello")
	signature, _ := sig.Sign(msg, priv)
	ok, _ := sig.Verify(msg, signature, pub)
	if !ok {
		t.Fatal("signature from stored key did not verify")
	}
	meta, _ := ks.GetMetadata(kid)
	if meta["uses"].(int) != 1 {
		t.Fatalf("expected 1 use, got %v", meta["uses"])
	}
}

func TestLocalKeyStorePersistAndWrongPassphrase(t *testing.T) {
	path := tmpStorePath(t)
	ks, _ := NewLocalKeyStore("right", path, nil, true)
	kid, _ := ks.GenerateAndStore("ML-KEM-768", nil)
	pub, _ := ks.GetPublicKey(kid)

	reopened, err := NewLocalKeyStore("right", path, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _ := reopened.GetPublicKey(kid)
	if !bytes.Equal(pub, pub2) {
		t.Fatal("public key changed across reopen")
	}
	if _, err := NewLocalKeyStore("wrong", path, nil, true); !errors.Is(err, ErrKMSAuth) {
		t.Fatalf("wrong passphrase should be ErrKMSAuth, got %v", err)
	}
}

func TestLocalKeyStoreRotationByUses(t *testing.T) {
	two := 2
	ks, _ := NewLocalKeyStore("secret", tmpStorePath(t), &RotationPolicy{MaxUses: &two}, true)
	kid, _ := ks.GenerateAndStore("ML-DSA-65", nil)
	ks.GetPrivateKey(kid, true)
	if need, _ := ks.NeedsRotation(kid); need {
		t.Fatal("should not need rotation after 1 use")
	}
	ks.GetPrivateKey(kid, true)
	newId, err := ks.RotateIfNeeded(kid)
	if err != nil || newId == "" || newId == kid {
		t.Fatalf("expected rotation, got id=%q err=%v", newId, err)
	}
	meta, _ := ks.GetMetadata(kid)
	if meta["status"] != "rotated" {
		t.Fatalf("old key status = %v", meta["status"])
	}
}

func TestLocalKeyStoreExportImport(t *testing.T) {
	a, _ := NewLocalKeyStore("store-a", tmpStorePath(t), nil, true)
	kid, _ := a.GenerateAndStore("ML-DSA-65", nil)
	pub, _ := a.GetPublicKey(kid)
	blob, err := a.ExportKey(kid, "transfer-pass")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewLocalKeyStore("store-b", tmpStorePath(t), nil, true)
	importedID, err := b.ImportKey(blob, "transfer-pass")
	if err != nil {
		t.Fatal(err)
	}
	pub2, _ := b.GetPublicKey(importedID)
	if !bytes.Equal(pub, pub2) {
		t.Fatal("imported public key differs")
	}
	if _, err := b.ImportKey(blob, "wrong"); !errors.Is(err, ErrKMSAuth) {
		t.Fatalf("wrong export passphrase should be ErrKMSAuth, got %v", err)
	}
}

func TestLocalKeyStoreAuditTamper(t *testing.T) {
	path := tmpStorePath(t)
	ks, _ := NewLocalKeyStore("secret", path, nil, true)
	ks.GenerateAndStore("ML-DSA-65", nil)
	if err := ks.VerifyAuditLog(); err != nil {
		t.Fatalf("fresh audit log should verify: %v", err)
	}
	// tamper the first entry's op
	data, _ := os.ReadFile(path + ".audit.log")
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var e map[string]any
	json.Unmarshal([]byte(lines[0]), &e)
	e["op"] = "forged"
	b, _ := json.Marshal(e)
	lines[0] = string(b)
	os.WriteFile(path+".audit.log", []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	reopened, _ := NewLocalKeyStore("secret", path, nil, true)
	if err := reopened.VerifyAuditLog(); !errors.Is(err, ErrKMS) {
		t.Fatalf("tampered audit log should fail, got %v", err)
	}
}

// mock KMS transport: wrapped = nonce(12) || aesgcm(masterKey, nonce, dataKey)
func mockKMS(t *testing.T, masterKey []byte, expectKey string) KMSTransport {
	return func(method, rawurl string, headers map[string]string, body []byte) (KMSResponse, error) {
		jsonResp := func(status int, obj map[string]any) KMSResponse {
			b, _ := json.Marshal(obj)
			return KMSResponse{Status: status, Body: b}
		}
		if headers["Authorization"] != "Bearer "+expectKey {
			return jsonResp(401, map[string]any{"error": "bad key"}), nil
		}
		u, _ := url.Parse(rawurl)
		switch {
		case method == "GET" && u.Path == "/v1/health":
			return jsonResp(200, map[string]any{"status": "ok"}), nil
		case method == "POST" && strings.HasSuffix(u.Path, "/data-key"):
			dk := randBytes(32)
			nonce := randBytes(12)
			ct, _ := aesSeal(masterKey, nonce, dk)
			wrapped := append(append([]byte{}, nonce...), ct...)
			mkid := strings.Split(u.Path, "/")[3]
			return jsonResp(200, map[string]any{
				"plaintext": b64u(dk), "ciphertext": b64u(wrapped), "master_key_id": mkid,
			}), nil
		case method == "POST" && u.Path == "/v1/decrypt":
			var p map[string]any
			json.Unmarshal(body, &p)
			wrapped, _ := base64.RawURLEncoding.DecodeString(p["ciphertext"].(string))
			nonce, ct := wrapped[:12], wrapped[12:]
			dk, err := aesOpen(masterKey, nonce, ct)
			if err != nil {
				return jsonResp(400, map[string]any{"error": "unwrap failed"}), nil
			}
			return jsonResp(200, map[string]any{"plaintext": b64u(dk)}), nil
		}
		return jsonResp(404, map[string]any{"error": "not found"}), nil
	}
}

func TestHostedKMSRoundTrip(t *testing.T) {
	masterKey := randBytes(32)
	kms, err := NewHostedKMS("https://kms.example", "sq_live_test", mockKMS(t, masterKey, "sq_live_test"))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("card number 4111 1111 1111 1111")
	blob, err := kms.Encrypt(secret, "mk-prod-1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := kms.Decrypt(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("decrypted value differs")
	}
	if h, _ := kms.Health(); h["status"] != "ok" {
		t.Fatalf("health = %v", h)
	}
}

func TestHostedKMSBadKey(t *testing.T) {
	kms, _ := NewHostedKMS("https://kms.example", "sq_live_wrong", mockKMS(t, randBytes(32), "sq_live_right"))
	if _, err := kms.Encrypt([]byte("x"), "mk"); !errors.Is(err, ErrKMSAuth) {
		t.Fatalf("bad key should be ErrKMSAuth, got %v", err)
	}
}

func TestHostedKMSConstructorValidation(t *testing.T) {
	if _, err := NewHostedKMS("", "k", nil); !errors.Is(err, ErrKMS) {
		t.Fatalf("empty endpoint should be ErrKMS, got %v", err)
	}
	if _, err := NewHostedKMS("https://x", "", nil); !errors.Is(err, ErrKMSAuth) {
		t.Fatalf("empty api key should be ErrKMSAuth, got %v", err)
	}
}

func TestTLSCapabilities(t *testing.T) {
	caps := Capabilities()
	if !strings.Contains(caps.Summary(), "PQC-hybrid TLS:") {
		t.Fatalf("bad summary: %s", caps.Summary())
	}
	cfg, c := BuildClientConfig(false)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatal("min version should be TLS 1.2")
	}
	if c.PQCHybridAvailable() {
		// Go 1.24+: the hybrid group should be first in preferences
		if len(cfg.CurvePreferences) == 0 || cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
			t.Fatal("PQC available but hybrid group not preferred")
		}
	}
}
