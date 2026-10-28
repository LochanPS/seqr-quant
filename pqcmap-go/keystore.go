package pqcmap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LocalKeyStore — encrypted local key store (AES-256-GCM at rest, key from a passphrase).
// Port of the Python/JS pqcmap.kms.local, with the same on-disk format (interoperable stores):
//
//	salt(16) || nonce(12) || AES-256-GCM(ciphertext || tag)
//
// The plaintext is a JSON document; the master key is PBKDF2-HMAC-SHA256(passphrase, salt,
// 100000, 32). A wrong passphrase surfaces as ErrKMSAuth (GCM tag mismatch).
const (
	ksSaltLen    = 16
	ksNonceLen   = 12
	pbkdf2Iters  = 100_000
	masterKeyLen = 32
	schemaVer    = 2
	auditGenesis = "0000000000000000000000000000000000000000000000000000000000000000"
)

var exportMagic = []byte("PQCKEXP1")

// RotationPolicy — when a key should be rotated. A nil field disables that dimension.
type RotationPolicy struct {
	MaxAgeDays *float64
	MaxUses    *int
}

func (p RotationPolicy) toDict() map[string]any {
	return map[string]any{"max_age_days": p.MaxAgeDays, "max_uses": p.MaxUses}
}

func rotationFromDict(d map[string]any) RotationPolicy {
	var p RotationPolicy
	if d == nil {
		return p
	}
	if v, ok := d["max_age_days"].(float64); ok {
		p.MaxAgeDays = &v
	}
	if v, ok := d["max_uses"].(float64); ok {
		n := int(v)
		p.MaxUses = &n
	}
	return p
}

type keyRecord struct {
	Algorithm  string         `json:"algorithm"`
	PublicKey  string         `json:"public_key"`
	SecretKey  string         `json:"secret_key"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  string         `json:"created_at"`
	Status     string         `json:"status"`
	RotatedTo  *string        `json:"rotated_to"`
	Uses       int            `json:"uses"`
	LastUsedAt *string        `json:"last_used_at"`
}

// LocalKeyStore holds keys encrypted at rest with per-key metadata, rotation, and audit.
type LocalKeyStore struct {
	passphrase   []byte
	Path         string
	AuditPath    string
	auditEnabled bool
	records      map[string]*keyRecord
	policy       RotationPolicy
	salt         []byte
	lastHash     string
}

// NewLocalKeyStore opens or creates a store at path (empty path == ~/.seqr/keys.enc).
func NewLocalKeyStore(passphrase, path string, policy *RotationPolicy, audit bool) (*LocalKeyStore, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("%w: a non-empty passphrase is required", ErrKMSAuth)
	}
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".seqr", "keys.enc")
	}
	ks := &LocalKeyStore{
		passphrase:   []byte(passphrase),
		Path:         path,
		AuditPath:    path + ".audit.log",
		auditEnabled: audit,
		records:      map[string]*keyRecord{},
	}
	if _, err := os.Stat(path); err == nil {
		if err := ks.load(); err != nil {
			return nil, err
		}
		if policy != nil {
			ks.policy = *policy
			if err := ks.save(); err != nil {
				return nil, err
			}
		}
	} else {
		ks.salt = randBytes(ksSaltLen)
		if policy != nil {
			ks.policy = *policy
			if err := ks.save(); err != nil {
				return nil, err
			}
		}
	}
	ks.lastHash = ks.readLastAuditHash()
	return ks, nil
}

// GenerateAndStore generates a fresh keypair for algorithm and stores it; returns the key id.
func (ks *LocalKeyStore) GenerateAndStore(algorithm string, metadata map[string]any) (string, error) {
	pub, sec, err := ks.generate(algorithm)
	if err != nil {
		return "", err
	}
	id, err := ks.Store(algorithm, pub, sec, metadata)
	if err != nil {
		return "", err
	}
	ks.audit("generate", id, algorithm, nil)
	return id, nil
}

// Store saves an existing keypair (raw bytes); returns its generated key id.
func (ks *LocalKeyStore) Store(algorithm string, publicKey, secretKey []byte, metadata map[string]any) (string, error) {
	if _, ok := algorithmMeta[algorithm]; !ok {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algorithm)
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	id := "key_" + hex.EncodeToString(randBytes(8))
	ks.records[id] = &keyRecord{
		Algorithm: algorithm,
		PublicKey: b64u(publicKey),
		SecretKey: b64u(secretKey),
		Metadata:  metadata,
		CreatedAt: now(),
		Status:    "active",
	}
	if err := ks.save(); err != nil {
		return "", err
	}
	ks.audit("store", id, algorithm, nil)
	return id, nil
}

// GetPublicKey returns the raw public key bytes for keyId.
func (ks *LocalKeyStore) GetPublicKey(keyId string) ([]byte, error) {
	rec, err := ks.record(keyId)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(rec.PublicKey)
}

// GetPrivateKey returns the raw secret key bytes. Counts as one "use" when recordUse is true.
func (ks *LocalKeyStore) GetPrivateKey(keyId string, recordUse bool) ([]byte, error) {
	rec, err := ks.record(keyId)
	if err != nil {
		return nil, err
	}
	if recordUse {
		rec.Uses++
		ts := now()
		rec.LastUsedAt = &ts
		if err := ks.save(); err != nil {
			return nil, err
		}
		ks.audit("access", keyId, rec.Algorithm, map[string]any{"uses": rec.Uses})
	}
	return base64.RawURLEncoding.DecodeString(rec.SecretKey)
}

// GetMetadata returns non-secret metadata for keyId.
func (ks *LocalKeyStore) GetMetadata(keyId string) (map[string]any, error) {
	rec, err := ks.record(keyId)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"algorithm": rec.Algorithm, "metadata": rec.Metadata, "created_at": rec.CreatedAt,
		"status": rec.Status, "rotated_to": rec.RotatedTo, "uses": rec.Uses, "last_used_at": rec.LastUsedAt,
	}, nil
}

// Rotate generates a new keypair (same algorithm) and marks the old one rotated.
func (ks *LocalKeyStore) Rotate(keyId string) (string, error) {
	rec, err := ks.record(keyId)
	if err != nil {
		return "", err
	}
	newId, err := ks.GenerateAndStore(rec.Algorithm, rec.Metadata)
	if err != nil {
		return "", err
	}
	rec.Status = "rotated"
	rec.RotatedTo = &newId
	if err := ks.save(); err != nil {
		return "", err
	}
	ks.audit("rotate", keyId, rec.Algorithm, map[string]any{"rotated_to": newId})
	return newId, nil
}

// NeedsRotation reports whether keyId exceeded the age or usage limit of the policy.
func (ks *LocalKeyStore) NeedsRotation(keyId string) (bool, error) {
	rec, err := ks.record(keyId)
	if err != nil {
		return false, err
	}
	if rec.Status != "active" {
		return false, nil
	}
	if ks.policy.MaxUses != nil && rec.Uses >= *ks.policy.MaxUses {
		return true, nil
	}
	if ks.policy.MaxAgeDays != nil {
		if t, err := time.Parse(time.RFC3339, rec.CreatedAt); err == nil {
			if time.Since(t).Hours()/24 >= *ks.policy.MaxAgeDays {
				return true, nil
			}
		}
	}
	return false, nil
}

// RotateIfNeeded rotates keyId if the policy says so; returns the new id or "".
func (ks *LocalKeyStore) RotateIfNeeded(keyId string) (string, error) {
	need, err := ks.NeedsRotation(keyId)
	if err != nil || !need {
		return "", err
	}
	return ks.Rotate(keyId)
}

// ExportKey emits a single key as a portable, passphrase-encrypted blob.
func (ks *LocalKeyStore) ExportKey(keyId, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("%w: a non-empty export passphrase is required", ErrKMSAuth)
	}
	rec, err := ks.record(keyId)
	if err != nil {
		return nil, err
	}
	doc, _ := json.Marshal(map[string]any{"key_id": keyId, "record": rec})
	salt := randBytes(ksSaltLen)
	nonce := randBytes(ksNonceLen)
	ct, err := aesSeal(deriveKey([]byte(passphrase), salt), nonce, doc)
	if err != nil {
		return nil, err
	}
	ks.audit("export", keyId, rec.Algorithm, nil)
	out := append([]byte{}, exportMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	return append(out, ct...), nil
}

// ImportKey imports a key produced by ExportKey; returns its id in this store.
func (ks *LocalKeyStore) ImportKey(blob []byte, passphrase string) (string, error) {
	if len(blob) < len(exportMagic) || string(blob[:len(exportMagic)]) != string(exportMagic) {
		return "", fmt.Errorf("%w: not a pqcmap key export (bad magic)", ErrKMS)
	}
	body := blob[len(exportMagic):]
	if len(body) < ksSaltLen+ksNonceLen {
		return "", fmt.Errorf("%w: truncated key export", ErrKMS)
	}
	salt := body[:ksSaltLen]
	nonce := body[ksSaltLen : ksSaltLen+ksNonceLen]
	ct := body[ksSaltLen+ksNonceLen:]
	pt, err := aesOpen(deriveKey([]byte(passphrase), salt), nonce, ct)
	if err != nil {
		return "", fmt.Errorf("%w: wrong export passphrase or corrupt export blob", ErrKMSAuth)
	}
	var doc struct {
		KeyID  string     `json:"key_id"`
		Record *keyRecord `json:"record"`
	}
	if err := json.Unmarshal(pt, &doc); err != nil {
		return "", fmt.Errorf("%w: %v", ErrKMS, err)
	}
	id := doc.KeyID
	if _, exists := ks.records[id]; id == "" || exists {
		id = "key_" + hex.EncodeToString(randBytes(8))
	}
	ks.records[id] = doc.Record
	if err := ks.save(); err != nil {
		return "", err
	}
	ks.audit("import", id, doc.Record.Algorithm, nil)
	return id, nil
}

// ListKeys returns metadata for every key (with its id).
func (ks *LocalKeyStore) ListKeys() []map[string]any {
	ids := make([]string, 0, len(ks.records))
	for id := range ks.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		m, _ := ks.GetMetadata(id)
		m["key_id"] = id
		out = append(out, m)
	}
	return out
}

// ReadAuditLog returns the parsed append-only audit entries (oldest first).
func (ks *LocalKeyStore) ReadAuditLog() []map[string]any {
	data, err := os.ReadFile(ks.AuditPath)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e map[string]any
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// VerifyAuditLog re-walks the hash chain; returns nil or an ErrKMS on tamper.
func (ks *LocalKeyStore) VerifyAuditLog() error {
	prev := auditGenesis
	for _, entry := range ks.ReadAuditLog() {
		expected := auditEntryHash(prev, entry)
		if entry["hash"] != expected || entry["prev"] != prev {
			return fmt.Errorf("%w: audit log tamper detected at seq %v", ErrKMS, entry["seq"])
		}
		prev, _ = entry["hash"].(string)
	}
	return nil
}

// -- internals --------------------------------------------------------------

func (ks *LocalKeyStore) record(keyId string) (*keyRecord, error) {
	rec, ok := ks.records[keyId]
	if !ok {
		return nil, fmt.Errorf("%w: no key with id %q", ErrKMSKeyNotFound, keyId)
	}
	return rec, nil
}

func (ks *LocalKeyStore) generate(algorithm string) (pub, sec []byte, err error) {
	if _, ok := kemSchemes[algorithm]; ok {
		kem, _ := NewKeyEncapsulation(algorithm)
		return kem.GenerateKeypair()
	}
	if _, ok := signSchemes[algorithm]; ok {
		sig, _ := NewSignature(algorithm)
		return sig.GenerateKeypair()
	}
	return nil, nil, fmt.Errorf("%w: cannot generate for %q", ErrUnsupportedAlgorithm, algorithm)
}

func (ks *LocalKeyStore) load() error {
	raw, err := os.ReadFile(ks.Path)
	if err != nil {
		return err
	}
	if len(raw) < ksSaltLen+ksNonceLen {
		return fmt.Errorf("%w: key store file is truncated or corrupt", ErrKMSAuth)
	}
	ks.salt = raw[:ksSaltLen]
	nonce := raw[ksSaltLen : ksSaltLen+ksNonceLen]
	ct := raw[ksSaltLen+ksNonceLen:]
	pt, err := aesOpen(deriveKey(ks.passphrase, ks.salt), nonce, ct)
	if err != nil {
		return fmt.Errorf("%w: could not decrypt key store — wrong passphrase or corrupt file", ErrKMSAuth)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(pt, &doc); err != nil {
		return fmt.Errorf("%w: %v", ErrKMS, err)
	}
	var version int
	if v, ok := doc["version"]; ok {
		json.Unmarshal(v, &version)
	}
	if version == schemaVer {
		json.Unmarshal(doc["keys"], &ks.records)
		var pol map[string]any
		json.Unmarshal(doc["policy"], &pol)
		ks.policy = rotationFromDict(pol)
	} else { // legacy v1: flat {key_id: record}
		json.Unmarshal(pt, &ks.records)
	}
	return nil
}

func (ks *LocalKeyStore) save() error {
	doc := map[string]any{"version": schemaVer, "keys": ks.records, "policy": ks.policy.toDict()}
	pt, _ := json.Marshal(doc)
	nonce := randBytes(ksNonceLen)
	ct, err := aesSeal(deriveKey(ks.passphrase, ks.salt), nonce, pt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ks.Path), 0o700); err != nil {
		return err
	}
	out := append([]byte{}, ks.salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	tmp := ks.Path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ks.Path)
}

func (ks *LocalKeyStore) readLastAuditHash() string {
	last := auditGenesis
	for _, e := range ks.ReadAuditLog() {
		if h, ok := e["hash"].(string); ok {
			last = h
		}
	}
	return last
}

func (ks *LocalKeyStore) audit(op, keyId, algorithm string, detail map[string]any) {
	if !ks.auditEnabled {
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	entry := map[string]any{
		"seq": len(ks.ReadAuditLog()), "ts": now(), "op": op,
		"key_id": keyId, "algorithm": algorithm, "detail": detail, "prev": ks.lastHash,
	}
	entry["hash"] = auditEntryHash(ks.lastHash, entry)
	os.MkdirAll(filepath.Dir(ks.AuditPath), 0o700)
	f, err := os.OpenFile(ks.AuditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line, _ := json.Marshal(entry)
	f.Write(append(line, '\n'))
	ks.lastHash, _ = entry["hash"].(string)
}

// -- crypto helpers ---------------------------------------------------------

func deriveKey(passphrase, salt []byte) []byte {
	key, _ := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iters, masterKeyLen)
	return key
}

func aesSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil // ciphertext || tag
}

func aesOpen(key, nonce, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

func auditEntryHash(prev string, entry map[string]any) string {
	material := map[string]any{
		"seq": entry["seq"], "ts": entry["ts"], "op": entry["op"],
		"key_id": entry["key_id"], "algorithm": entry["algorithm"], "detail": entry["detail"],
	}
	canon, _ := canonicalJSON(material)
	sum := sha256.Sum256(append([]byte(prev), canon...))
	return hex.EncodeToString(sum[:])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
