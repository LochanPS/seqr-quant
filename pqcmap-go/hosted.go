package pqcmap

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HostedKMS — client for the SeQr hosted KMS. Port of the Python/JS pqcmap.kms.hosted, with
// the same envelope wire format (interoperable blobs). The master key never leaves the KMS;
// envelope encryption wraps a data key under it. Bearer sq_live_ auth; status maps to the
// error family (401/403 -> ErrKMSAuth, 404 -> ErrKMSKeyNotFound, else ErrKMS).
var kmsMagic = []byte("PQCKMS1")

// KMSResponse is a minimal transport response.
type KMSResponse struct {
	Status int
	Body   []byte
}

// KMSTransport performs one HTTP request. Injectable so tests mock the network while the
// local envelope crypto stays real.
type KMSTransport func(method, url string, headers map[string]string, body []byte) (KMSResponse, error)

// HostedKMS is the envelope-encryption client.
type HostedKMS struct {
	Endpoint  string
	apiKey    string
	transport KMSTransport
}

// NewHostedKMS builds a client. A nil transport uses net/http over the platform's TLS.
func NewHostedKMS(endpoint, apiKey string, transport KMSTransport) (*HostedKMS, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("%w: a KMS endpoint URL is required", ErrKMS)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("%w: a KMS API key is required", ErrKMSAuth)
	}
	if transport == nil {
		transport = httpTransport(10 * time.Second)
	}
	return &HostedKMS{Endpoint: strings.TrimRight(endpoint, "/"), apiKey: apiKey, transport: transport}, nil
}

// GenerateDataKey asks the KMS to mint a data key under masterKeyID (envelope pattern).
func (k *HostedKMS) GenerateDataKey(masterKeyID string) (plaintext, wrapped []byte, mkid string, err error) {
	body, err := k.request("POST", fmt.Sprintf("/v1/keys/%s/data-key", masterKeyID), map[string]any{"key_bytes": 32})
	if err != nil {
		return nil, nil, "", err
	}
	pt, err := kmsB64(body, "plaintext")
	if err != nil {
		return nil, nil, "", err
	}
	w, err := kmsB64(body, "ciphertext")
	if err != nil {
		return nil, nil, "", err
	}
	mkid = masterKeyID
	if v, ok := body["master_key_id"].(string); ok {
		mkid = v
	}
	return pt, w, mkid, nil
}

// DecryptDataKey asks the KMS to unwrap a previously wrapped data key.
func (k *HostedKMS) DecryptDataKey(wrapped []byte, masterKeyID string) ([]byte, error) {
	payload := map[string]any{"ciphertext": b64u(wrapped)}
	if masterKeyID != "" {
		payload["master_key_id"] = masterKeyID
	}
	body, err := k.request("POST", "/v1/decrypt", payload)
	if err != nil {
		return nil, err
	}
	return kmsB64(body, "plaintext")
}

// Encrypt envelope-encrypts plaintext and returns a self-describing blob.
func (k *HostedKMS) Encrypt(plaintext []byte, masterKeyID string) ([]byte, error) {
	dk, wrapped, mkid, err := k.GenerateDataKey(masterKeyID)
	if err != nil {
		return nil, err
	}
	nonce := randBytes(12)
	ct, err := aesSeal(dk, nonce, plaintext)
	if err != nil {
		return nil, err
	}
	return kmsPack(mkid, wrapped, nonce, ct), nil
}

// Decrypt decrypts a blob produced by Encrypt.
func (k *HostedKMS) Decrypt(envelope []byte) ([]byte, error) {
	mkid, wrapped, nonce, ct, err := kmsUnpack(envelope)
	if err != nil {
		return nil, err
	}
	dk, err := k.DecryptDataKey(wrapped, mkid)
	if err != nil {
		return nil, err
	}
	pt, err := aesOpen(dk, nonce, ct)
	if err != nil {
		return nil, fmt.Errorf("%w: envelope decryption failed: %v", ErrKMS, err)
	}
	return pt, nil
}

// Health returns the KMS health document (a cheap connectivity check).
func (k *HostedKMS) Health() (map[string]any, error) {
	return k.request("GET", "/v1/health", nil)
}

func (k *HostedKMS) request(method, path string, payload map[string]any) (map[string]any, error) {
	url := k.Endpoint + path
	headers := map[string]string{
		"Authorization": "Bearer " + k.apiKey,
		"Accept":        "application/json",
		"User-Agent":    "pqcmap-hosted-kms",
	}
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
		headers["Content-Type"] = "application/json"
	}
	resp, err := k.transport(method, url, headers, body)
	if err != nil {
		return nil, fmt.Errorf("%w: KMS request to %s failed: %v", ErrKMS, path, err)
	}
	return handleKMSStatus(path, resp)
}

func handleKMSStatus(path string, resp KMSResponse) (map[string]any, error) {
	if resp.Status >= 200 && resp.Status < 300 {
		if len(resp.Body) == 0 {
			return map[string]any{}, nil
		}
		var out map[string]any
		if err := json.Unmarshal(resp.Body, &out); err != nil {
			return nil, fmt.Errorf("%w: KMS returned invalid JSON from %s: %v", ErrKMS, path, err)
		}
		return out, nil
	}
	detail := kmsErrorDetail(resp.Body)
	switch {
	case resp.Status == 401 || resp.Status == 403:
		return nil, fmt.Errorf("%w: KMS rejected the API key (%d): %s", ErrKMSAuth, resp.Status, detail)
	case resp.Status == 404:
		return nil, fmt.Errorf("%w: KMS key not found (404): %s", ErrKMSKeyNotFound, detail)
	default:
		return nil, fmt.Errorf("%w: KMS error %d from %s: %s", ErrKMS, resp.Status, path, detail)
	}
}

func kmsB64(body map[string]any, field string) ([]byte, error) {
	v, ok := body[field].(string)
	if !ok {
		return nil, fmt.Errorf("%w: KMS response missing %q", ErrKMS, field)
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("%w: KMS response %q was not valid base64: %v", ErrKMS, field, err)
	}
	return b, nil
}

func kmsErrorDetail(body []byte) string {
	var data map[string]any
	if json.Unmarshal(body, &data) == nil {
		if e, ok := data["error"].(string); ok {
			return e
		}
		if m, ok := data["message"].(string); ok {
			return m
		}
	}
	if len(body) == 0 {
		return "(no body)"
	}
	if len(body) > 200 {
		body = body[:200]
	}
	return string(body)
}

func kmsPack(masterKeyID string, wrapped, nonce, ciphertext []byte) []byte {
	mkid := []byte(masterKeyID)
	var buf bytes.Buffer
	buf.Write(kmsMagic)
	binary.Write(&buf, binary.BigEndian, uint16(len(mkid)))
	buf.Write(mkid)
	binary.Write(&buf, binary.BigEndian, uint16(len(wrapped)))
	buf.Write(wrapped)
	buf.Write(nonce)
	buf.Write(ciphertext)
	return buf.Bytes()
}

func kmsUnpack(blob []byte) (masterKeyID string, wrapped, nonce, ciphertext []byte, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("%w: malformed KMS envelope", ErrKMS)
		}
	}()
	if len(blob) < len(kmsMagic) || !bytes.Equal(blob[:len(kmsMagic)], kmsMagic) {
		return "", nil, nil, nil, fmt.Errorf("%w: not a pqcmap KMS envelope (bad magic)", ErrKMS)
	}
	pos := len(kmsMagic)
	mkidLen := int(binary.BigEndian.Uint16(blob[pos : pos+2]))
	pos += 2
	masterKeyID = string(blob[pos : pos+mkidLen])
	pos += mkidLen
	wrappedLen := int(binary.BigEndian.Uint16(blob[pos : pos+2]))
	pos += 2
	wrapped = blob[pos : pos+wrappedLen]
	pos += wrappedLen
	nonce = blob[pos : pos+12]
	pos += 12
	ciphertext = blob[pos:]
	return masterKeyID, wrapped, nonce, ciphertext, nil
}

func httpTransport(timeout time.Duration) KMSTransport {
	client := &http.Client{Timeout: timeout}
	return func(method, url string, headers map[string]string, body []byte) (KMSResponse, error) {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, url, rdr)
		if err != nil {
			return KMSResponse{}, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return KMSResponse{}, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return KMSResponse{Status: resp.StatusCode, Body: b}, nil
	}
}
