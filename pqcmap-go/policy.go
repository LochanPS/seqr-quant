package pqcmap

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Crypto-policy enforcement for application code — port of Python/JS pqcmap.policy. The
// policy shape is the SeQr platform spine's {"rules": [...]} body (loads as-is). Rule types:
// family_in / family_not_in / min_key_size / min_nist_level. Default: no quantum-vulnerable
// families, PQC at NIST Level 3+.

var classicalFamilies = [][2]string{
	{"ML-KEM", "ML-KEM"}, {"ML-DSA", "ML-DSA"}, {"SLH-DSA", "SLH-DSA"},
	{"RSA", "RSA"}, {"ECDSA", "ECDSA"}, {"ED25519", "EdDSA"}, {"ED448", "EdDSA"},
	{"ECDH", "ECDH"}, {"X25519", "ECDH"}, {"X448", "ECDH"}, {"DSA", "DSA"}, {"DH", "DH"},
}

var keySizeRe = regexp.MustCompile(`(\d{3,5})`)

// FamilyOf returns the best-effort crypto family for algorithm, or "unknown".
func FamilyOf(algorithm string) string {
	name := strings.ToUpper(algorithm)
	for _, pair := range classicalFamilies {
		if strings.HasPrefix(name, pair[0]) || strings.Contains(name, pair[0]) {
			return pair[1]
		}
	}
	return "unknown"
}

type resolved struct {
	name      string
	family    string
	nistLevel int
	hasLevel  bool
	keySize   int
	hasSize   bool
}

func resolveAlg(algorithm string) resolved {
	if m, ok := algorithmMeta[algorithm]; ok {
		return resolved{name: m.Name, family: FamilyOf(m.Name), nistLevel: m.NISTLevel, hasLevel: true}
	}
	r := resolved{name: algorithm, family: FamilyOf(algorithm)}
	if match := keySizeRe.FindString(algorithm); match != "" {
		fmt.Sscanf(match, "%d", &r.keySize)
		r.hasSize = true
	}
	return r
}

// Violation is one failed rule for one algorithm.
type Violation struct {
	RuleKey  string
	Severity string
	Actual   string
	Target   string
	Message  string
}

// DefaultPolicyBody is the code-layer baseline (no quantum-vulnerable families; NIST L3+).
var DefaultPolicyBody = map[string]any{
	"name":    "pqcmap baseline (PCI DSS + SEBI CSCRF intent)",
	"version": "1",
	"rules": []any{
		map[string]any{
			"key": "no_quantum_vulnerable_family", "type": "family_not_in",
			"forbidden": []any{"RSA", "ECDSA", "EdDSA", "ECDH", "DSA", "DH"},
			"severity": "immediate", "target": "ML-KEM (KEM) / ML-DSA (signatures)",
		},
		map[string]any{
			"key": "min_nist_level_3", "type": "min_nist_level", "min": float64(3),
			"severity": "urgent", "target": "NIST Level 3+ (ML-KEM-768 / ML-DSA-65)",
		},
	},
}

var slotToKind = map[string]string{"tls:kex": "kem", "tls:cert": "sign"}
var algorithmRuleTypes = map[string]bool{"family_in": true, "family_not_in": true, "min_key_size": true, "min_nist_level": true}
var severityOrder = map[string]int{"immediate": 0, "urgent": 1, "planned": 2}

// CryptoPolicy is a loaded policy that evaluates a single algorithm choice.
type CryptoPolicy struct {
	Name  string
	rules []map[string]any
}

// NewCryptoPolicy builds a policy from a spine {"rules": [...]} body.
func NewCryptoPolicy(body map[string]any) (*CryptoPolicy, error) {
	rulesRaw, ok := body["rules"].([]any)
	if !ok {
		return nil, fmt.Errorf("policy body must have a 'rules' array")
	}
	rules := make([]map[string]any, 0, len(rulesRaw))
	for _, r := range rulesRaw {
		if m, ok := r.(map[string]any); ok {
			rules = append(rules, m)
		}
	}
	name, _ := body["name"].(string)
	if name == "" {
		name = "custom policy"
	}
	return &CryptoPolicy{Name: name, rules: rules}, nil
}

// DefaultPolicy returns the built-in baseline policy.
func DefaultPolicy() *CryptoPolicy {
	p, _ := NewCryptoPolicy(DefaultPolicyBody)
	return p
}

// PolicyFromFile loads a JSON policy body from disk.
func PolicyFromFile(path string) (*CryptoPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, err
	}
	return NewCryptoPolicy(body)
}

func ruleKind(rule map[string]any) string {
	if k, ok := rule["kind"].(string); ok && k != "" {
		return k
	}
	if slot, ok := rule["slot"].(string); ok {
		return slotToKind[slot]
	}
	return ""
}

// Evaluate returns every Violation algorithm triggers (empty == compliant), most-severe first.
// kind ("kem"/"sign", or "") scopes which rules apply.
func (p *CryptoPolicy) Evaluate(algorithm, kind string) []Violation {
	r := resolveAlg(algorithm)
	var found []Violation
	for _, rule := range p.rules {
		rtype, _ := rule["type"].(string)
		if !algorithmRuleTypes[rtype] {
			continue
		}
		if rk := ruleKind(rule); rk != "" && kind != "" && rk != kind {
			continue
		}
		if v := p.checkRule(rule, r); v != nil {
			found = append(found, *v)
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		return severityOrder[found[i].Severity] < severityOrder[found[j].Severity]
	})
	return found
}

func toStringSet(v any) map[string]bool {
	out := map[string]bool{}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

func (p *CryptoPolicy) checkRule(rule map[string]any, r resolved) *Violation {
	rtype, _ := rule["type"].(string)
	target, _ := rule["target"].(string)
	key, _ := rule["key"].(string)
	if key == "" {
		key = rtype
	}
	sev, _ := rule["severity"].(string)
	if sev == "" {
		sev = "planned"
	}

	switch rtype {
	case "family_not_in":
		if toStringSet(rule["forbidden"])[r.family] {
			return &Violation{key, sev, fmt.Sprintf("%s (%s)", r.name, r.family), target,
				fmt.Sprintf("%s is a %s algorithm, which policy %q forbids (%s). Use %s.", r.name, r.family, p.Name, key, target)}
		}
	case "family_in":
		if !toStringSet(rule["allowed"])[r.family] {
			return &Violation{key, sev, fmt.Sprintf("%s (%s)", r.name, r.family), target,
				fmt.Sprintf("%s is a %s algorithm; policy %q does not allow it here (%s). Use %s.", r.name, r.family, p.Name, key, target)}
		}
	case "min_nist_level":
		if r.hasLevel {
			if min, ok := rule["min"].(float64); ok && float64(r.nistLevel) < min {
				return &Violation{key, sev, fmt.Sprintf("%s (NIST Level %d)", r.name, r.nistLevel), target,
					fmt.Sprintf("%s is NIST Level %d; policy %q requires Level %d+ (%s). Use %s.", r.name, r.nistLevel, p.Name, int(min), key, target)}
			}
		}
	case "min_key_size":
		fam, _ := rule["family"].(string)
		if r.hasSize && r.family == fam {
			if min, ok := rule["min"].(float64); ok && float64(r.keySize) < min {
				return &Violation{key, sev, fmt.Sprintf("%s (%d-bit)", r.name, r.keySize), target,
					fmt.Sprintf("%s is %d-bit; policy %q requires %s-%d+ (%s). Use %s.", r.name, r.keySize, p.Name, fam, int(min), key, target)}
			}
		}
	}
	return nil
}

// --- active policy (process-wide) -------------------------------------------

var (
	policyMu     sync.RWMutex
	activePolicy *CryptoPolicy
)

// LoadPolicy resolves from an explicit body, the PQCMAP_POLICY env var, or the default.
func LoadPolicy(body map[string]any) (*CryptoPolicy, error) {
	if body != nil {
		return NewCryptoPolicy(body)
	}
	if env := os.Getenv("PQCMAP_POLICY"); env != "" {
		return PolicyFromFile(env)
	}
	return DefaultPolicy(), nil
}

// GetActivePolicy returns the process-wide active policy (lazy-loaded).
func GetActivePolicy() *CryptoPolicy {
	policyMu.RLock()
	p := activePolicy
	policyMu.RUnlock()
	if p != nil {
		return p
	}
	policyMu.Lock()
	defer policyMu.Unlock()
	if activePolicy == nil {
		activePolicy, _ = LoadPolicy(nil)
	}
	return activePolicy
}

// SetActivePolicy installs the process-wide active policy; nil resets to default.
func SetActivePolicy(p *CryptoPolicy) {
	policyMu.Lock()
	defer policyMu.Unlock()
	if p == nil {
		p = DefaultPolicy()
	}
	activePolicy = p
}

// IsCompliant reports whether algorithm satisfies the active policy.
func IsCompliant(algorithm, kind string) bool {
	return len(GetActivePolicy().Evaluate(algorithm, kind)) == 0
}

// AssertCompliant returns an error wrapping ErrPolicyViolation if algorithm is below policy.
func AssertCompliant(algorithm, kind string) error {
	vs := GetActivePolicy().Evaluate(algorithm, kind)
	if len(vs) > 0 {
		return fmt.Errorf("%w: %s", ErrPolicyViolation, vs[0].Message)
	}
	return nil
}

// NewCompliantKeyEncapsulation is NewKeyEncapsulation gated by the active policy.
func NewCompliantKeyEncapsulation(algorithm string) (*KeyEncapsulation, error) {
	if algorithm == "" {
		algorithm = DefaultKEM
	}
	if err := AssertCompliant(algorithm, "kem"); err != nil {
		return nil, err
	}
	return NewKeyEncapsulation(algorithm)
}

// NewCompliantSignature is NewSignature gated by the active policy.
func NewCompliantSignature(algorithm string) (*Signature, error) {
	if algorithm == "" {
		algorithm = DefaultSign
	}
	if err := AssertCompliant(algorithm, "sign"); err != nil {
		return nil, err
	}
	return NewSignature(algorithm)
}
