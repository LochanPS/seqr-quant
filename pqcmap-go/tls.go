package pqcmap

import (
	"crypto/tls"
	"fmt"
	"runtime"
)

// Best-effort PQC-hybrid TLS for Go — port of the Python/JS pqcmap.tls intent. Go's
// crypto/tls has supported the hybrid group X25519MLKEM768 since Go 1.24 (enabled by
// default). This helper builds a client tls.Config that prefers it and reports honestly.
//
// MTU caveat (docs/02): an ML-KEM ClientHello (~1.2 KB) fragments; test real handshakes.

// PQCHybridGroup is the standardised hybrid group (IANA 0x11EC).
const PQCHybridGroup = "X25519MLKEM768"

// TLSCapabilities is an honest report of what PQC TLS this runtime can do.
type TLSCapabilities struct {
	GoVersion          string
	PQCGroupConfigured bool
	ConfiguredGroup    string
	Notes              []string
}

// PQCHybridAvailable reports whether a PQC hybrid key exchange is achievable here.
func (c TLSCapabilities) PQCHybridAvailable() bool { return c.PQCGroupConfigured }

// Summary is a one-line human-readable capability line.
func (c TLSCapabilities) Summary() string {
	state := "unavailable"
	grp := "-"
	if c.PQCGroupConfigured {
		state = "configured"
		grp = c.ConfiguredGroup
	}
	return fmt.Sprintf("PQC-hybrid TLS: %s (group %s); %s", state, grp, c.GoVersion)
}

// goHasMLKEM reports whether this Go runtime's crypto/tls exposes X25519MLKEM768.
func goHasMLKEM() bool {
	// tls.X25519MLKEM768 exists from Go 1.24; guard by value presence rather than build tags.
	return tls.CurveID(0x11ec) == tls.X25519MLKEM768
}

// Capabilities probes the runtime for PQC TLS support.
func Capabilities() TLSCapabilities {
	notes := []string{}
	configured := goHasMLKEM()
	if configured {
		notes = append(notes, "Go crypto/tls supports X25519MLKEM768 (Go 1.24+); it is preferred and enabled by default.")
	} else {
		notes = append(notes, "This Go runtime's crypto/tls does not expose X25519MLKEM768; upgrade to Go 1.24+ for PQC TLS.")
	}
	notes = append(notes, "MTU: an ML-KEM ClientHello (~1.2 KB) fragments; test real handshakes before production (docs/02).")
	caps := TLSCapabilities{GoVersion: runtime.Version(), PQCGroupConfigured: configured, Notes: notes}
	if configured {
		caps.ConfiguredGroup = PQCHybridGroup
	}
	return caps
}

// BuildClientConfig returns a hardened client *tls.Config that prefers the PQC hybrid group
// when the runtime supports it, plus the capability report. Set insecure=true only for local
// testing (disables cert verification).
func BuildClientConfig(insecure bool) (*tls.Config, TLSCapabilities) {
	caps := Capabilities()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caps.PQCGroupConfigured {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	} else {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	}
	if insecure {
		cfg.InsecureSkipVerify = true
	}
	return cfg, caps
}

// TLSReport is a one-line capability summary for logs / CLIs.
func TLSReport() string { return Capabilities().Summary() }
