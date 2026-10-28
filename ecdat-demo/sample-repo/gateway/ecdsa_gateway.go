// ACME Bank — payment gateway client-auth keys (ECDSA).

package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// GenerateGatewayECDSAKey returns an ECDSA P-256 private key (quantum-vulnerable).
func GenerateGatewayECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
