// ACME Bank — payment gateway TLS bootstrap (RSA).

package gateway

import (
	"crypto/rand"
	"crypto/rsa"
)

// GenerateGatewayRSAKey returns an RSA-2048 private key (quantum-vulnerable).
func GenerateGatewayRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
