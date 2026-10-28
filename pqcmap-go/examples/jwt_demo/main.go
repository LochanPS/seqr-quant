// Command jwt_demo issues and verifies an ML-DSA-65 JWT, and prints the public key + token
// so another SDK (Python/JS) can verify the same token — a live cross-language interop check.
//
//	go run ./examples/jwt_demo
package main

import (
	"encoding/hex"
	"fmt"

	pqcmap "github.com/LochanPS/SeQr-Labs/pqcmap-go"
)

func main() {
	sig, err := pqcmap.NewSignature("ML-DSA-65")
	if err != nil {
		panic(err)
	}
	pub, sec, err := sig.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	payload := map[string]any{"sub": "123", "role": "admin", "iss": "seqr"}
	token, err := pqcmap.EncodeToken(payload, sec, "ML-DSA-65")
	if err != nil {
		panic(err)
	}

	claims, err := pqcmap.DecodeToken(token, pub, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("verified in Go: %+v\n", claims)
	fmt.Printf("PUB %s\n", hex.EncodeToString(pub))
	fmt.Printf("TOK %s\n", token)
}
