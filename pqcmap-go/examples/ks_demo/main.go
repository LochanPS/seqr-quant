// Command ks_demo creates an encrypted LocalKeyStore, stores an ML-DSA-65 key, and prints
// the store path + key id + public key. Run with a shared passphrase, then read the same
// store from the Python/JS SDK to confirm the on-disk format is interoperable.
//
//	go run ./examples/ks_demo <path> <passphrase>
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	pqcmap "github.com/LochanPS/SeQr-Labs/pqcmap-go"
)

func main() {
	path, pass := "keys.enc", "shared-pass"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if len(os.Args) > 2 {
		pass = os.Args[2]
	}
	ks, err := pqcmap.NewLocalKeyStore(pass, path, nil, true)
	if err != nil {
		panic(err)
	}
	kid, err := ks.GenerateAndStore("ML-DSA-65", map[string]any{"purpose": "jwt"})
	if err != nil {
		panic(err)
	}
	pub, _ := ks.GetPublicKey(kid)
	fmt.Printf("KID %s\n", kid)
	fmt.Printf("PUB %s\n", hex.EncodeToString(pub))
}
