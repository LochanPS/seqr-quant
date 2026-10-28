package pqcmap

import (
	"bytes"
	"errors"
	"testing"
)

func TestBackendAvailable(t *testing.T) {
	if !Available() {
		t.Fatal("Available() should be true (circl is compiled in)")
	}
	if Backend() != "circl" {
		t.Fatalf("Backend() = %q, want circl", Backend())
	}
}

func TestMetaSizes(t *testing.T) {
	m, err := Meta(MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	if m.PublicKeyBytes != 1184 || m.SecretKeyBytes != 2400 || m.OutputBytes != 1088 || m.NISTLevel != 3 {
		t.Fatalf("ML-KEM-768 meta wrong: %+v", m)
	}
	if _, err := Meta("RSA-2048"); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestKEMRoundTrip(t *testing.T) {
	for _, alg := range []string{MLKEM512, MLKEM768, MLKEM1024} {
		kem, err := NewKeyEncapsulation(alg)
		if err != nil {
			t.Fatal(err)
		}
		pk, sk, err := kem.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		ct, ss, err := kem.Encapsulate(pk)
		if err != nil {
			t.Fatal(err)
		}
		ss2, err := kem.Decapsulate(sk, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ss, ss2) {
			t.Fatalf("%s: shared secrets differ", alg)
		}
	}
}

func TestKEMWrongSize(t *testing.T) {
	kem, _ := NewKeyEncapsulation(MLKEM768)
	if _, _, err := kem.Encapsulate(make([]byte, 10)); !errors.Is(err, ErrKeySize) {
		t.Fatalf("expected ErrKeySize, got %v", err)
	}
}

func TestSignRoundTrip(t *testing.T) {
	for _, alg := range []string{MLDSA44, MLDSA65, MLDSA87} {
		sig, err := NewSignature(alg)
		if err != nil {
			t.Fatal(err)
		}
		pk, sk, err := sig.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("authorize transfer")
		signature, err := sig.Sign(msg, sk)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := sig.Verify(msg, signature, pk)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("%s: valid signature did not verify", alg)
		}
		bad, _ := sig.Verify([]byte("tampered"), signature, pk)
		if bad {
			t.Fatalf("%s: tampered message verified", alg)
		}
	}
}

func TestWrongFamilyRejected(t *testing.T) {
	if _, err := NewKeyEncapsulation(MLDSA65); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
	if _, err := NewSignature(MLKEM768); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestErrorFamily(t *testing.T) {
	_, err := Meta("nope")
	if !errors.Is(err, ErrPQC) {
		t.Fatalf("every pqcmap error should wrap ErrPQC; got %v", err)
	}
}
