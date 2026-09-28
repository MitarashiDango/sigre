package sigre_test

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/MitarashiDango/sigre"
)

func assertPackageError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	var packageError *sigre.SigreError
	if !errors.As(err, &packageError) {
		t.Fatalf("error %v is not wrapped by *SigreError", err)
	}
}

func decodeTestPEM(t *testing.T, data []byte, name string) *pem.Block {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("test key %q is not a single PEM block", name)
	}
	return block
}

func loadTestPrivateKeyFile(t *testing.T, path string) crypto.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test private key %q: %v", path, err)
	}
	block := decodeTestPEM(t, data, path)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test private key %q: %v", path, err)
	}
	return key
}

func loadTestPublicKeyFile(t *testing.T, path string) crypto.PublicKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test public key %q: %v", path, err)
	}
	block := decodeTestPEM(t, data, path)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test public key %q: %v", path, err)
	}
	return key
}
