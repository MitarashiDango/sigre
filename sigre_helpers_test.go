package sigre_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MitarashiDango/sigre"
)

func assertPackageError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	var packageError *sigre.Error
	if !errors.As(err, &packageError) {
		t.Fatalf("error %v is not wrapped by *Error", err)
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

// Static test keys keep signature vectors reproducible.
const testRSAPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz5wcFrzkXvQgvbXngC32au35pwT0zHYbcrFe/OSm5G1UJlyh
M6+trtaPH9uQBziFE6EmUbDlums2qJpmS1vn4rmVb2YgfrnKmMPzHMeM3sshp0Z+
gT3HdBBgZ+5b7xvs+nEWWT4C/0BbZ2MDrde3h7aILJi5cKPYPOff2MdKA9RLjSyH
NBjZj8GdL+gSNWAFgUYcWD0yNZSoCcNDLhMInD+6JZ+mm+yCt1A5Oao6e1iD5nkj
ghXTNmaBqX/okYPXUf6wAk+UI6uIfSfbefHboGPO25zmOAJR7tRR4CTsCMIn6Dbu
/1JSTg8XJM0oia+YmcS7KetZUeghv4uM9q36XQIDAQABAoIBABGp7pngqG2Lx91c
RL4bKwQeC0eynEFpKxyvCq3ppml5A9ffubd0Ewr1JmhHfhGfNXNeGqyIqIMb7CKc
QGfZAfnAYH6B6fHeTOaChYTFVa7/CXX6AXltkDLH0ewF07ycW6VTSdt98zNUfnJl
ckKwP+VEGoHw3JZA2n0UHW+MRTfeCPSagSyOKVDsrlix/tO5qwXhugocUN58ZaTo
inatgF2PyUJmpdlLa0tOFFSTH3F40sIdAC1cHLajYT6sp6IAvSDfuG+HLQYO1/6a
4d2ZDmKenSW7UDktz7t4XBCOtUPDlT54I3lLg0DScTGcsCwrhhejYZyoeJlugXoZ
wAOb3OECgYEA5WaWniln9IXKKqmEqDmB6MpQm37cCCPGxNR7/ibUH7gkjy2Y1od5
PB1ulLsqYqe/WzhQS6cTqNN1HIY6H+ziKOaKNduc8NZwby8oMqqgQxGbX5xAJbJR
A2UJGve7lDgyTH3zVssVf+jVnAeLllPjWVWrt+UVlP+8KziK8uiCsJMCgYEA566w
0wwwzwspEJRUYIn8SYtmobqaUxPEJf6iwNch8BifFBi4M54gDtTzqAuQL8PK6nlH
9SFUtdRuR0sJQkb0undaVu0NJi7vht+uGYuagOHtipg5lhPsZfxiMP04OfNqWO75
rizwN5Fnqqz2j/eOcFZk++vbCOqjMrwcaynnr08CgYAQ+Rsxzpx7ch64M1y2WbLr
93QpXSSIkaUWUSZvco4FXsmNsnD5hoKI2SCiboq/S+wTosIGJvGEb0jd+Gx6ijtd
jVkyjPI6u5MMFvAhd5BuBfJ6C4SPhXcLCkG3Nhcx60qFcFg91r7bfO25IrHISKKs
rHMNIy0KnjVc+U0Glf99cwKBgQCbbCCpZEs2ChmhSrCUFt1NhRvzsRgoVWFHz9vl
HC1jQVEujSq9Tf3ZlVhjymYO9P0icPwp4RNP69OTNi5e7PTuRnUvTVV94QzE4TeN
YY7jmSzexiIToQf8nuRMUwMuNTKJuL987h60WHJAGEpL6FoA2KRkMCQ/hhC3T2SN
K46GlwKBgC/hwcwKqHx5lEVsIQaUDuoSpEeBJHpmW8D01SzR7bsczjIw6QwlhoAv
KT27nz/wWooXv+Z6l1bGvskWxRbdY4IlkziguvR5VxCpiiwADluX2iK+Etf231CY
lfoa3jvZZXlHvNAsPkvJVYTJiDvSsuhHOrPOoSV0EQ6AtXu7Wh2t
-----END RSA PRIVATE KEY-----`

const testRSAPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz5wcFrzkXvQgvbXngC32
au35pwT0zHYbcrFe/OSm5G1UJlyhM6+trtaPH9uQBziFE6EmUbDlums2qJpmS1vn
4rmVb2YgfrnKmMPzHMeM3sshp0Z+gT3HdBBgZ+5b7xvs+nEWWT4C/0BbZ2MDrde3
h7aILJi5cKPYPOff2MdKA9RLjSyHNBjZj8GdL+gSNWAFgUYcWD0yNZSoCcNDLhMI
nD+6JZ+mm+yCt1A5Oao6e1iD5nkjghXTNmaBqX/okYPXUf6wAk+UI6uIfSfbefHb
oGPO25zmOAJR7tRR4CTsCMIn6Dbu/1JSTg8XJM0oia+YmcS7KetZUeghv4uM9q36
XQIDAQAB
-----END PUBLIC KEY-----`

const testECDSAPrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHYkGVux8qaVm70//JmEmsCpopfHRJ8HNXxfflM1xzw3oAoGCCqGSM49
AwEHoUQDQgAEnNXHQzaD5HXNK4RgIvEBZNxKRR+GJqFpSx5fDc7vKwSeu8mjYPV1
6CHta3/VzziupiyM0JwX9RqvyfBSRrtYDA==
-----END EC PRIVATE KEY-----`

const testECDSAPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnNXHQzaD5HXNK4RgIvEBZNxKRR+G
JqFpSx5fDc7vKwSeu8mjYPV16CHta3/VzziupiyM0JwX9RqvyfBSRrtYDA==
-----END PUBLIC KEY-----`

const testEd25519PrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICcT+YOJKFs5p9zksAMb9H2hYwm2cguxTOc0HVPDLmiI
-----END PRIVATE KEY-----`

const testEd25519PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAXqAc1ePYsErSWb5ZhyRLjUQXx4nbWvLJqAPlnLGuLq8=
-----END PUBLIC KEY-----`

const testHMACSecret = "test-hmac-secret-key-for-sigre-testing"

var testFixedTime = time.Date(2024, 6, 8, 10, 30, 0, 0, time.UTC)

func fixedRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	block := decodeTestPEM(t, []byte(testRSAPrivateKeyPEM), "testRSAPrivateKeyPEM")
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse RSA private key: %v", err)
	}
	return key
}

func fixedRSAPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	block := decodeTestPEM(t, []byte(testRSAPublicKeyPEM), "testRSAPublicKeyPEM")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse RSA public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not an RSA public key")
	}
	return rsaPub
}

func fixedECDSAPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	block := decodeTestPEM(t, []byte(testECDSAPrivateKeyPEM), "testECDSAPrivateKeyPEM")
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse ECDSA private key: %v", err)
	}
	return key
}

func fixedECDSAPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	block := decodeTestPEM(t, []byte(testECDSAPublicKeyPEM), "testECDSAPublicKeyPEM")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse ECDSA public key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not an ECDSA public key")
	}
	return ecPub
}

func fixedEd25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	block := decodeTestPEM(t, []byte(testEd25519PrivateKeyPEM), "testEd25519PrivateKeyPEM")
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 private key: %v", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("parsed key is not an Ed25519 private key")
	}
	return edKey
}

func fixedEd25519PublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	block := decodeTestPEM(t, []byte(testEd25519PublicKeyPEM), "testEd25519PublicKeyPEM")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 public key: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatal("parsed key is not an Ed25519 public key")
	}
	return edPub
}

func newTestRequest(t *testing.T, method, urlStr, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create test request: %v", err)
	}
	req.RequestURI = req.URL.RequestURI()
	return req
}

func fixedPublicVerificationKey(keyID string, algorithm sigre.AlgorithmID, publicKey crypto.PublicKey) sigre.VerificationKey {
	return sigre.VerificationKey{
		Metadata:  sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		PublicKey: publicKey,
	}
}

func fixedHMACVerificationKey(keyID string, algorithm sigre.AlgorithmID, secret []byte) sigre.HMACVerificationKey {
	return sigre.HMACVerificationKey{
		Metadata: sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		Secret:   secret,
	}
}

func fixedSigningKey(keyID string, algorithm sigre.AlgorithmID, privateKey crypto.PrivateKey) sigre.SigningKey {
	return sigre.SigningKey{
		Metadata:   sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		PrivateKey: privateKey,
	}
}

func fixedHMACSigningKey(keyID string, algorithm sigre.AlgorithmID, secret []byte) sigre.HMACSigningKey {
	return sigre.HMACSigningKey{
		Metadata: sigre.TrustedKeyMetadata{KeyID: keyID, Algorithm: algorithm},
		Secret:   secret,
	}
}
