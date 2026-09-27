package sigre

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

func digestSigningString(hashID crypto.Hash, data []byte) ([]byte, error) {
	switch hashID {
	case crypto.SHA256:
		digest := sha256.Sum256(data)
		return digest[:], nil
	case crypto.SHA512:
		digest := sha512.Sum512(data)
		return digest[:], nil
	default:
		return nil, fmt.Errorf("unsupported trusted hash %v", hashID)
	}
}

func computeHMAC(hashID crypto.Hash, secret, data []byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch hashID {
	case crypto.SHA256:
		newHash = sha256.New
	case crypto.SHA512:
		newHash = sha512.New
	default:
		return nil, fmt.Errorf("unsupported trusted HMAC hash %v", hashID)
	}
	mac := hmac.New(newHash, secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}
