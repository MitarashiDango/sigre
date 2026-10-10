package sigre

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
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

// The caller has already checked the key type against algorithm.keyKind.
func signAsymmetric(key crypto.PrivateKey, algorithm algorithmDefinition, data []byte) ([]byte, error) {
	switch algorithm.keyKind {
	case algorithmKeyRSA:
		digest, err := digestSigningString(algorithm.hash, data)
		if err != nil {
			return nil, err
		}
		return rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), algorithm.hash, digest)
	case algorithmKeyECDSA:
		digest, err := digestSigningString(algorithm.hash, data)
		if err != nil {
			return nil, err
		}
		return ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest)
	case algorithmKeyEd25519:
		return ed25519.Sign(key.(ed25519.PrivateKey), data), nil
	}
	return nil, fmt.Errorf("%w: unsupported asymmetric AlgorithmID %d", ErrAlgorithmMismatch, algorithm.id)
}

// The caller has already checked the key type against algorithm.keyKind.
func verifyAsymmetric(key crypto.PublicKey, algorithm algorithmDefinition, sig, data []byte) error {
	switch algorithm.keyKind {
	case algorithmKeyRSA:
		return verifyRSAPKCS1v15(key.(*rsa.PublicKey), sig, data, algorithm.hash)
	case algorithmKeyECDSA:
		return verifyECDSAASN1(key.(*ecdsa.PublicKey), sig, data, algorithm.hash)
	case algorithmKeyEd25519:
		return verifyEd25519(key.(ed25519.PublicKey), sig, data)
	}
	return fmt.Errorf("%w: unsupported asymmetric AlgorithmID %d", ErrAlgorithmMismatch, algorithm.id)
}

func verifyRSAPKCS1v15(publicKey *rsa.PublicKey, sig, data []byte, hashID crypto.Hash) error {
	digest, err := digestSigningString(hashID, data)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(publicKey, hashID, digest, sig); err != nil {
		return fmt.Errorf("%w: RSA PKCS #1 v1.5 verification failed: %v", ErrVerification, err)
	}
	return nil
}

func verifyECDSAASN1(publicKey *ecdsa.PublicKey, sig, data []byte, hashID crypto.Hash) error {
	digest, err := digestSigningString(hashID, data)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(publicKey, digest, sig) {
		return fmt.Errorf("%w: ECDSA verification failed", ErrVerification)
	}
	return nil
}

func verifyEd25519(publicKey ed25519.PublicKey, sig, data []byte) error {
	if !ed25519.Verify(publicKey, data, sig) {
		return fmt.Errorf("%w: Ed25519 verification failed", ErrVerification)
	}
	return nil
}

func verifyHMAC(secret, sig, data []byte, hashID crypto.Hash) error {
	mac, err := computeHMAC(hashID, secret, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, mac) {
		return fmt.Errorf("%w: HMAC verification failed", ErrVerification)
	}
	return nil
}
