package sigre

import (
	"crypto"
	"fmt"
)

// AlgorithmID identifies one complete signature or MAC algorithm.
// Each value fixes the key type, hash function, and RSA padding where applicable.
// The zero value is invalid.
type AlgorithmID uint16

const (
	// AlgorithmRSAPKCS1v15SHA512 identifies RSA PKCS #1 v1.5 with SHA-512.
	AlgorithmRSAPKCS1v15SHA512 AlgorithmID = iota + 1
	// AlgorithmRSAPKCS1v15SHA256 identifies RSA PKCS #1 v1.5 with SHA-256.
	AlgorithmRSAPKCS1v15SHA256
	// AlgorithmECDSAASN1SHA512 identifies ECDSA with SHA-512 and an ASN.1 signature.
	AlgorithmECDSAASN1SHA512
	// AlgorithmECDSAASN1SHA256 identifies ECDSA with SHA-256 and an ASN.1 signature.
	AlgorithmECDSAASN1SHA256
	// AlgorithmEd25519 identifies plain Ed25519 over the un-hashed signing string.
	AlgorithmEd25519
	// AlgorithmHMACSHA512 identifies HMAC with SHA-512.
	AlgorithmHMACSHA512
	// AlgorithmHMACSHA256 identifies HMAC with SHA-256.
	AlgorithmHMACSHA256
)

type algorithmKeyKind uint8

const (
	algorithmKeyRSA algorithmKeyKind = iota + 1
	algorithmKeyECDSA
	algorithmKeyEd25519
	algorithmKeyHMAC
)

type algorithmDefinition struct {
	id      AlgorithmID
	keyKind algorithmKeyKind
	hash    crypto.Hash
}

func algorithmDefinitionFor(id AlgorithmID) (algorithmDefinition, error) {
	switch id {
	case AlgorithmRSAPKCS1v15SHA512:
		return algorithmDefinition{id: id, keyKind: algorithmKeyRSA, hash: crypto.SHA512}, nil
	case AlgorithmRSAPKCS1v15SHA256:
		return algorithmDefinition{id: id, keyKind: algorithmKeyRSA, hash: crypto.SHA256}, nil
	case AlgorithmECDSAASN1SHA512:
		return algorithmDefinition{id: id, keyKind: algorithmKeyECDSA, hash: crypto.SHA512}, nil
	case AlgorithmECDSAASN1SHA256:
		return algorithmDefinition{id: id, keyKind: algorithmKeyECDSA, hash: crypto.SHA256}, nil
	case AlgorithmEd25519:
		return algorithmDefinition{id: id, keyKind: algorithmKeyEd25519}, nil
	case AlgorithmHMACSHA512:
		return algorithmDefinition{id: id, keyKind: algorithmKeyHMAC, hash: crypto.SHA512}, nil
	case AlgorithmHMACSHA256:
		return algorithmDefinition{id: id, keyKind: algorithmKeyHMAC, hash: crypto.SHA256}, nil
	default:
		return algorithmDefinition{}, fmt.Errorf("%w: unsupported AlgorithmID %d", ErrInvalidKeyMetadata, id)
	}
}
