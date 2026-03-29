package sigre

import (
	"crypto"
	"fmt"
	"strconv"
)

func getHash(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case "sha256":
		return crypto.SHA256, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, ErrUnsupportedHashAlgorithm
	}
}

func isValidUnixTime(s string) error {
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return fmt.Errorf("invalid integer format: %w", err)
	}
	return nil
}
