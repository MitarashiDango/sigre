package sigre

import (
	"fmt"
	"slices"
	"strings"
)

// hs2019 is listed as active in draft-cavage-http-signatures-12 Appendix E.2.
const hs2019 = "hs2019"

// These are the default allowed algorithms and the ones hs2019 permits
// without AllowHS2019WithSHA256. Draft-12 Appendix E.2 defines hs2019 with
// SHA-512; Ed25519 uses no separate hash. Strict signing uses the same set.
var defaultCavageVerificationAlgorithms = []AlgorithmID{
	AlgorithmRSAPKCS1v15SHA512,
	AlgorithmECDSAASN1SHA512,
	AlgorithmEd25519,
	AlgorithmHMACSHA512,
}

var legacyCavageAlgorithms = [...]struct {
	label string
	id    AlgorithmID
}{
	{label: "rsa-sha256", id: AlgorithmRSAPKCS1v15SHA256},
	{label: "ecdsa-sha256", id: AlgorithmECDSAASN1SHA256},
	{label: "hmac-sha256", id: AlgorithmHMACSHA256},
}

func isStrictCavageAlgorithm(id AlgorithmID) bool {
	return slices.Contains(defaultCavageVerificationAlgorithms, id)
}

func isLegacyCavageAlgorithm(id AlgorithmID) bool {
	_, ok := legacyCavageAlgorithmLabel(id)
	return ok
}

// rsa-sha1 is unsupported, but draft-12 Appendix E.2 registers it, so an
// extension label must not reuse it.
func isReservedCavageAlgorithmLabel(label string) bool {
	if label == hs2019 || label == "rsa-sha1" {
		return true
	}
	_, ok := legacyCavageAlgorithmID(label)
	return ok
}

func legacyCavageAlgorithmID(label string) (AlgorithmID, bool) {
	for _, algorithm := range legacyCavageAlgorithms {
		if algorithm.label == label {
			return algorithm.id, true
		}
	}
	return 0, false
}

func legacyCavageAlgorithmLabel(id AlgorithmID) (string, bool) {
	for _, algorithm := range legacyCavageAlgorithms {
		if algorithm.id == id {
			return algorithm.label, true
		}
	}
	return "", false
}

func validateCavageExtensionAlgorithm(label string, id AlgorithmID) error {
	if label == "" {
		return fmt.Errorf("label must not be empty")
	}
	if err := validateCavageQuotedStringValue("algorithm", label); err != nil {
		return err
	}
	if isReservedCavageAlgorithmLabel(label) {
		return fmt.Errorf("label is reserved")
	}
	if _, err := algorithmDefinitionFor(id); err != nil {
		return fmt.Errorf("unsupported AlgorithmID %d", id)
	}
	return nil
}

// validateCavagePseudoHeadersForAlgorithmLabel enforces draft-12 Section 2.3:
// the (created) and (expires) pseudo-headers MUST NOT appear in the headers list
// when the algorithm label starts with "rsa", "hmac", or "ecdsa".
// This restriction applies to both deprecated and extension labels.
func validateCavagePseudoHeadersForAlgorithmLabel(label string, headers []string) error {
	var family string
	switch {
	case strings.HasPrefix(label, "rsa"):
		family = "rsa"
	case strings.HasPrefix(label, "hmac"):
		family = "hmac"
	case strings.HasPrefix(label, "ecdsa"):
		family = "ecdsa"
	default:
		return nil
	}
	if slices.Contains(headers, CavageCreated) {
		return fmt.Errorf("%w: '(created)' MUST NOT be used with '%s' family algorithms", ErrInvalidSignatureAlgorithm, family)
	}
	if slices.Contains(headers, CavageExpires) {
		return fmt.Errorf("%w: '(expires)' MUST NOT be used with '%s' family algorithms", ErrInvalidSignatureAlgorithm, family)
	}
	return nil
}
