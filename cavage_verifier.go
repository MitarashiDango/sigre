package sigre

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	availableKeyTypes = []string{"rsa", "ecdsa", "hmac", "ed25519"}
	availableHashes   = []string{"sha256", "sha512"}
)

// CavageVerifier verifies a Cavage HTTP signature (draft-cavage-http-signatures-12).
// Set Now to override the time source used for (created) and (expires) checks;
// this is primarily useful in tests.
type CavageVerifier struct {
	// Now overrides the clock used for created/expires validation. Uses time.Now when nil.
	Now func() time.Time

	host   string
	method string
	url    *url.URL
	header http.Header
	params *cavageParams
}

// NewCavageRequestVerifier creates a [CavageVerifier] from req.
// Returns an error if the Signature header is absent or malformed.
func NewCavageRequestVerifier(req *http.Request) (*CavageVerifier, error) {
	hf := GetSignatureHeaderFields(req.Header)
	if hf.Signature == "" {
		return nil, &SigreError{Err: ErrMissingSignature}
	}
	p, err := parseCavageParams(hf.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP signature parameters from request: %w", err)
	}
	return &CavageVerifier{
		host:   req.Host,
		method: strings.ToLower(req.Method),
		url:    req.URL,
		header: req.Header,
		params: p,
	}, nil
}

// NewCavageResponseVerifier creates a [CavageVerifier] from res.
// Returns an error if the Signature header is absent or malformed.
func NewCavageResponseVerifier(res *http.Response) (*CavageVerifier, error) {
	hf := GetSignatureHeaderFields(res.Header)
	if hf.Signature == "" {
		return nil, &SigreError{Err: ErrMissingSignature}
	}
	p, err := parseCavageParams(hf.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP signature parameters from response: %w", err)
	}

	var host, method string
	var reqURL *url.URL
	if res.Request != nil {
		host = res.Request.Host
		method = strings.ToLower(res.Request.Method)
		reqURL = res.Request.URL
	}

	return &CavageVerifier{
		host:   host,
		method: method,
		url:    reqURL,
		header: res.Header,
		params: p,
	}, nil
}

// KeyId returns the key identifier from the signature parameters.
func (v *CavageVerifier) KeyId() string {
	if v.params == nil {
		return ""
	}
	return v.params.KeyId
}

// Verify checks an asymmetric signature (RSA, ECDSA, Ed25519) against key.
// Returns an error if the signature was created with HMAC; use [CavageVerifier.VerifyHMAC] instead.
// Passing nil opts is equivalent to passing a zero-value [VerifyOptions].
func (v *CavageVerifier) Verify(key crypto.PublicKey, opts *VerifyOptions) error {
	if key == nil {
		return ErrMissingPublicKey
	}
	if opts == nil {
		opts = &VerifyOptions{}
	}

	message, signature, keyType, hashesToTry, err := v.prepare(opts)
	if err != nil {
		return err
	}

	if keyType == "hmac" {
		return fmt.Errorf("%w: signature algorithm is HMAC; use VerifyHMAC instead", ErrAlgorithmMismatch)
	}

	return verifyAsymmetric(key, keyType, signature, message, hashesToTry, v.params.Algorithm)
}

// VerifyHMAC checks an HMAC signature against secret.
// Returns an error if the signature was created with an asymmetric algorithm; use [CavageVerifier.Verify] instead.
// Passing nil opts is equivalent to passing a zero-value [VerifyOptions].
func (v *CavageVerifier) VerifyHMAC(secret []byte, opts *VerifyOptions) error {
	if len(secret) == 0 {
		return ErrMissingSharedSecret
	}
	if opts == nil {
		opts = &VerifyOptions{}
	}

	message, signature, keyType, hashes, err := v.prepare(opts)
	if err != nil {
		return err
	}

	switch keyType {
	case "hmac":
		if len(hashes) != 1 {
			return fmt.Errorf("HMAC verification requires exactly one hash algorithm, got %d from algorithm parameter '%s'", len(hashes), v.params.Algorithm)
		}
		h, err := getHash(hashes[0])
		if err != nil {
			return fmt.Errorf("unsupported hash '%s' for HMAC: %w", hashes[0], err)
		}
		return verifyHMAC(secret, signature, message, h)
	case hs2019:
		// algorithm="hs2019" or absent: try all supported hashes.
		for _, name := range hashes {
			h, err := getHash(name)
			if err != nil {
				continue
			}
			if verifyHMAC(secret, signature, message, h) == nil {
				return nil
			}
		}
		return fmt.Errorf("%w: HMAC verification failed for all hash algorithms", ErrVerification)
	default:
		return fmt.Errorf("%w: signature algorithm is '%s'; use Verify for asymmetric keys", ErrAlgorithmMismatch, keyType)
	}
}

// prepare performs the common pre-verification steps:
// clock checks, required-header check, builds the verification string,
// decodes the base64 signature, and resolves the algorithm.
func (v *CavageVerifier) prepare(opts *VerifyOptions) (message, signature []byte, keyType string, hashesToTry []string, err error) {
	if v.params == nil {
		return nil, nil, "", nil, fmt.Errorf("signature parameters not available for verification")
	}

	var nowUnix int64
	if v.Now == nil {
		nowUnix = time.Now().UTC().Unix()
	} else {
		nowUnix = v.Now().Unix()
	}
	skew := int64(opts.AllowedClockSkew.Seconds())

	if len(opts.RequiredHeaders) > 0 {
		signed := make(map[string]bool, len(v.params.Headers))
		for _, h := range v.params.Headers {
			signed[h] = true
		}
		for _, required := range opts.RequiredHeaders {
			if !signed[strings.ToLower(required)] {
				return nil, nil, "", nil, fmt.Errorf("%w: '%s' not found in 'headers' signature parameter", ErrRequiredHeaderMissing, required)
			}
		}
	}

	if err = v.checkCreated(nowUnix, skew, opts.AllowedClockSkew > 0); err != nil {
		return nil, nil, "", nil, err
	}
	if err = v.checkExpires(nowUnix, skew, opts.AllowedClockSkew > 0); err != nil {
		return nil, nil, "", nil, err
	}

	message, err = v.buildVerificationString()
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("failed to create verification string: %w", err)
	}

	signature, err = base64.StdEncoding.DecodeString(v.params.Signature)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	keyType, hashesToTry, err = v.resolveAlgorithm()
	if err != nil {
		return nil, nil, "", nil, err
	}

	hashesToTry, err = filterAllowedHashes(hashesToTry, opts.AllowedHashAlgorithms)
	if err != nil {
		return nil, nil, "", nil, err
	}

	if keyType != hs2019 {
		if err = validateCreatedExpiresWithAlgorithm(v.params.Headers, keyType); err != nil {
			return nil, nil, "", nil, err
		}
	}

	return message, signature, keyType, hashesToTry, nil
}

func (v *CavageVerifier) checkCreated(nowUnix, skew int64, skewEnabled bool) error {
	isCreatedSigned := slices.Contains(v.params.Headers, Created)
	if !isCreatedSigned && v.params.Created == "" {
		return nil
	}

	if v.params.Created == "" {
		if isCreatedSigned {
			return fmt.Errorf("signature parameters list '%s' but 'created' parameter is missing", Created)
		}
		return nil
	}

	createdUnix, err := strconv.ParseInt(v.params.Created, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid 'created' parameter format: %w", err)
	}

	// Section 2.1.4: MUST NOT process signatures with a future (created) timestamp.
	// skew is 0 when AllowedClockSkew is unset, so any future value is rejected.
	if createdUnix > nowUnix+skew {
		return fmt.Errorf("%w: 'created' time (%d) is too far in the future (current: %d, skew: %d)", ErrInvalidCreationTime, createdUnix, nowUnix, skew)
	}
	if skewEnabled && createdUnix < nowUnix-skew {
		return fmt.Errorf("%w: 'created' time (%d) is too old (current: %d, skew: %d)", ErrInvalidCreationTime, createdUnix, nowUnix, skew)
	}
	return nil
}

func (v *CavageVerifier) checkExpires(nowUnix, skew int64, skewEnabled bool) error {
	isExpiresSigned := slices.Contains(v.params.Headers, Expires)
	if !isExpiresSigned && v.params.Expires == "" {
		return nil
	}

	if v.params.Expires == "" {
		if isExpiresSigned {
			return fmt.Errorf("signature parameters list '%s' but 'expires' parameter is missing", Expires)
		}
		return nil
	}

	expiresUnix, err := strconv.ParseInt(v.params.Expires, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid 'expires' parameter format: %w", err)
	}

	if skewEnabled {
		if expiresUnix < nowUnix-skew {
			return fmt.Errorf("%w: 'expires' time (%d) has passed (current: %d, skew: %d)", ErrSignatureExpired, expiresUnix, nowUnix, skew)
		}
	} else if expiresUnix < nowUnix {
		return ErrSignatureExpired
	}
	return nil
}

func (v *CavageVerifier) buildVerificationString() ([]byte, error) {
	if v.params == nil {
		return nil, fmt.Errorf("signature parameters are nil")
	}

	var path, query string
	if v.url != nil {
		path = v.url.Path
		if path == "" {
			path = "/"
		}
		query = v.url.RawQuery
	}

	// Section 2.1.6: default to (created) when headers parameter was absent.
	headers := v.params.Headers
	if len(headers) == 0 {
		headers = []string{Created}
	}

	buf, err := generateSignatureStringBuffer(headers, v.host, v.method, path, query, v.header, v.params.Created, v.params.Expires)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// resolveAlgorithm parses the algorithm parameter and returns the base key type and
// the list of hash algorithm names to attempt during verification.
// For hs2019 or an absent algorithm, keyType is hs2019 and all supported hashes are tried.
func (v *CavageVerifier) resolveAlgorithm() (keyType string, hashesToTry []string, err error) {
	algo := v.params.Algorithm
	if algo == "" || algo == hs2019 {
		return hs2019, availableHashes, nil
	}

	parts := strings.SplitN(algo, "-", 2)
	keyType = parts[0]

	if !slices.Contains(availableKeyTypes, keyType) {
		return "", nil, fmt.Errorf("%w: key type '%s' from algorithm '%s'", ErrUnsupportedKeyFormat, keyType, algo)
	}

	if keyType == "ed25519" {
		if len(parts) > 1 {
			return "", nil, fmt.Errorf("%w: ed25519 algorithm should not have a hash suffix, got '%s'", ErrInvalidSignatureAlgorithm, algo)
		}
		return "ed25519", nil, nil
	}

	if len(parts) < 2 || parts[1] == "" {
		return "", nil, fmt.Errorf("%w: missing hash component for algorithm '%s'", ErrInvalidSignatureAlgorithm, algo)
	}

	hashStr := parts[1]
	if !slices.Contains(availableHashes, hashStr) {
		return "", nil, fmt.Errorf("%w: hash '%s' from algorithm '%s'", ErrUnsupportedHashAlgorithm, hashStr, algo)
	}

	return keyType, []string{hashStr}, nil
}

func verifyAsymmetric(key crypto.PublicKey, keyType string, sig, data []byte, hashes []string, algoParam string) error {
	switch pub := key.(type) {
	case *rsa.PublicKey:
		if keyType != "rsa" && keyType != hs2019 && algoParam != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is RSA", ErrAlgorithmMismatch, keyType)
		}
		return verifyRSA(pub, sig, data, hashes)
	case *ecdsa.PublicKey:
		if keyType != "ecdsa" && keyType != hs2019 && algoParam != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is ECDSA", ErrAlgorithmMismatch, keyType)
		}
		return verifyECDSA(pub, sig, data, hashes)
	case ed25519.PublicKey:
		if keyType != "ed25519" && keyType != hs2019 && algoParam != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is Ed25519", ErrAlgorithmMismatch, keyType)
		}
		return verifyEd25519(pub, sig, data)
	case *ed25519.PublicKey:
		if keyType != "ed25519" && keyType != hs2019 && algoParam != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is Ed25519", ErrAlgorithmMismatch, keyType)
		}
		return verifyEd25519(*pub, sig, data)
	default:
		return fmt.Errorf("unknown or unsupported public key type: %T", key)
	}
}

func verifyRSA(pub *rsa.PublicKey, sig, data []byte, hashes []string) error {
	if len(hashes) == 0 {
		hashes = availableHashes
	}
	var lastErr error
	for _, name := range hashes {
		h, err := getHash(name)
		if err != nil {
			lastErr = fmt.Errorf("invalid hash %s for RSA: %w", name, err)
			continue
		}
		digest := h.New()
		if _, err := digest.Write(data); err != nil {
			lastErr = fmt.Errorf("failed to hash data for RSA verification with %s: %w", name, err)
			continue
		}
		err = rsa.VerifyPKCS1v15(pub, h, digest.Sum(nil), sig)
		if err == nil {
			return nil
		}
		lastErr = err
		if !errors.Is(err, rsa.ErrVerification) {
			return fmt.Errorf("RSA verification with %s failed: %w", name, err)
		}
	}
	if lastErr != nil {
		return fmt.Errorf("%w: RSA verification failed: %v", ErrVerification, lastErr)
	}
	return ErrVerification
}

func verifyECDSA(pub *ecdsa.PublicKey, sig, data []byte, hashes []string) error {
	if len(hashes) == 0 {
		hashes = availableHashes
	}
	for _, name := range hashes {
		h, err := getHash(name)
		if err != nil {
			continue
		}
		digest := h.New()
		if _, err := digest.Write(data); err != nil {
			continue
		}
		if ecdsa.VerifyASN1(pub, digest.Sum(nil), sig) {
			return nil
		}
	}
	return fmt.Errorf("%w: ECDSA verification failed", ErrVerification)
}

func verifyEd25519(pub ed25519.PublicKey, sig, data []byte) error {
	if ed25519.Verify(pub, data, sig) {
		return nil
	}
	return fmt.Errorf("%w: Ed25519 verification failed", ErrVerification)
}

func verifyHMAC(secret, sig, data []byte, hash crypto.Hash) error {
	if len(secret) == 0 {
		return ErrMissingSharedSecret
	}
	if !hash.Available() {
		return ErrUnsupportedHashAlgorithm
	}
	mac := hmac.New(hash.New, secret)
	if _, err := mac.Write(data); err != nil {
		return fmt.Errorf("failed to compute HMAC for verification: %w", err)
	}
	if hmac.Equal(sig, mac.Sum(nil)) {
		return nil
	}
	return fmt.Errorf("%w: HMAC verification failed", ErrVerification)
}

// filterAllowedHashes filters hashesToTry against the allowed hash algorithm list.
// When allowed is empty, [DefaultAllowedHashAlgorithms] is used.
// Returns an error if no hashes remain after filtering.
// For algorithms that do not use a separate hash (e.g. Ed25519), hashesToTry is nil
// and is returned unchanged.
func filterAllowedHashes(hashesToTry []string, allowed []crypto.Hash) ([]string, error) {
	if len(hashesToTry) == 0 {
		return hashesToTry, nil
	}
	if len(allowed) == 0 {
		allowed = DefaultAllowedHashAlgorithms
	}
	filtered := make([]string, 0, len(hashesToTry))
	for _, name := range hashesToTry {
		h, err := getHash(name)
		if err != nil {
			continue
		}
		if slices.Contains(allowed, h) {
			filtered = append(filtered, name)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("%w: none of the resolved hash algorithms are permitted by AllowedHashAlgorithms", ErrUnsupportedHashAlgorithm)
	}
	return filtered, nil
}
