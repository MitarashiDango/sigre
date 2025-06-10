package dchttpsig

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

	"github.com/MitarashiDango/sigre/common"
)

var (
	availableKeyTypes = []string{
		"rsa",
		"ecdsa",
		"hmac",
		"ed25519", // ed25519 does not use a hyphenated hash suffix in its 'algorithm' param
	}

	availableHashAlgorithms = []string{
		"sha256",
		"sha512",
	}
)

type VerifyOptions = common.VerifyOptions

type verifier struct {
	host   string
	method string
	url    *url.URL
	header http.Header
	sp     *signaturesParameters
}

func NewRequestVerifier(req *http.Request, signatureParametersString string) (*verifier, error) {
	sp, err := parseSignatureParameters(signatureParametersString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP signature parameters from request: %w", err)
	}

	return &verifier{
		host:   req.Host,
		method: strings.ToLower(req.Method),
		url:    req.URL,
		header: req.Header,
		sp:     sp,
	}, nil
}

func NewResponseVerifier(res *http.Response, signatureParametersString string) (*verifier, error) {
	sp, err := parseSignatureParameters(signatureParametersString)
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

	return &verifier{
		host:   host,
		method: method,
		url:    reqURL,
		header: res.Header,
		sp:     sp,
	}, nil
}

func (v *verifier) Verify(verifyOptions *VerifyOptions) error {
	if verifyOptions == nil {
		return fmt.Errorf("verifyOptions cannot be nil")
	}

	if v.sp == nil {
		return fmt.Errorf("signature parameters not available for verification")
	}

	var nowUnix int64
	if verifyOptions.NowFunc == nil {
		nowUnix = time.Now().UTC().Unix()
	} else {
		nowUnix = verifyOptions.NowFunc().Unix()
	}

	skewSeconds := int64(verifyOptions.AllowedClockSkew.Seconds())

	if len(verifyOptions.RequiredHeaders) > 0 {
		signedHeadersMap := make(map[string]bool, len(v.sp.SignTargetHeaders))
		for _, h := range v.sp.SignTargetHeaders {
			signedHeadersMap[h] = true
		}

		for _, reqHeader := range verifyOptions.RequiredHeaders {
			if !signedHeadersMap[strings.ToLower(reqHeader)] {
				return fmt.Errorf("%w: '%s' not found in 'headers' signature parameter", ErrRequiredHeaderMissing, reqHeader)
			}
		}
	}

	isCreatedSigned := slices.Contains(v.sp.SignTargetHeaders, Created)
	if verifyOptions.AllowedClockSkew > 0 && (isCreatedSigned || v.sp.Created != "") {
		if v.sp.Created == "" {
			if isCreatedSigned {
				return fmt.Errorf("signature parameters list '%s' but 'created' parameter is missing", Created)
			}
		} else {
			createdTimeUnix, err := strconv.ParseInt(v.sp.Created, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid 'created' parameter format: %w", err)
			}
			if createdTimeUnix > nowUnix+skewSeconds {
				return fmt.Errorf("%w: 'created' time (%d) is too far in the future (current: %d, skew: %d)", ErrInvalidCreationTime, createdTimeUnix, nowUnix, skewSeconds)
			}
			if createdTimeUnix < nowUnix-skewSeconds {
				return fmt.Errorf("%w: 'created' time (%d) is too old (current: %d, skew: %d)", ErrInvalidCreationTime, createdTimeUnix, nowUnix, skewSeconds)
			}
		}
	}

	isExpiresSigned := slices.Contains(v.sp.SignTargetHeaders, Expires)
	if isExpiresSigned || v.sp.Expires != "" {
		if v.sp.Expires == "" {
			if isExpiresSigned {
				return fmt.Errorf("signature parameters list '%s' but 'expires' parameter is missing", Expires)
			}
		} else {
			expiresTimeUnix, err := strconv.ParseInt(v.sp.Expires, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid 'expires' parameter format: %w", err)
			}

			if verifyOptions.AllowedClockSkew > 0 {
				// Expired even considering skew
				if expiresTimeUnix < nowUnix-skewSeconds {
					return fmt.Errorf("%w: 'expires' time (%d) has passed (current: %d, skew: %d)", ErrSignatureExpired, expiresTimeUnix, nowUnix, skewSeconds)
				}
			} else {
				if expiresTimeUnix < nowUnix {
					return ErrSignatureExpired
				}
			}
		}
	}

	verificationStringBytes, err := v.createVerificationStringBytes()
	if err != nil {
		return fmt.Errorf("failed to create verification string: %w", err)
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(v.sp.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	keyTypeFromAlgoParam, hashAlgosToTry, err := v.determineVerificationAlgorithms()
	if err != nil {
		return err
	}

	return v.verifyDecodedSignature(verifyOptions, keyTypeFromAlgoParam, decodedSignature, verificationStringBytes, hashAlgosToTry)
}

func (v *verifier) verifyDecodedSignature(verifyOpts *VerifyOptions, keyTypeFromAlgoParam string, decodedSignature []byte, verificationStringBytes []byte, hashAlgosToTry []string) error {
	if keyTypeFromAlgoParam == "hmac" {
		if verifyOpts.SharedSecret == nil {
			return ErrMissingSharedSecret
		}

		// For HMAC, hashAlgosToTry should contain exactly one hash derived from the algorithm param (e.g., "hmac-sha256")
		if len(hashAlgosToTry) != 1 {
			return fmt.Errorf("HMAC verification requires exactly one hash algorithm, got %d from algorithm parameter '%s'", len(hashAlgosToTry), v.sp.Algorithm)
		}

		parsedHash, err := getHash(hashAlgosToTry[0])
		if err != nil {
			return fmt.Errorf("unsupported hash '%s' for HMAC from algorithm parameter '%s': %w", hashAlgosToTry[0], v.sp.Algorithm, err)
		}

		return verifyHmacSignature(verifyOpts.SharedSecret, decodedSignature, verificationStringBytes, parsedHash)
	}

	if verifyOpts.PublicKey == nil {
		return ErrMissingPublicKey
	}

	switch pubKey := verifyOpts.PublicKey.(type) {
	case *rsa.PublicKey:
		if keyTypeFromAlgoParam != "rsa" && keyTypeFromAlgoParam != HS2019 && v.sp.Algorithm != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is RSA", ErrAlgorithmMismatch, keyTypeFromAlgoParam)
		}
		return verifyRsaSignature(pubKey, decodedSignature, verificationStringBytes, hashAlgosToTry)
	case *ecdsa.PublicKey:
		if keyTypeFromAlgoParam != "ecdsa" && keyTypeFromAlgoParam != HS2019 && v.sp.Algorithm != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is ECDSA", ErrAlgorithmMismatch, keyTypeFromAlgoParam)
		}
		return verifyEcdsaSignature(pubKey, decodedSignature, verificationStringBytes, hashAlgosToTry)
	case ed25519.PublicKey:
		if keyTypeFromAlgoParam != "ed25519" && keyTypeFromAlgoParam != HS2019 && v.sp.Algorithm != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is Ed25519", ErrAlgorithmMismatch, keyTypeFromAlgoParam)
		}

		// Ed25519 does not use hashAlgosToTry list. hash is implicit.
		return verifyEd25519Signature(pubKey, decodedSignature, verificationStringBytes)
	case *ed25519.PublicKey:
		if keyTypeFromAlgoParam != "ed25519" && keyTypeFromAlgoParam != HS2019 && v.sp.Algorithm != "" {
			return fmt.Errorf("%w: signature algorithm is '%s', public key is Ed25519", ErrAlgorithmMismatch, keyTypeFromAlgoParam)
		}

		// Ed25519 does not use hashAlgosToTry list. hash is implicit.
		return verifyEd25519Signature(*pubKey, decodedSignature, verificationStringBytes)
	default:
		return fmt.Errorf("unknown or unsupported public key type: %T", verifyOpts.PublicKey)
	}
}

func (v *verifier) KeyId() string {
	if v.sp == nil {
		return ""
	}
	return v.sp.KeyId
}

// determineVerificationAlgorithms parses the 'algorithm' parameter from the signature.
// It returns the base key type (e.g., "rsa", "ed25519") and a list of hash algorithm strings to attempt.
// For "hs2019" or missing algorithm param, it returns "hs2019" as keyType and a list of available hashes to try.
// For specific algorithms like "rsa-sha256", it returns "rsa" and ["sha256"].
// For "ed25519", it returns "ed25519" and an empty list (hash is implicit).
func (v *verifier) determineVerificationAlgorithms() (keyType string, hashAlgosToTry []string, err error) {
	algoParam := v.sp.Algorithm
	if algoParam == "" || algoParam == HS2019 {
		return HS2019, availableHashAlgorithms, nil
	}

	parts := strings.SplitN(algoParam, "-", 2)
	keyType = parts[0]

	if !slices.Contains(availableKeyTypes, keyType) {
		return "", nil, fmt.Errorf("%w: key type '%s' from algorithm '%s'", ErrUnsupportedKeyFormat, keyType, algoParam)
	}

	if keyType == "ed25519" {
		if len(parts) > 1 {
			return "", nil, fmt.Errorf("%w: ed25519 algorithm should not have a hash suffix, got '%s'", ErrInvalidSignatureAlgorithm, algoParam)
		}
		return "ed25519", []string{}, nil // Hash is implicit for ed25519
	}

	// For rsa, ecdsa, hmac, a hash suffix is expected
	if len(parts) < 2 || parts[1] == "" {
		return "", nil, fmt.Errorf("%w: missing hash component for algorithm '%s'", ErrInvalidSignatureAlgorithm, algoParam)
	}

	hashStr := parts[1]
	if !slices.Contains(availableHashAlgorithms, hashStr) {
		return "", nil, fmt.Errorf("%w: hash '%s' from algorithm '%s'", ErrUnsupportedHashAlgorithm, hashStr, algoParam)
	}

	return keyType, []string{hashStr}, nil
}

func (v *verifier) createVerificationStringBytes() ([]byte, error) {
	if v.sp == nil {
		return nil, fmt.Errorf("signature parameters (sp) are nil in verifier context")
	}

	var reqPath, reqQuery string
	if v.url != nil {
		reqPath = v.url.Path
		if reqPath == "" {
			reqPath = "/"
		}
		reqQuery = v.url.RawQuery
	}

	buf, err := generateSignatureStringBuffer(
		v.sp.SignTargetHeaders,
		v.host,
		v.method,
		reqPath,
		reqQuery,
		v.header,
		v.sp.Created,
		v.sp.Expires,
	)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func verifyRsaSignature(publicKey *rsa.PublicKey, signature, verifyTarget []byte, hashAlgosToTry []string) error {
	if len(hashAlgosToTry) == 0 {
		hashAlgosToTry = availableHashAlgorithms
	}

	var lastErr error
	for _, hashAlgorithmStr := range hashAlgosToTry {
		hashEnum, err := getHash(hashAlgorithmStr)
		if err != nil {
			lastErr = fmt.Errorf("invalid hash %s for RSA: %w", hashAlgorithmStr, err)
			continue
		}

		h := hashEnum.New()
		if _, err := h.Write(verifyTarget); err != nil {
			lastErr = fmt.Errorf("failed to write to hash for RSA verification with %s: %w", hashAlgorithmStr, err)
			continue
		}

		hashed := h.Sum(nil)
		err = rsa.VerifyPKCS1v15(publicKey, hashEnum, hashed, signature)
		if err == nil {
			return nil
		}

		lastErr = err
		if !errors.Is(err, rsa.ErrVerification) {
			return fmt.Errorf("RSA verification with %s failed with unexpected error: %w", hashAlgorithmStr, err)
		}
	}

	if lastErr != nil {
		return fmt.Errorf("%w: RSA verification failed after trying specified hash(es): %v", ErrVerification, lastErr)
	}

	return ErrVerification
}

func verifyEcdsaSignature(publicKey *ecdsa.PublicKey, signature, verifyTarget []byte, hashAlgosToTry []string) error {
	if len(hashAlgosToTry) == 0 {
		hashAlgosToTry = availableHashAlgorithms
	}

	var lastAttemptFailed bool
	for _, hashAlgorithmStr := range hashAlgosToTry {
		hashEnum, err := getHash(hashAlgorithmStr)
		if err != nil {
			lastAttemptFailed = true
			continue
		}

		h := hashEnum.New()
		if _, err := h.Write(verifyTarget); err != nil {
			lastAttemptFailed = true
			continue
		}

		hashed := h.Sum(nil)
		if ecdsa.VerifyASN1(publicKey, hashed, signature) {
			return nil
		}

		lastAttemptFailed = true
	}

	if lastAttemptFailed {
		return fmt.Errorf("%w: ECDSA verification failed after trying specified hash(es)", ErrVerification)
	}

	return ErrVerification
}

func verifyEd25519Signature(publicKey ed25519.PublicKey, signature, verifyTarget []byte) error {
	if ed25519.Verify(publicKey, verifyTarget, signature) {
		return nil
	}

	return fmt.Errorf("%w: Ed25519 verification failed", ErrVerification)
}

func verifyHmacSignature(secret []byte, signature, verifyTarget []byte, hash crypto.Hash) error {
	if len(secret) == 0 {
		return ErrMissingSharedSecret
	}

	if !hash.Available() {
		return ErrUnsupportedHashAlgorithm
	}

	mac := hmac.New(hash.New, secret)
	if _, err := mac.Write(verifyTarget); err != nil {
		return fmt.Errorf("failed to write to HMAC for verification: %w", err)
	}

	expectedMAC := mac.Sum(nil)
	if hmac.Equal(signature, expectedMAC) {
		return nil
	}

	return fmt.Errorf("%w: HMAC verification failed", ErrVerification)
}
