package sigre

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// CavageVerifier verifies a Cavage HTTP signature (draft-cavage-http-signatures-12).
type CavageVerifier struct {
	// Now overrides the clock used for created, expires, and Date validation.
	// The current UTC time is used when Now is nil.
	Now func() time.Time

	host          string
	method        string
	requestTarget string
	header        http.Header
	params        *cavageParams
}

// NewCavageRequestVerifier creates a [CavageVerifier] from req.
// Returns an error if the Cavage signature is absent or malformed.
func NewCavageRequestVerifier(req *http.Request) (*CavageVerifier, error) {
	signatureValue, present, err := cavageSignatureValue(req.Header)
	if err != nil {
		return nil, wrapSigreError(err)
	}
	if !present {
		return nil, wrapSigreError(ErrMissingSignature)
	}
	p, err := parseCavageParams(signatureValue)
	if err != nil {
		return nil, wrapSigreError(fmt.Errorf("failed to parse HTTP signature parameters from request: %w", err))
	}
	return &CavageVerifier{
		host:          req.Host,
		method:        req.Method,
		requestTarget: req.RequestURI,
		header:        req.Header,
		params:        p,
	}, nil
}

// NewCavageResponseVerifier creates a [CavageVerifier] from res.
// Returns an error if the Cavage signature is absent or malformed.
func NewCavageResponseVerifier(res *http.Response) (*CavageVerifier, error) {
	signatureValue, present, err := cavageSignatureValue(res.Header)
	if err != nil {
		return nil, wrapSigreError(err)
	}
	if !present {
		return nil, wrapSigreError(ErrMissingSignature)
	}
	p, err := parseCavageParams(signatureValue)
	if err != nil {
		return nil, wrapSigreError(fmt.Errorf("failed to parse HTTP signature parameters from response: %w", err))
	}

	var host, method, requestTarget string
	if res.Request != nil {
		host = res.Request.Host
		method = res.Request.Method
		requestTarget = associatedRequestTarget(res.Request)
	}

	return &CavageVerifier{
		host:          host,
		method:        method,
		requestTarget: requestTarget,
		header:        res.Header,
		params:        p,
	}, nil
}

// KeyId returns the opaque key identifier from the signature parameters.
func (v *CavageVerifier) KeyId() string {
	if v.params == nil {
		return ""
	}
	return v.params.KeyId
}

// Verify checks an RSA, ECDSA, or Ed25519 signature using the algorithm bound
// to key.Metadata. The received algorithm parameter is used only for consistency checks.
// Passing nil opts is equivalent to the strict zero-value [CavageVerificationOptions].
func (v *CavageVerifier) Verify(key VerificationKey, opts *CavageVerificationOptions) error {
	algorithm, err := v.validateMetadata(key.Metadata)
	if err != nil {
		return wrapSigreError(err)
	}
	if key.PublicKey == nil {
		return wrapSigreError(ErrMissingPublicKey)
	}
	if algorithm.keyKind == algorithmKeyHMAC {
		return wrapSigreError(fmt.Errorf("%w: HMAC AlgorithmID must be used with VerifyHMAC", ErrAlgorithmMismatch))
	}
	if err := validatePublicKey(key.PublicKey, algorithm.keyKind); err != nil {
		return wrapSigreError(err)
	}

	options, err := validateCavageVerificationOptions(opts)
	if err != nil {
		return wrapSigreError(err)
	}
	message, signature, err := v.prepareVerification(key.Metadata.Algorithm, options)
	if err != nil {
		return wrapSigreError(err)
	}
	return wrapSigreError(verifyAsymmetric(key.PublicKey, algorithm, signature, message))
}

// VerifyHMAC checks an HMAC signature using the algorithm bound to key.Metadata.
// The received algorithm parameter is used only for consistency checks.
// Passing nil opts is equivalent to the strict zero-value [CavageVerificationOptions].
func (v *CavageVerifier) VerifyHMAC(key HMACVerificationKey, opts *CavageVerificationOptions) error {
	algorithm, err := v.validateMetadata(key.Metadata)
	if err != nil {
		return wrapSigreError(err)
	}
	if len(key.Secret) == 0 {
		return wrapSigreError(ErrMissingSharedSecret)
	}
	if algorithm.keyKind != algorithmKeyHMAC {
		return wrapSigreError(fmt.Errorf("%w: asymmetric AlgorithmID must be used with Verify", ErrAlgorithmMismatch))
	}

	options, err := validateCavageVerificationOptions(opts)
	if err != nil {
		return wrapSigreError(err)
	}
	message, signature, err := v.prepareVerification(key.Metadata.Algorithm, options)
	if err != nil {
		return wrapSigreError(err)
	}
	return wrapSigreError(verifyHMAC(key.Secret, signature, message, algorithm.hash))
}

func (v *CavageVerifier) validateMetadata(metadata TrustedKeyMetadata) (verificationAlgorithm, error) {
	if v.params == nil {
		return verificationAlgorithm{}, fmt.Errorf("signature parameters not available for verification")
	}
	if metadata.KeyID == "" {
		return verificationAlgorithm{}, fmt.Errorf("%w: KeyID is empty", ErrInvalidKeyMetadata)
	}
	if v.params.KeyId != metadata.KeyID {
		return verificationAlgorithm{}, fmt.Errorf("%w: received %q, trusted %q", ErrKeyIDMismatch, v.params.KeyId, metadata.KeyID)
	}
	return verificationAlgorithmFor(metadata.Algorithm)
}

func validatePublicKey(key crypto.PublicKey, expected algorithmKeyKind) error {
	switch expected {
	case algorithmKeyRSA:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires RSA, public key is %T", ErrAlgorithmMismatch, key)
		}
		if pub == nil {
			return ErrMissingPublicKey
		}
	case algorithmKeyECDSA:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires ECDSA, public key is %T", ErrAlgorithmMismatch, key)
		}
		if pub == nil {
			return ErrMissingPublicKey
		}
	case algorithmKeyEd25519:
		switch pub := key.(type) {
		case ed25519.PublicKey:
			if len(pub) == 0 {
				return ErrMissingPublicKey
			}
			if len(pub) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: invalid Ed25519 public key length %d", ErrUnsupportedKeyFormat, len(pub))
			}
		case *ed25519.PublicKey:
			if pub == nil || len(*pub) == 0 {
				return ErrMissingPublicKey
			}
			if len(*pub) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: invalid Ed25519 public key length %d", ErrUnsupportedKeyFormat, len(*pub))
			}
		default:
			return fmt.Errorf("%w: AlgorithmID requires Ed25519, public key is %T", ErrAlgorithmMismatch, key)
		}
	default:
		return fmt.Errorf("%w: asymmetric verification received a non-public-key AlgorithmID", ErrAlgorithmMismatch)
	}
	return nil
}

func validateCavageVerificationOptions(opts *CavageVerificationOptions) (CavageVerificationOptions, error) {
	if opts == nil {
		return CavageVerificationOptions{}, nil
	}
	options := *opts
	if options.MaxSignatureAge < 0 {
		return CavageVerificationOptions{}, fmt.Errorf("%w: MaxSignatureAge must not be negative", ErrInvalidVerificationOptions)
	}
	if options.MaxDateAge < 0 {
		return CavageVerificationOptions{}, fmt.Errorf("%w: MaxDateAge must not be negative", ErrInvalidVerificationOptions)
	}
	for _, id := range options.AllowedAlgorithms {
		if _, err := verificationAlgorithmFor(id); err != nil {
			return CavageVerificationOptions{}, fmt.Errorf("%w: AllowedAlgorithms contains AlgorithmID %d", ErrInvalidVerificationOptions, id)
		}
	}

	compatibility := options.Compatibility
	if compatibility == nil {
		return options, nil
	}
	if compatibility.AllowedCreatedFutureSkew < 0 {
		return CavageVerificationOptions{}, fmt.Errorf("%w: AllowedCreatedFutureSkew must not be negative", ErrInvalidVerificationOptions)
	}
	if compatibility.AllowedExpiredSkew < 0 {
		return CavageVerificationOptions{}, fmt.Errorf("%w: AllowedExpiredSkew must not be negative", ErrInvalidVerificationOptions)
	}
	for _, id := range compatibility.AllowedLegacyAlgorithms {
		if !isLegacyCavageAlgorithm(id) {
			return CavageVerificationOptions{}, fmt.Errorf("%w: AllowedLegacyAlgorithms contains non-legacy AlgorithmID %d", ErrInvalidVerificationOptions, id)
		}
	}
	for label, id := range compatibility.ExtensionAlgorithms {
		if label == "" {
			return CavageVerificationOptions{}, fmt.Errorf("%w: ExtensionAlgorithms contains an empty label", ErrInvalidVerificationOptions)
		}
		if isReservedCavageAlgorithmLabel(label) {
			return CavageVerificationOptions{}, fmt.Errorf("%w: ExtensionAlgorithms must not override known label %q", ErrInvalidVerificationOptions, label)
		}
		if _, err := verificationAlgorithmFor(id); err != nil {
			return CavageVerificationOptions{}, fmt.Errorf("%w: extension label %q maps to unsupported AlgorithmID %d", ErrInvalidVerificationOptions, label, id)
		}
	}
	return options, nil
}

func (v *CavageVerifier) prepareVerification(id AlgorithmID, opts CavageVerificationOptions) (message, signature []byte, err error) {
	if err := v.validateWireAlgorithm(id, opts); err != nil {
		return nil, nil, err
	}

	headers := v.effectiveHeaders()
	if opts.RequireExplicitHeaders && !v.params.HeadersPresent {
		return nil, nil, fmt.Errorf("%w: headers parameter is required", ErrRequiredHeaderMissing)
	}
	if family := legacyAlgorithmFamily(v.params.Algorithm); family != "" {
		if err := validateCreatedExpiresWithAlgorithm(headers, family); err != nil {
			return nil, nil, err
		}
	}
	if err := validateRequiredHeaders(headers, opts.RequiredHeaders); err != nil {
		return nil, nil, err
	}

	now := v.currentTime()
	createdFutureSkew, expiredSkew := time.Duration(0), time.Duration(0)
	if opts.Compatibility != nil {
		createdFutureSkew = opts.Compatibility.AllowedCreatedFutureSkew
		expiredSkew = opts.Compatibility.AllowedExpiredSkew
	}
	if err := v.checkCreated(now, headers, createdFutureSkew, opts.MaxSignatureAge); err != nil {
		return nil, nil, err
	}
	if err := v.checkExpires(now, headers, expiredSkew); err != nil {
		return nil, nil, err
	}
	if err := v.checkDate(now, headers, opts.MaxDateAge); err != nil {
		return nil, nil, err
	}

	message, err = v.buildVerificationString(headers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verification string: %w", err)
	}
	signature, err = base64.StdEncoding.Strict().DecodeString(v.params.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	return message, signature, nil
}

func (v *CavageVerifier) validateWireAlgorithm(id AlgorithmID, opts CavageVerificationOptions) error {
	if len(opts.AllowedAlgorithms) > 0 && !slices.Contains(opts.AllowedAlgorithms, id) {
		return fmt.Errorf("%w: trusted AlgorithmID %d is not permitted by AllowedAlgorithms", ErrInvalidSignatureAlgorithm, id)
	}

	label := v.params.Algorithm
	compatibility := opts.Compatibility
	if label == "" {
		if opts.RequireAlgorithm {
			return fmt.Errorf("%w: algorithm parameter is required", ErrInvalidSignatureAlgorithm)
		}
		if isStrictCavageAlgorithm(id) {
			return nil
		}
		if compatibility != nil && slices.Contains(compatibility.AllowedLegacyAlgorithms, id) {
			return nil
		}
		return fmt.Errorf("%w: trusted AlgorithmID %d requires explicit compatibility", ErrInvalidSignatureAlgorithm, id)
	}

	if label == hs2019 {
		if isStrictCavageAlgorithm(id) {
			return nil
		}
		if id == AlgorithmRSAPKCS1v15SHA256 && compatibility != nil && compatibility.AllowHS2019WithSHA256 {
			return nil
		}
		return fmt.Errorf("%w: algorithm %q does not identify trusted AlgorithmID %d", ErrAlgorithmMismatch, label, id)
	}

	if legacyID, ok := legacyAlgorithmID(label); ok {
		if legacyID != id {
			return fmt.Errorf("%w: algorithm %q identifies AlgorithmID %d, trusted metadata specifies %d", ErrAlgorithmMismatch, label, legacyID, id)
		}
		if compatibility == nil || !slices.Contains(compatibility.AllowedLegacyAlgorithms, id) {
			return fmt.Errorf("%w: deprecated algorithm %q is not enabled", ErrInvalidSignatureAlgorithm, label)
		}
		return nil
	}

	if compatibility == nil {
		return fmt.Errorf("%w: unregistered algorithm label %q", ErrInvalidSignatureAlgorithm, label)
	}
	extensionID, ok := compatibility.ExtensionAlgorithms[label]
	if !ok {
		return fmt.Errorf("%w: unregistered algorithm label %q", ErrInvalidSignatureAlgorithm, label)
	}
	if extensionID != id {
		return fmt.Errorf("%w: extension label %q identifies AlgorithmID %d, trusted metadata specifies %d", ErrAlgorithmMismatch, label, extensionID, id)
	}
	return nil
}

func isReservedCavageAlgorithmLabel(label string) bool {
	switch label {
	case hs2019, "rsa-sha1", "rsa-sha256", "ecdsa-sha256", "hmac-sha256":
		return true
	default:
		return false
	}
}

func legacyAlgorithmID(label string) (AlgorithmID, bool) {
	switch label {
	case "rsa-sha256":
		return AlgorithmRSAPKCS1v15SHA256, true
	case "ecdsa-sha256":
		return AlgorithmECDSASHA256, true
	case "hmac-sha256":
		return AlgorithmHMACSHA256, true
	default:
		return 0, false
	}
}

func legacyAlgorithmFamily(label string) string {
	switch {
	case strings.HasPrefix(label, "rsa"):
		return "rsa"
	case strings.HasPrefix(label, "hmac"):
		return "hmac"
	case strings.HasPrefix(label, "ecdsa"):
		return "ecdsa"
	default:
		return ""
	}
}

func (v *CavageVerifier) effectiveHeaders() []string {
	if len(v.params.Headers) == 0 {
		return []string{Created}
	}
	return v.params.Headers
}

func validateRequiredHeaders(signedHeaders, requiredHeaders []string) error {
	for _, required := range requiredHeaders {
		name, err := normalizeCavageSignedHeaderName(required)
		if err != nil {
			return fmt.Errorf("%w: invalid RequiredHeaders entry %q: %v", ErrInvalidVerificationOptions, required, err)
		}
		if !slices.Contains(signedHeaders, name) {
			return fmt.Errorf("%w: %q is not in the effective signed-header list", ErrRequiredHeaderMissing, required)
		}
	}
	return nil
}

func (v *CavageVerifier) currentTime() time.Time {
	if v.Now == nil {
		return time.Now().UTC()
	}
	return v.Now().UTC()
}

func (v *CavageVerifier) checkCreated(now time.Time, headers []string, futureSkew, maxAge time.Duration) error {
	isSigned := slices.Contains(headers, Created)
	if maxAge > 0 && !isSigned {
		return fmt.Errorf("%w: MaxSignatureAge requires %s", ErrRequiredHeaderMissing, Created)
	}
	if v.params.Created == "" {
		if isSigned || maxAge > 0 {
			return fmt.Errorf("%w: signature requires a valid created parameter", ErrInvalidCreationTime)
		}
		return nil
	}

	createdUnix, err := strconv.ParseInt(v.params.Created, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid created parameter: %v", ErrInvalidCreationTime, err)
	}
	created := time.Unix(createdUnix, 0)
	if created.After(now.Add(futureSkew)) {
		return fmt.Errorf("%w: created %s is after the permitted future boundary %s", ErrInvalidCreationTime, created, now.Add(futureSkew))
	}
	if maxAge > 0 && now.Sub(created) > maxAge {
		return fmt.Errorf("%w: signature age %s exceeds MaxSignatureAge %s", ErrInvalidCreationTime, now.Sub(created), maxAge)
	}
	return nil
}

func (v *CavageVerifier) checkExpires(now time.Time, headers []string, expiredSkew time.Duration) error {
	isSigned := slices.Contains(headers, Expires)
	if v.params.Expires == "" {
		if isSigned {
			return fmt.Errorf("%w: signature requires a valid expires parameter", ErrSignatureExpired)
		}
		return nil
	}

	expiresUnix, err := strconv.ParseInt(v.params.Expires, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid expires parameter: %v", ErrSignatureExpired, err)
	}
	expires := time.Unix(expiresUnix, 0)
	if expires.Before(now.Add(-expiredSkew)) {
		return fmt.Errorf("%w: expires %s is before the permitted past boundary %s", ErrSignatureExpired, expires, now.Add(-expiredSkew))
	}
	return nil
}

func (v *CavageVerifier) checkDate(now time.Time, headers []string, maxAge time.Duration) error {
	if maxAge == 0 {
		return nil
	}
	if !slices.Contains(headers, "date") {
		return fmt.Errorf("%w: MaxDateAge requires date", ErrRequiredHeaderMissing)
	}
	values := v.header.Values("Date")
	if len(values) != 1 {
		return fmt.Errorf("%w: MaxDateAge requires exactly one Date value, got %d", ErrInvalidDate, len(values))
	}
	date, err := http.ParseTime(values[0])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDate, err)
	}
	if date.Before(now.Add(-maxAge)) || date.After(now.Add(maxAge)) {
		return fmt.Errorf("%w: Date %s differs from current time %s by more than %s", ErrInvalidDate, date, now, maxAge)
	}
	return nil
}

func (v *CavageVerifier) buildVerificationString(headers []string) ([]byte, error) {
	buf, err := generateSignatureStringBuffer(headers, v.host, v.method, v.requestTarget, v.header, v.params.Created, v.params.Expires)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func verifyAsymmetric(key crypto.PublicKey, algorithm verificationAlgorithm, sig, data []byte) error {
	switch algorithm.keyKind {
	case algorithmKeyRSA:
		return verifyRSA(key.(*rsa.PublicKey), sig, data, algorithm.hash)
	case algorithmKeyECDSA:
		return verifyECDSA(key.(*ecdsa.PublicKey), sig, data, algorithm.hash)
	case algorithmKeyEd25519:
		switch pub := key.(type) {
		case ed25519.PublicKey:
			return verifyEd25519(pub, sig, data)
		case *ed25519.PublicKey:
			return verifyEd25519(*pub, sig, data)
		}
	}
	return fmt.Errorf("%w: unsupported asymmetric AlgorithmID %d", ErrAlgorithmMismatch, algorithm.id)
}

func verifyRSA(pub *rsa.PublicKey, sig, data []byte, hashID crypto.Hash) error {
	digest, err := hashMessage(hashID, data)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(pub, hashID, digest, sig); err != nil {
		return fmt.Errorf("%w: RSA PKCS #1 v1.5 verification failed: %v", ErrVerification, err)
	}
	return nil
}

func verifyECDSA(pub *ecdsa.PublicKey, sig, data []byte, hashID crypto.Hash) error {
	digest, err := hashMessage(hashID, data)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		return fmt.Errorf("%w: ECDSA verification failed", ErrVerification)
	}
	return nil
}

func verifyEd25519(pub ed25519.PublicKey, sig, data []byte) error {
	if !ed25519.Verify(pub, data, sig) {
		return fmt.Errorf("%w: Ed25519 verification failed", ErrVerification)
	}
	return nil
}

func verifyHMAC(secret, sig, data []byte, hashID crypto.Hash) error {
	hashFunc, err := hmacHash(hashID)
	if err != nil {
		return err
	}
	mac := hmac.New(hashFunc, secret)
	if _, err := mac.Write(data); err != nil {
		return fmt.Errorf("failed to compute HMAC for verification: %w", err)
	}
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return fmt.Errorf("%w: HMAC verification failed", ErrVerification)
	}
	return nil
}

func hashMessage(hashID crypto.Hash, data []byte) ([]byte, error) {
	switch hashID {
	case crypto.SHA256:
		digest := sha256.Sum256(data)
		return digest[:], nil
	case crypto.SHA512:
		digest := sha512.Sum512(data)
		return digest[:], nil
	default:
		return nil, fmt.Errorf("%w: unsupported trusted hash %v", ErrUnsupportedHashAlgorithm, hashID)
	}
}

func hmacHash(hashID crypto.Hash) (func() hash.Hash, error) {
	switch hashID {
	case crypto.SHA256:
		return sha256.New, nil
	case crypto.SHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: unsupported trusted HMAC hash %v", ErrUnsupportedHashAlgorithm, hashID)
	}
}
