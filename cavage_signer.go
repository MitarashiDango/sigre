package sigre

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SigningKey contains trusted metadata and an asymmetric private key.
// Metadata.Algorithm determines the key kind, hash, and RSA padding.
type SigningKey struct {
	// Metadata binds the wire keyId to the only algorithm used for signing.
	Metadata TrustedKeyMetadata
	// PrivateKey is an RSA, ECDSA, or Ed25519 private key matching Metadata.Algorithm.
	PrivateKey crypto.PrivateKey
}

// HMACSigningKey contains trusted metadata and an HMAC shared secret.
// Metadata.Algorithm determines the HMAC hash.
type HMACSigningKey struct {
	// Metadata binds the wire keyId to the only HMAC algorithm used for signing.
	Metadata TrustedKeyMetadata
	// Secret is the non-empty shared secret used for HMAC signing.
	Secret []byte
}

// CavageSignaturePlacement identifies where a Cavage signature is written.
// The zero value is invalid; every request signing call must choose a placement.
type CavageSignaturePlacement uint8

const (
	// CavageSignaturePlacementSignature writes the signature to the Signature header.
	CavageSignaturePlacementSignature CavageSignaturePlacement = iota + 1
	// CavageSignaturePlacementAuthorization writes a request signature as Authorization: Signature.
	// It is invalid when authorization is among the signed fields.
	CavageSignaturePlacementAuthorization
)

// CavageSigningOptions configures how a Cavage HTTP signature is created.
// Passing nil is equivalent to the strict zero value. The strict zero value
// accepts AlgorithmRSAPKCS1v15SHA512, AlgorithmECDSAASN1SHA512, AlgorithmEd25519,
// or AlgorithmHMACSHA512; emits hs2019; signs (request-target) and (created) for
// a request; and omits the response headers parameter so that its effective
// value is (created). SHA-256 algorithms require an explicit Compatibility
// setting. Signing never calculates a Digest field from a message body.
type CavageSigningOptions struct {
	// AdditionalHeaders appends fields to the strict request or response defaults.
	AdditionalHeaders []string
	// ExpiresAfter sets expires to the current time plus this duration. Whole-second
	// deadlines use integer notation, and subsecond deadlines use decimal notation.
	// A positive value is valid only when (expires) is in the effective signed-header list.
	ExpiresAfter time.Duration

	// Compatibility explicitly selects non-default wire representations or headers.
	Compatibility *CavageSigningCompatibility
}

// CavageSigningCompatibility configures explicit interoperability choices.
type CavageSigningCompatibility struct {
	// AlgorithmField selects the representation of the algorithm parameter.
	// It never selects the cryptographic algorithm.
	AlgorithmField CavageAlgorithmFieldMode
	// ExactHeaders, when non-nil, completely replaces the effective signed-header
	// list and causes an explicit headers parameter to be emitted.
	ExactHeaders []string
	// OmitHeaders explicitly omits the headers parameter. Its effective signed-header
	// list is (created). A response already has the same wire form in strict mode;
	// setting this field records that the omission is an interoperability choice.
	OmitHeaders bool
	// Extension binds an unregistered wire label to one trusted AlgorithmID.
	Extension *CavageExtensionAlgorithm
}

// CavageAlgorithmFieldMode identifies how the algorithm parameter is represented.
// The zero value is the strict draft-12 representation.
type CavageAlgorithmFieldMode uint8

const (
	// CavageAlgorithmFieldStrict emits hs2019 for active SHA-512 and Ed25519 algorithms.
	CavageAlgorithmFieldStrict CavageAlgorithmFieldMode = iota
	// CavageAlgorithmFieldOmitted omits the algorithm parameter.
	CavageAlgorithmFieldOmitted
	// CavageAlgorithmFieldLegacy emits a deprecated SHA-256 algorithm label. It requires
	// ExactHeaders containing date and, for requests, (request-target).
	CavageAlgorithmFieldLegacy
	// CavageAlgorithmFieldHS2019WithSHA256 emits the Fediverse hs2019 representation
	// for RSA PKCS #1 v1.5 with SHA-256.
	CavageAlgorithmFieldHS2019WithSHA256
)

// CavageExtensionAlgorithm binds one unregistered wire label to one AlgorithmID.
type CavageExtensionAlgorithm struct {
	// Label is the exact unregistered algorithm parameter value to emit.
	Label string
	// Algorithm is the trusted algorithm to which Label is bound.
	Algorithm AlgorithmID
}

// CavageSigner creates HTTP signatures following draft-cavage-http-signatures-12.
type CavageSigner struct {
	// Now overrides the time source used for (created) and (expires). Uses time.Now when nil.
	Now func() time.Time
}

// NewCavageSigner returns a new [CavageSigner].
func NewCavageSigner() *CavageSigner {
	return &CavageSigner{Now: time.Now}
}

// SignRequest signs req with the algorithm bound to key.Metadata and writes the
// result to placement. Authorization placement is invalid when authorization is
// among the effective signed fields. Passing nil opts is equivalent to a
// zero-value [CavageSigningOptions].
func (s *CavageSigner) SignRequest(
	req *http.Request,
	key SigningKey,
	placement CavageSignaturePlacement,
	opts *CavageSigningOptions,
) error {
	if req == nil {
		return wrapError(fmt.Errorf("%w: request is nil", ErrInvalidHTTPMessage))
	}
	algorithm, privateKey, err := validateSigningKey(key)
	if err != nil {
		return wrapError(err)
	}
	err = s.signRequestWith(req, key.Metadata, algorithm, placement, opts, func(data []byte) ([]byte, error) {
		return signAsymmetric(privateKey, algorithm, data)
	})
	return wrapError(err)
}

// SignResponse signs res with the algorithm bound to key.Metadata and writes
// the result to the Signature header. Passing nil opts is equivalent to a
// zero-value [CavageSigningOptions].
func (s *CavageSigner) SignResponse(
	res *http.Response,
	key SigningKey,
	opts *CavageSigningOptions,
) error {
	if res == nil {
		return wrapError(fmt.Errorf("%w: response is nil", ErrInvalidHTTPMessage))
	}
	algorithm, privateKey, err := validateSigningKey(key)
	if err != nil {
		return wrapError(err)
	}
	err = s.signResponseWith(res, key.Metadata, algorithm, opts, func(data []byte) ([]byte, error) {
		return signAsymmetric(privateKey, algorithm, data)
	})
	return wrapError(err)
}

// SignRequestWithHMAC signs req with the HMAC algorithm bound to key.Metadata
// and writes the result to placement. Authorization placement is invalid when
// authorization is among the effective signed fields. Passing nil opts is
// equivalent to a zero-value [CavageSigningOptions].
func (s *CavageSigner) SignRequestWithHMAC(
	req *http.Request,
	key HMACSigningKey,
	placement CavageSignaturePlacement,
	opts *CavageSigningOptions,
) error {
	if req == nil {
		return wrapError(fmt.Errorf("%w: request is nil", ErrInvalidHTTPMessage))
	}
	algorithm, err := validateHMACSigningKey(key)
	if err != nil {
		return wrapError(err)
	}
	err = s.signRequestWith(req, key.Metadata, algorithm, placement, opts, func(data []byte) ([]byte, error) {
		return computeHMAC(algorithm.hash, key.Secret, data)
	})
	return wrapError(err)
}

// SignResponseWithHMAC signs res with the HMAC algorithm bound to key.Metadata
// and writes the result to the Signature header. Passing nil opts is equivalent
// to a zero-value [CavageSigningOptions].
func (s *CavageSigner) SignResponseWithHMAC(
	res *http.Response,
	key HMACSigningKey,
	opts *CavageSigningOptions,
) error {
	if res == nil {
		return wrapError(fmt.Errorf("%w: response is nil", ErrInvalidHTTPMessage))
	}
	algorithm, err := validateHMACSigningKey(key)
	if err != nil {
		return wrapError(err)
	}
	err = s.signResponseWith(res, key.Metadata, algorithm, opts, func(data []byte) ([]byte, error) {
		return computeHMAC(algorithm.hash, key.Secret, data)
	})
	return wrapError(err)
}

func (s *CavageSigner) signRequestWith(
	req *http.Request,
	metadata TrustedKeyMetadata,
	algorithm algorithmDefinition,
	placement CavageSignaturePlacement,
	opts *CavageSigningOptions,
	sign func([]byte) ([]byte, error),
) error {
	header := req.Header
	if header == nil {
		header = make(http.Header)
	}
	message := requestSigningMessage(req, header)
	err := s.signMessage(message, metadata, algorithm, placement, opts, sign)
	if err == nil {
		req.Header = header
	}
	return err
}

func (s *CavageSigner) signResponseWith(
	res *http.Response,
	metadata TrustedKeyMetadata,
	algorithm algorithmDefinition,
	opts *CavageSigningOptions,
	sign func([]byte) ([]byte, error),
) error {
	header := res.Header
	if header == nil {
		header = make(http.Header)
	}
	message := responseSigningMessage(res, header)
	err := s.signMessage(message, metadata, algorithm, CavageSignaturePlacementSignature, opts, sign)
	if err == nil {
		res.Header = header
	}
	return err
}

type cavageSigningMessage struct {
	isRequest            bool
	method               string
	header               http.Header
	resolveRequestTarget func() (string, error)
	resolveFields        func([]string) (http.Header, error)
}

func requestSigningMessage(req *http.Request, header http.Header) cavageSigningMessage {
	method := req.Method
	if method == "" {
		// For client requests, net/http defines an empty method as GET.
		method = http.MethodGet
	}
	return cavageSigningMessage{
		isRequest: true,
		method:    method,
		header:    header,
		resolveRequestTarget: func() (string, error) {
			return outgoingRequestTarget(req)
		},
		resolveFields: func(headers []string) (http.Header, error) {
			return resolveOutgoingRequestFields(req, header, headers)
		},
	}
}

func responseSigningMessage(res *http.Response, header http.Header) cavageSigningMessage {
	message := cavageSigningMessage{header: header}
	if res.Request != nil {
		message.method = associatedRequestMethod(res.Request)
		message.resolveRequestTarget = func() (string, error) {
			return associatedRequestTarget(res.Request)
		}
	}
	message.resolveFields = func(headers []string) (http.Header, error) {
		return resolveOutgoingResponseFields(res, header, headers)
	}
	return message
}

type cavageSigningConfiguration struct {
	algorithm      string
	headers        []string
	headersPresent bool
	expiresAfter   time.Duration
}

func (s *CavageSigner) signMessage(
	message cavageSigningMessage,
	metadata TrustedKeyMetadata,
	algorithm algorithmDefinition,
	placement CavageSignaturePlacement,
	opts *CavageSigningOptions,
	sign func([]byte) ([]byte, error),
) error {
	if err := validateCavageSignaturePlacement(placement); err != nil {
		return err
	}
	configuration, err := resolveCavageSigningConfiguration(message.isRequest, metadata.Algorithm, opts)
	if err != nil {
		return err
	}
	if message.isRequest && placement == CavageSignaturePlacementAuthorization && slices.Contains(configuration.headers, "authorization") {
		return fmt.Errorf("%w: request Authorization placement creates a self-reference when authorization is a signed field", ErrInvalidSignaturePlacement)
	}
	if err := ensureCavageSignatureAbsent(message.header); err != nil {
		return err
	}
	signingHeader, err := message.resolveFields(configuration.headers)
	if err != nil {
		return fmt.Errorf("failed to create signing string: %w", err)
	}
	requestTarget := ""
	if slices.Contains(configuration.headers, CavageRequestTarget) && message.resolveRequestTarget != nil {
		requestTarget, err = message.resolveRequestTarget()
		if err != nil {
			return fmt.Errorf("failed to create signing string: %w", err)
		}
	}

	now := s.currentTime()
	created, expires := signingTimestamps(now, configuration.headers, configuration.expiresAfter)
	buf, err := generateSignatureStringBuffer(
		configuration.headers,
		message.method,
		requestTarget,
		signingHeader,
		created,
		expires,
	)
	if err != nil {
		return fmt.Errorf("failed to create signing string: %w", err)
	}

	signature, err := sign(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create signature with trusted AlgorithmID %d: %w", algorithm.id, err)
	}
	params := cavageParams{
		KeyID:          metadata.KeyID,
		Signature:      base64.StdEncoding.EncodeToString(signature),
		Algorithm:      configuration.algorithm,
		Created:        created,
		Expires:        expires,
		HeadersPresent: configuration.headersPresent,
	}
	if configuration.headersPresent {
		params.Headers = configuration.headers
	}
	value, err := serializeCavageParams(&params)
	if err != nil {
		return fmt.Errorf("failed to serialize signature parameters: %w", err)
	}
	setCavageSignature(message.header, placement, value)
	return nil
}

func validateSigningKey(key SigningKey) (algorithmDefinition, crypto.PrivateKey, error) {
	algorithm, err := validateSigningMetadata(key.Metadata)
	if err != nil {
		return algorithmDefinition{}, nil, err
	}
	if key.PrivateKey == nil {
		return algorithmDefinition{}, nil, ErrMissingPrivateKey
	}
	if algorithm.keyKind == algorithmKeyHMAC {
		return algorithmDefinition{}, nil, fmt.Errorf("%w: HMAC AlgorithmID must be used with HMACSigningKey", ErrAlgorithmMismatch)
	}
	privateKey := normalizeEd25519PrivateKey(key.PrivateKey)
	if err := validatePrivateKey(privateKey, algorithm.keyKind); err != nil {
		return algorithmDefinition{}, nil, err
	}
	return algorithm, privateKey, nil
}

func normalizeEd25519PrivateKey(key crypto.PrivateKey) crypto.PrivateKey {
	privateKey, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return key
	}
	if privateKey == nil {
		return ed25519.PrivateKey(nil)
	}
	return *privateKey
}

func validateHMACSigningKey(key HMACSigningKey) (algorithmDefinition, error) {
	algorithm, err := validateSigningMetadata(key.Metadata)
	if err != nil {
		return algorithmDefinition{}, err
	}
	if len(key.Secret) == 0 {
		return algorithmDefinition{}, ErrMissingSharedSecret
	}
	if algorithm.keyKind != algorithmKeyHMAC {
		return algorithmDefinition{}, fmt.Errorf("%w: asymmetric AlgorithmID must be used with SigningKey", ErrAlgorithmMismatch)
	}
	return algorithm, nil
}

func validateSigningMetadata(metadata TrustedKeyMetadata) (algorithmDefinition, error) {
	if err := validateCavageKeyID(metadata.KeyID); err != nil {
		return algorithmDefinition{}, fmt.Errorf("%w: %v", ErrInvalidKeyMetadata, err)
	}
	return algorithmDefinitionFor(metadata.Algorithm)
}

func validatePrivateKey(key crypto.PrivateKey, expected algorithmKeyKind) error {
	switch expected {
	case algorithmKeyRSA:
		privateKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires RSA, private key is %T", ErrAlgorithmMismatch, key)
		}
		if privateKey == nil {
			return ErrMissingPrivateKey
		}
		if privateKey.N == nil || privateKey.D == nil {
			return fmt.Errorf("%w: invalid RSA private key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyECDSA:
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires ECDSA, private key is %T", ErrAlgorithmMismatch, key)
		}
		if privateKey == nil {
			return ErrMissingPrivateKey
		}
		// Intentionally inspect the deprecated X, Y, and D fields: SignASN1 and
		// PrivateKey.Bytes can panic when key fields are nil.
		if privateKey.Curve == nil || privateKey.X == nil || privateKey.Y == nil || privateKey.D == nil {
			return fmt.Errorf("%w: invalid ECDSA private key", ErrUnsupportedKeyFormat)
		}
		if _, err := privateKey.Bytes(); err != nil {
			return fmt.Errorf("%w: invalid ECDSA private key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyEd25519:
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires Ed25519, private key is %T", ErrAlgorithmMismatch, key)
		}
		if len(privateKey) == 0 {
			return ErrMissingPrivateKey
		}
		if len(privateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("%w: invalid Ed25519 private key length %d", ErrUnsupportedKeyFormat, len(privateKey))
		}
	default:
		return fmt.Errorf("%w: SigningKey received a non-asymmetric AlgorithmID", ErrAlgorithmMismatch)
	}
	return nil
}

func resolveCavageSigningConfiguration(
	isRequest bool,
	algorithm AlgorithmID,
	opts *CavageSigningOptions,
) (cavageSigningConfiguration, error) {
	options := CavageSigningOptions{}
	if opts != nil {
		options = *opts
	}
	if options.ExpiresAfter < 0 {
		return cavageSigningConfiguration{}, invalidSigningOptions("ExpiresAfter must not be negative")
	}

	compatibility := CavageSigningCompatibility{}
	if options.Compatibility != nil {
		compatibility = *options.Compatibility
	}
	wireAlgorithm, err := resolveSigningAlgorithmField(algorithm, compatibility)
	if err != nil {
		return cavageSigningConfiguration{}, err
	}
	headers, headersPresent, err := resolveSigningHeaders(isRequest, options.AdditionalHeaders, compatibility)
	if err != nil {
		return cavageSigningConfiguration{}, err
	}

	if compatibility.AlgorithmField == CavageAlgorithmFieldLegacy {
		if compatibility.ExactHeaders == nil {
			return cavageSigningConfiguration{}, invalidSigningOptions("CavageAlgorithmFieldLegacy requires ExactHeaders")
		}
		required := []string{"date"}
		if isRequest {
			required = []string{CavageRequestTarget, "date"}
		}
		for _, name := range required {
			if !slices.Contains(headers, name) {
				return cavageSigningConfiguration{}, invalidSigningOptions("CavageAlgorithmFieldLegacy requires %q in ExactHeaders", name)
			}
		}
	}
	if err := validateCavagePseudoHeadersForAlgorithmLabel(wireAlgorithm, headers); err != nil {
		return cavageSigningConfiguration{}, invalidSigningAlgorithmOptions(err)
	}

	hasExpires := slices.Contains(headers, CavageExpires)
	if hasExpires && options.ExpiresAfter == 0 {
		return cavageSigningConfiguration{}, invalidSigningOptions("%s requires a positive ExpiresAfter", CavageExpires)
	}
	if !hasExpires && options.ExpiresAfter > 0 {
		return cavageSigningConfiguration{}, invalidSigningOptions("ExpiresAfter requires %s in the effective signed-header list", CavageExpires)
	}

	return cavageSigningConfiguration{
		algorithm:      wireAlgorithm,
		headers:        headers,
		headersPresent: headersPresent,
		expiresAfter:   options.ExpiresAfter,
	}, nil
}

func resolveSigningAlgorithmField(id AlgorithmID, compatibility CavageSigningCompatibility) (string, error) {
	if compatibility.Extension != nil {
		if compatibility.AlgorithmField != CavageAlgorithmFieldStrict {
			return "", invalidSigningOptions("Extension and a non-strict AlgorithmField cannot be combined")
		}
		extension := compatibility.Extension
		if err := validateCavageExtensionAlgorithm(extension.Label, extension.Algorithm); err != nil {
			return "", invalidSigningOptions("Extension label %q: %v", extension.Label, err)
		}
		if extension.Algorithm != id {
			return "", invalidSigningOptions("Extension.Algorithm %d does not match SigningKey AlgorithmID %d", extension.Algorithm, id)
		}
		return extension.Label, nil
	}

	switch compatibility.AlgorithmField {
	case CavageAlgorithmFieldStrict:
		if !isStrictCavageAlgorithm(id) {
			return "", invalidSigningAlgorithmOptions(fmt.Errorf("%w: AlgorithmID %d is not active in strict mode", ErrInvalidSignatureAlgorithm, id))
		}
		return hs2019, nil
	case CavageAlgorithmFieldOmitted:
		if _, err := algorithmDefinitionFor(id); err != nil {
			return "", invalidSigningOptions("invalid AlgorithmID: %v", err)
		}
		return "", nil
	case CavageAlgorithmFieldLegacy:
		label, ok := legacyAlgorithmLabel(id)
		if !ok {
			return "", invalidSigningAlgorithmOptions(fmt.Errorf("%w: AlgorithmID %d has no deprecated label", ErrInvalidSignatureAlgorithm, id))
		}
		return label, nil
	case CavageAlgorithmFieldHS2019WithSHA256:
		if id != AlgorithmRSAPKCS1v15SHA256 {
			return "", invalidSigningAlgorithmOptions(fmt.Errorf("%w: hs2019 with SHA-256 is only defined for RSA PKCS #1 v1.5", ErrInvalidSignatureAlgorithm))
		}
		return hs2019, nil
	default:
		return "", invalidSigningOptions("unknown AlgorithmField value %d", compatibility.AlgorithmField)
	}
}

func resolveSigningHeaders(
	isRequest bool,
	additional []string,
	compatibility CavageSigningCompatibility,
) ([]string, bool, error) {
	if compatibility.ExactHeaders != nil {
		if len(compatibility.ExactHeaders) == 0 {
			return nil, false, invalidSigningOptions("ExactHeaders must not be empty")
		}
		if len(additional) > 0 {
			return nil, false, invalidSigningOptions("AdditionalHeaders and ExactHeaders cannot be combined")
		}
		if compatibility.OmitHeaders {
			return nil, false, invalidSigningOptions("ExactHeaders and OmitHeaders cannot be combined")
		}
		headers, err := normalizeUniqueSigningHeaders(compatibility.ExactHeaders, nil)
		if err != nil {
			return nil, false, err
		}
		return headers, true, nil
	}

	if compatibility.OmitHeaders {
		if len(additional) > 0 {
			return nil, false, invalidSigningOptions("AdditionalHeaders and OmitHeaders cannot be combined")
		}
		return []string{CavageCreated}, false, nil
	}

	headers := []string{CavageCreated}
	headersPresent := false
	if isRequest {
		headers = []string{CavageRequestTarget, CavageCreated}
		headersPresent = true
	}
	if len(additional) == 0 {
		return headers, headersPresent, nil
	}
	normalized, err := normalizeUniqueSigningHeaders(additional, headers)
	if err != nil {
		return nil, false, err
	}
	return append(headers, normalized...), true, nil
}

func normalizeUniqueSigningHeaders(headers, existing []string) ([]string, error) {
	seen := make(map[string]struct{}, len(existing)+len(headers))
	for _, name := range existing {
		seen[name] = struct{}{}
	}
	normalized := make([]string, 0, len(headers))
	for _, configuredName := range headers {
		name, err := normalizeCavageSignedHeaderName(configuredName)
		if err != nil {
			return nil, invalidSigningOptions("invalid signed header %q: %v", configuredName, err)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, invalidSigningOptions("duplicate signed header %q", configuredName)
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	return normalized, nil
}

func validateCavageSignaturePlacement(placement CavageSignaturePlacement) error {
	switch placement {
	case CavageSignaturePlacementSignature, CavageSignaturePlacementAuthorization:
		return nil
	default:
		return fmt.Errorf("%w: unsupported placement %d", ErrInvalidSignaturePlacement, placement)
	}
}

func ensureCavageSignatureAbsent(header http.Header) error {
	candidate, err := requestCavageSignatureCandidate(header, CavageRequestSignatureSourceSignatureOrAuthorization)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignaturePlacement, err)
	}
	if candidate.placement != 0 {
		return fmt.Errorf("%w: message already contains a Cavage signature", ErrInvalidSignaturePlacement)
	}
	return nil
}

func setCavageSignature(header http.Header, placement CavageSignaturePlacement, value string) {
	switch placement {
	case CavageSignaturePlacementSignature:
		header.Set(HeaderSignature, value)
	case CavageSignaturePlacementAuthorization:
		header.Set(HeaderAuthorization, "Signature "+value)
	}
}

func (s *CavageSigner) currentTime() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func signingTimestamps(now time.Time, headers []string, expiresAfter time.Duration) (created, expires string) {
	if slices.Contains(headers, CavageCreated) {
		created = strconv.FormatInt(now.Unix(), 10)
	}
	if slices.Contains(headers, CavageExpires) {
		deadline := now.Add(expiresAfter)
		expires = formatCavageExpires(deadline)
	}
	return created, expires
}

func formatCavageExpires(deadline time.Time) string {
	seconds := deadline.Unix()
	nanoseconds := int64(deadline.Nanosecond())
	if nanoseconds == 0 {
		return strconv.FormatInt(seconds, 10)
	}

	prefix := ""
	if seconds < 0 {
		prefix = "-"
		seconds = -(seconds + 1)
		nanoseconds = int64(time.Second) - nanoseconds
	}
	fraction := strconv.FormatInt(int64(time.Second)+nanoseconds, 10)[1:]
	fraction = strings.TrimRight(fraction, "0")
	return prefix + strconv.FormatInt(seconds, 10) + "." + fraction
}

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

func invalidSigningOptions(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSigningOptions, fmt.Sprintf(format, args...))
}

func invalidSigningAlgorithmOptions(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidSigningOptions, err)
}
