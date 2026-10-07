package sigre

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"time"
)

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
// Signing reads Header values using canonical map keys. It rejects map keys that
// differ only in case from canonical keys for signed fields or Signature, and for
// Authorization when a value uses the Signature scheme.
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
	message := cavageRequestSigningMessage(req, header)
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
	message := cavageResponseSigningMessage(res, header)
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

func cavageRequestSigningMessage(req *http.Request, header http.Header) cavageSigningMessage {
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
			return outgoingCavageRequestTarget(req)
		},
		resolveFields: func(headers []string) (http.Header, error) {
			return resolveOutgoingRequestFields(req, header, headers)
		},
	}
}

func cavageResponseSigningMessage(res *http.Response, header http.Header) cavageSigningMessage {
	message := cavageSigningMessage{header: header}
	if res.Request != nil {
		message.method = associatedRequestMethod(res.Request)
		message.resolveRequestTarget = func() (string, error) {
			return associatedCavageRequestTarget(res.Request)
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
	if err := rejectNonCanonicalOutgoingFieldKeys(message.header, configuration.headers); err != nil {
		return fmt.Errorf("failed to create signing string: %w", err)
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
	created, expires := cavageSigningTimestamps(now, configuration.headers, configuration.expiresAfter)
	buf, err := generateCavageSigningString(
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
		return cavageSigningConfiguration{}, invalidCavageSigningOptions("ExpiresAfter must not be negative")
	}

	compatibility := CavageSigningCompatibility{}
	if options.Compatibility != nil {
		compatibility = *options.Compatibility
	}
	wireAlgorithm, err := resolveCavageSigningAlgorithmField(algorithm, compatibility)
	if err != nil {
		return cavageSigningConfiguration{}, err
	}
	headers, headersPresent, err := resolveCavageSigningHeaders(isRequest, options.AdditionalHeaders, compatibility)
	if err != nil {
		return cavageSigningConfiguration{}, err
	}

	if compatibility.AlgorithmField == CavageAlgorithmFieldLegacy {
		if compatibility.ExactHeaders == nil {
			return cavageSigningConfiguration{}, invalidCavageSigningOptions("CavageAlgorithmFieldLegacy requires ExactHeaders")
		}
		required := []string{"date"}
		if isRequest {
			required = []string{CavageRequestTarget, "date"}
		}
		for _, name := range required {
			if !slices.Contains(headers, name) {
				return cavageSigningConfiguration{}, invalidCavageSigningOptions("CavageAlgorithmFieldLegacy requires %q in ExactHeaders", name)
			}
		}
	}
	if err := validateCavagePseudoHeadersForAlgorithmLabel(wireAlgorithm, headers); err != nil {
		return cavageSigningConfiguration{}, invalidCavageSigningAlgorithmOptions(err)
	}

	hasExpires := slices.Contains(headers, CavageExpires)
	if hasExpires && options.ExpiresAfter == 0 {
		return cavageSigningConfiguration{}, invalidCavageSigningOptions("%s requires a positive ExpiresAfter", CavageExpires)
	}
	if !hasExpires && options.ExpiresAfter > 0 {
		return cavageSigningConfiguration{}, invalidCavageSigningOptions("ExpiresAfter requires %s in the effective signed-header list", CavageExpires)
	}

	return cavageSigningConfiguration{
		algorithm:      wireAlgorithm,
		headers:        headers,
		headersPresent: headersPresent,
		expiresAfter:   options.ExpiresAfter,
	}, nil
}

func resolveCavageSigningAlgorithmField(id AlgorithmID, compatibility CavageSigningCompatibility) (string, error) {
	if compatibility.Extension != nil {
		if compatibility.AlgorithmField != CavageAlgorithmFieldStrict {
			return "", invalidCavageSigningOptions("Extension and a non-strict AlgorithmField cannot be combined")
		}
		extension := compatibility.Extension
		if err := validateCavageExtensionAlgorithm(extension.Label, extension.Algorithm); err != nil {
			return "", invalidCavageSigningOptions("Extension label %q: %v", extension.Label, err)
		}
		if extension.Algorithm != id {
			return "", invalidCavageSigningOptions("Extension.Algorithm %d does not match SigningKey AlgorithmID %d", extension.Algorithm, id)
		}
		return extension.Label, nil
	}

	switch compatibility.AlgorithmField {
	case CavageAlgorithmFieldStrict:
		if !isStrictCavageAlgorithm(id) {
			return "", invalidCavageSigningAlgorithmOptions(fmt.Errorf("%w: AlgorithmID %d is not active in strict mode", ErrInvalidSignatureAlgorithm, id))
		}
		return hs2019, nil
	case CavageAlgorithmFieldOmitted:
		if _, err := algorithmDefinitionFor(id); err != nil {
			return "", invalidCavageSigningOptions("invalid AlgorithmID: %v", err)
		}
		return "", nil
	case CavageAlgorithmFieldLegacy:
		label, ok := legacyCavageAlgorithmLabel(id)
		if !ok {
			return "", invalidCavageSigningAlgorithmOptions(fmt.Errorf("%w: AlgorithmID %d has no deprecated label", ErrInvalidSignatureAlgorithm, id))
		}
		return label, nil
	case CavageAlgorithmFieldHS2019WithSHA256:
		if id != AlgorithmRSAPKCS1v15SHA256 {
			return "", invalidCavageSigningAlgorithmOptions(fmt.Errorf("%w: hs2019 with SHA-256 is only defined for RSA PKCS #1 v1.5", ErrInvalidSignatureAlgorithm))
		}
		return hs2019, nil
	default:
		return "", invalidCavageSigningOptions("unknown AlgorithmField value %d", compatibility.AlgorithmField)
	}
}

func resolveCavageSigningHeaders(
	isRequest bool,
	additional []string,
	compatibility CavageSigningCompatibility,
) ([]string, bool, error) {
	if compatibility.ExactHeaders != nil {
		if len(compatibility.ExactHeaders) == 0 {
			return nil, false, invalidCavageSigningOptions("ExactHeaders must not be empty")
		}
		if len(additional) > 0 {
			return nil, false, invalidCavageSigningOptions("AdditionalHeaders and ExactHeaders cannot be combined")
		}
		if compatibility.OmitHeaders {
			return nil, false, invalidCavageSigningOptions("ExactHeaders and OmitHeaders cannot be combined")
		}
		headers, err := normalizeUniqueCavageSigningHeaders(compatibility.ExactHeaders, nil)
		if err != nil {
			return nil, false, err
		}
		return headers, true, nil
	}

	if compatibility.OmitHeaders {
		if len(additional) > 0 {
			return nil, false, invalidCavageSigningOptions("AdditionalHeaders and OmitHeaders cannot be combined")
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
	normalized, err := normalizeUniqueCavageSigningHeaders(additional, headers)
	if err != nil {
		return nil, false, err
	}
	return append(headers, normalized...), true, nil
}

func normalizeUniqueCavageSigningHeaders(headers, existing []string) ([]string, error) {
	seen := make(map[string]struct{}, len(existing)+len(headers))
	for _, name := range existing {
		seen[name] = struct{}{}
	}
	normalized := make([]string, 0, len(headers))
	for _, configuredName := range headers {
		name, err := normalizeCavageSignedHeaderName(configuredName)
		if err != nil {
			return nil, invalidCavageSigningOptions("invalid signed header %q: %v", configuredName, err)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, invalidCavageSigningOptions("duplicate signed header %q", configuredName)
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
	for key, values := range header {
		canonicalName := http.CanonicalHeaderKey(key)
		if key == canonicalName {
			continue
		}
		switch canonicalName {
		case HeaderSignature:
			return fmt.Errorf("%w: message already contains a Cavage signature under non-canonical map key %q", ErrInvalidSignaturePlacement, key)
		case HeaderAuthorization:
			for _, value := range values {
				if _, ok := cavageAuthorizationParams(value); ok {
					return fmt.Errorf("%w: message already contains a Cavage signature under non-canonical map key %q", ErrInvalidSignaturePlacement, key)
				}
			}
		}
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

func invalidCavageSigningOptions(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSigningOptions, fmt.Sprintf(format, args...))
}

func invalidCavageSigningAlgorithmOptions(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidSigningOptions, err)
}
