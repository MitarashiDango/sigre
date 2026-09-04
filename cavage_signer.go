package sigre

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
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
// The zero value is invalid; every signing call must choose a placement.
type CavageSignaturePlacement uint8

const (
	// CavageSignaturePlacementSignature writes the signature to the Signature header.
	CavageSignaturePlacementSignature CavageSignaturePlacement = iota + 1
	// CavageSignaturePlacementAuthorization writes a request signature as Authorization: Signature.
	// It is invalid for responses and when authorization is among the signed fields.
	CavageSignaturePlacementAuthorization
)

// CavageSigningOptions configures how a Cavage HTTP signature is created.
// Passing nil is equivalent to the strict zero value. The strict zero value
// accepts AlgorithmRSAPKCS1v15SHA512, AlgorithmECDSASHA512, AlgorithmEd25519,
// or AlgorithmHMACSHA512; emits hs2019; signs (request-target) and (created) for
// a request; and omits the response headers parameter so that its effective
// value is (created). SHA-256 algorithms require an explicit Compatibility
// setting. Signing never calculates a Digest field from a message body.
type CavageSigningOptions struct {
	// AdditionalHeaders appends fields to the strict request or response defaults.
	// It does not replace those defaults.
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
	AlgorithmField AlgorithmFieldMode
	// ExactHeaders, when non-nil, completely replaces the effective signed-header
	// list and causes an explicit headers parameter to be emitted.
	ExactHeaders []string
	// OmitHeaders explicitly omits the headers parameter. Its effective signed-header
	// list is (created). A response already has the same wire form in strict mode;
	// setting this field records that the omission is an interoperability choice.
	OmitHeaders bool
	// Extension binds an unregistered wire label to one trusted AlgorithmID.
	Extension *ExtensionAlgorithm
}

// AlgorithmFieldMode identifies how the algorithm parameter is represented.
// The zero value is the strict draft-12 representation.
type AlgorithmFieldMode uint8

const (
	// AlgorithmFieldStrict emits hs2019 for active SHA-512 and Ed25519 algorithms.
	AlgorithmFieldStrict AlgorithmFieldMode = iota
	// AlgorithmFieldOmitted omits the algorithm parameter.
	AlgorithmFieldOmitted
	// AlgorithmFieldLegacy emits a deprecated SHA-256 algorithm label. It requires
	// ExactHeaders containing date and, for requests, (request-target).
	AlgorithmFieldLegacy
	// AlgorithmFieldHS2019WithSHA256 emits the Fediverse hs2019 representation
	// for RSA PKCS #1 v1.5 with SHA-256.
	AlgorithmFieldHS2019WithSHA256
)

// ExtensionAlgorithm binds one unregistered wire label to one AlgorithmID.
type ExtensionAlgorithm struct {
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
		return wrapSigreError(fmt.Errorf("%w: request is nil", ErrInvalidHTTPMessage))
	}
	algorithm, err := validateSigningKey(key)
	if err != nil {
		return wrapSigreError(err)
	}
	header := req.Header
	if header == nil {
		header = make(http.Header)
	}
	message := requestSigningMessage(req, header)
	err = s.signMessage(message, key.Metadata, algorithm, placement, opts, func(data []byte) ([]byte, error) {
		return signAsymmetric(key.PrivateKey, algorithm, data)
	})
	if err == nil {
		req.Header = header
	}
	return wrapSigreError(err)
}

// SignResponse signs res with the algorithm bound to key.Metadata and writes
// the result to the Signature header. Placement must be
// [CavageSignaturePlacementSignature]. Passing nil opts is equivalent to a
// zero-value [CavageSigningOptions].
func (s *CavageSigner) SignResponse(
	res *http.Response,
	key SigningKey,
	placement CavageSignaturePlacement,
	opts *CavageSigningOptions,
) error {
	if res == nil {
		return wrapSigreError(fmt.Errorf("%w: response is nil", ErrInvalidHTTPMessage))
	}
	algorithm, err := validateSigningKey(key)
	if err != nil {
		return wrapSigreError(err)
	}
	header := res.Header
	if header == nil {
		header = make(http.Header)
	}
	message := responseSigningMessage(res, header)
	err = s.signMessage(message, key.Metadata, algorithm, placement, opts, func(data []byte) ([]byte, error) {
		return signAsymmetric(key.PrivateKey, algorithm, data)
	})
	if err == nil {
		res.Header = header
	}
	return wrapSigreError(err)
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
		return wrapSigreError(fmt.Errorf("%w: request is nil", ErrInvalidHTTPMessage))
	}
	algorithm, err := validateHMACSigningKey(key)
	if err != nil {
		return wrapSigreError(err)
	}
	header := req.Header
	if header == nil {
		header = make(http.Header)
	}
	message := requestSigningMessage(req, header)
	err = s.signMessage(message, key.Metadata, algorithm, placement, opts, func(data []byte) ([]byte, error) {
		return signHMAC(key.Secret, algorithm.hash, data)
	})
	if err == nil {
		req.Header = header
	}
	return wrapSigreError(err)
}

// SignResponseWithHMAC signs res with the HMAC algorithm bound to key.Metadata
// and writes the result to the Signature header. Placement must be
// [CavageSignaturePlacementSignature]. Passing nil opts is equivalent to a
// zero-value [CavageSigningOptions].
func (s *CavageSigner) SignResponseWithHMAC(
	res *http.Response,
	key HMACSigningKey,
	placement CavageSignaturePlacement,
	opts *CavageSigningOptions,
) error {
	if res == nil {
		return wrapSigreError(fmt.Errorf("%w: response is nil", ErrInvalidHTTPMessage))
	}
	algorithm, err := validateHMACSigningKey(key)
	if err != nil {
		return wrapSigreError(err)
	}
	header := res.Header
	if header == nil {
		header = make(http.Header)
	}
	message := responseSigningMessage(res, header)
	err = s.signMessage(message, key.Metadata, algorithm, placement, opts, func(data []byte) ([]byte, error) {
		return signHMAC(key.Secret, algorithm.hash, data)
	})
	if err == nil {
		res.Header = header
	}
	return wrapSigreError(err)
}

type cavageSigningMessage struct {
	isRequest            bool
	host                 string
	method               string
	header               http.Header
	resolveRequestTarget func() (string, error)
	resolveFields        func([]string) (string, http.Header, error)
}

func requestSigningMessage(req *http.Request, header http.Header) cavageSigningMessage {
	return cavageSigningMessage{
		isRequest: true,
		host:      req.Host,
		method:    req.Method,
		header:    header,
		resolveRequestTarget: func() (string, error) {
			return outgoingRequestTarget(req)
		},
		resolveFields: func(headers []string) (string, http.Header, error) {
			return resolveOutgoingRequestFields(req, header, headers)
		},
	}
}

func responseSigningMessage(res *http.Response, header http.Header) cavageSigningMessage {
	message := cavageSigningMessage{header: header}
	if res.Request != nil {
		message.host = res.Request.Host
		message.method = res.Request.Method
		message.resolveRequestTarget = func() (string, error) {
			return associatedRequestTarget(res.Request)
		}
	}
	message.resolveFields = func(headers []string) (string, http.Header, error) {
		return resolveOutgoingResponseFields(res, message.host, header, headers)
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
	if !message.isRequest && placement == CavageSignaturePlacementAuthorization {
		return fmt.Errorf("%w: Authorization placement cannot be used for a response", ErrInvalidSignaturePlacement)
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
	signingHost := message.host
	signingHeader := message.header
	if message.resolveFields != nil {
		signingHost, signingHeader, err = message.resolveFields(configuration.headers)
		if err != nil {
			return fmt.Errorf("failed to create signing string: %w", err)
		}
	}
	requestTarget := ""
	if slices.Contains(configuration.headers, RequestTarget) && message.resolveRequestTarget != nil {
		requestTarget, err = message.resolveRequestTarget()
		if err != nil {
			return fmt.Errorf("failed to create signing string: %w", err)
		}
	}

	now := s.currentTime()
	created, expires := signingTimestamps(now, configuration.headers, configuration.expiresAfter)
	buf, err := generateSignatureStringBuffer(
		configuration.headers,
		signingHost,
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

func validateSigningKey(key SigningKey) (algorithmDefinition, error) {
	if err := validateSigningMetadata(key.Metadata); err != nil {
		return algorithmDefinition{}, err
	}
	algorithm, err := algorithmDefinitionFor(key.Metadata.Algorithm)
	if err != nil {
		return algorithmDefinition{}, err
	}
	if key.PrivateKey == nil {
		return algorithmDefinition{}, ErrMissingPrivateKey
	}
	if algorithm.keyKind == algorithmKeyHMAC {
		return algorithmDefinition{}, fmt.Errorf("%w: HMAC AlgorithmID must be used with HMACSigningKey", ErrAlgorithmMismatch)
	}
	if err := validatePrivateKey(key.PrivateKey, algorithm.keyKind); err != nil {
		return algorithmDefinition{}, err
	}
	return algorithm, nil
}

func validateHMACSigningKey(key HMACSigningKey) (algorithmDefinition, error) {
	if err := validateSigningMetadata(key.Metadata); err != nil {
		return algorithmDefinition{}, err
	}
	algorithm, err := algorithmDefinitionFor(key.Metadata.Algorithm)
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

func validateSigningMetadata(metadata TrustedKeyMetadata) error {
	if err := validateCavageKeyID(metadata.KeyID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKeyMetadata, err)
	}
	if _, err := algorithmDefinitionFor(metadata.Algorithm); err != nil {
		return err
	}
	return nil
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
	case algorithmKeyECDSA:
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires ECDSA, private key is %T", ErrAlgorithmMismatch, key)
		}
		if privateKey == nil {
			return ErrMissingPrivateKey
		}
	case algorithmKeyEd25519:
		switch privateKey := key.(type) {
		case ed25519.PrivateKey:
			if len(privateKey) == 0 {
				return ErrMissingPrivateKey
			}
			if len(privateKey) != ed25519.PrivateKeySize {
				return fmt.Errorf("%w: invalid Ed25519 private key length %d", ErrUnsupportedKeyFormat, len(privateKey))
			}
		case *ed25519.PrivateKey:
			if privateKey == nil || len(*privateKey) == 0 {
				return ErrMissingPrivateKey
			}
			if len(*privateKey) != ed25519.PrivateKeySize {
				return fmt.Errorf("%w: invalid Ed25519 private key length %d", ErrUnsupportedKeyFormat, len(*privateKey))
			}
		default:
			return fmt.Errorf("%w: AlgorithmID requires Ed25519, private key is %T", ErrAlgorithmMismatch, key)
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

	if compatibility.AlgorithmField == AlgorithmFieldLegacy {
		if compatibility.ExactHeaders == nil {
			return cavageSigningConfiguration{}, invalidSigningOptions("AlgorithmFieldLegacy requires ExactHeaders")
		}
		required := []string{"date"}
		if isRequest {
			required = []string{RequestTarget, "date"}
		}
		for _, name := range required {
			if !slices.Contains(headers, name) {
				return cavageSigningConfiguration{}, invalidSigningOptions("AlgorithmFieldLegacy requires %q in ExactHeaders", name)
			}
		}
	}
	if family := legacyAlgorithmFamily(wireAlgorithm); family != "" {
		if err := validateCreatedExpiresWithAlgorithm(headers, family); err != nil {
			return cavageSigningConfiguration{}, invalidSigningAlgorithmOptions(err)
		}
	}

	hasExpires := slices.Contains(headers, Expires)
	if hasExpires && options.ExpiresAfter == 0 {
		return cavageSigningConfiguration{}, invalidSigningOptions("%s requires a positive ExpiresAfter", Expires)
	}
	if !hasExpires && options.ExpiresAfter > 0 {
		return cavageSigningConfiguration{}, invalidSigningOptions("ExpiresAfter requires %s in the effective signed-header list", Expires)
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
		if compatibility.AlgorithmField != AlgorithmFieldStrict {
			return "", invalidSigningOptions("Extension and a non-strict AlgorithmField cannot be combined")
		}
		extension := compatibility.Extension
		if extension.Label == "" {
			return "", invalidSigningOptions("Extension.Label must not be empty")
		}
		if err := validateCavageQuotedStringValue("algorithm", extension.Label); err != nil {
			return "", invalidSigningOptions("invalid Extension.Label: %v", err)
		}
		if isReservedCavageAlgorithmLabel(extension.Label) {
			return "", invalidSigningOptions("Extension must not override known label %q", extension.Label)
		}
		if _, err := algorithmDefinitionFor(extension.Algorithm); err != nil {
			return "", invalidSigningOptions("Extension.Algorithm is invalid: %v", err)
		}
		if extension.Algorithm != id {
			return "", invalidSigningOptions("Extension.Algorithm %d does not match SigningKey AlgorithmID %d", extension.Algorithm, id)
		}
		return extension.Label, nil
	}

	switch compatibility.AlgorithmField {
	case AlgorithmFieldStrict:
		if !isStrictCavageAlgorithm(id) {
			return "", invalidSigningAlgorithmOptions(fmt.Errorf("%w: AlgorithmID %d is not active in strict mode", ErrInvalidSignatureAlgorithm, id))
		}
		return hs2019, nil
	case AlgorithmFieldOmitted:
		if _, err := algorithmDefinitionFor(id); err != nil {
			return "", invalidSigningOptions("invalid AlgorithmID: %v", err)
		}
		return "", nil
	case AlgorithmFieldLegacy:
		label, ok := legacyAlgorithmLabel(id)
		if !ok {
			return "", invalidSigningAlgorithmOptions(fmt.Errorf("%w: AlgorithmID %d has no deprecated label", ErrInvalidSignatureAlgorithm, id))
		}
		return label, nil
	case AlgorithmFieldHS2019WithSHA256:
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
		return []string{Created}, false, nil
	}

	headers := []string{Created}
	headersPresent := false
	if isRequest {
		headers = []string{RequestTarget, Created}
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
		header.Set(Signature, value)
	case CavageSignaturePlacementAuthorization:
		header.Set(Authorization, "Signature "+value)
	}
}

func (s *CavageSigner) currentTime() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func signingTimestamps(now time.Time, headers []string, expiresAfter time.Duration) (created, expires string) {
	if slices.Contains(headers, Created) {
		created = strconv.FormatInt(now.Unix(), 10)
	}
	if slices.Contains(headers, Expires) {
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
		digest, err := hashSigningString(algorithm.hash, data)
		if err != nil {
			return nil, err
		}
		return rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), algorithm.hash, digest)
	case algorithmKeyECDSA:
		digest, err := hashSigningString(algorithm.hash, data)
		if err != nil {
			return nil, err
		}
		return ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), digest)
	case algorithmKeyEd25519:
		switch privateKey := key.(type) {
		case ed25519.PrivateKey:
			return ed25519.Sign(privateKey, data), nil
		case *ed25519.PrivateKey:
			return ed25519.Sign(*privateKey, data), nil
		}
	}
	return nil, fmt.Errorf("%w: unsupported asymmetric AlgorithmID %d", ErrAlgorithmMismatch, algorithm.id)
}

func signHMAC(secret []byte, hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("trusted hash %v is unavailable", hash)
	}
	mac := hmac.New(hash.New, secret)
	if _, err := mac.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write signing string to HMAC: %w", err)
	}
	return mac.Sum(nil), nil
}

func hashSigningString(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("trusted hash %v is unavailable", hash)
	}
	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to hash signing string: %w", err)
	}
	return h.Sum(nil), nil
}

func invalidSigningOptions(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSigningOptions, fmt.Sprintf(format, args...))
}

func invalidSigningAlgorithmOptions(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidSigningOptions, err)
}
