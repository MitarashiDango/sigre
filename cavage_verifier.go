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
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

var defaultCavageVerificationAlgorithms = []AlgorithmID{
	AlgorithmRSAPKCS1v15SHA512,
	AlgorithmECDSASHA512,
	AlgorithmEd25519,
	AlgorithmHMACSHA512,
}

type cavageVerifierIdentity struct {
	value byte
}

type cavageVerificationConfig struct {
	requestSource            CavageRequestSignatureSource
	requiredHeaders          []string
	allowedAlgorithms        map[AlgorithmID]struct{}
	requireAlgorithm         bool
	requireExplicitHeaders   bool
	maxSignatureAge          time.Duration
	maxDateAge               time.Duration
	now                      func() time.Time
	allowedCreatedFutureSkew time.Duration
	allowedExpiredSkew       time.Duration
	allowedLegacyAlgorithms  map[AlgorithmID]struct{}
	extensionAlgorithms      map[string]AlgorithmID
	allowHS2019WithSHA256    bool
}

// CavageVerifier parses and verifies immutable Cavage HTTP signature
// snapshots. Construct it with [NewCavageVerifier]; its zero value is invalid.
// A constructed verifier is immutable and may be used concurrently. It does
// not parse or verify RFC 9421 HTTP Message Signatures.
type CavageVerifier struct {
	identity *cavageVerifierIdentity
	config   cavageVerificationConfig
}

// CavageSignature is an immutable snapshot returned by ParseRequest or
// ParseResponse. It owns the parsed parameters, signature bytes, effective
// signed fields, signing string, and message values used to build that string.
// A snapshot can be verified only by the CavageVerifier that parsed it.
type CavageSignature struct {
	origin            *cavageVerifierIdentity
	keyID             string
	placement         CavageSignaturePlacement
	algorithmLabel    string
	algorithmPresent  bool
	created           time.Time
	createdPresent    bool
	expires           time.Time
	expiresPresent    bool
	signedHeaders     []string
	headersExplicit   bool
	signature         []byte
	signingString     []byte
	method            string
	requestTarget     string
	host              string
	signedFieldValues map[string][]string
}

// NewCavageVerifier validates and copies opts. Passing nil selects the strict
// zero-value policy. The constructor does not call opts.Now.
func NewCavageVerifier(opts *CavageVerificationOptions) (*CavageVerifier, error) {
	config, err := newCavageVerificationConfig(opts)
	if err != nil {
		return nil, wrapSigreError(err)
	}
	return &CavageVerifier{
		identity: &cavageVerifierIdentity{},
		config:   config,
	}, nil
}

// ParseRequest parses the configured request signature source and returns an
// immutable snapshot. The request is not modified. The default source is only
// the Signature field; RFC 9421 Signature-Input is always ignored.
// If trailer is signed, call ParseRequest before Body reaches EOF because
// net/http then merges received fields and the declaration cannot be recovered.
func (v *CavageVerifier) ParseRequest(req *http.Request) (*CavageSignature, error) {
	if err := v.validateConstructed(); err != nil {
		return nil, wrapSigreError(err)
	}
	if req == nil {
		return nil, wrapSigreError(fmt.Errorf("%w: request is nil", ErrInvalidHTTPMessage))
	}
	candidate, err := requestCavageSignatureCandidate(req.Header, v.config.requestSource)
	if err != nil {
		return nil, wrapSigreError(err)
	}
	if candidate.placement == 0 {
		return nil, wrapSigreError(ErrMissingSignature)
	}
	snapshot := cavageMessageSnapshot{
		isRequest: true,
		host:      req.Host,
		method:    req.Method,
		resolveRequestTarget: func() (string, error) {
			return receivedRequestTarget(req)
		},
		header:           req.Header,
		transferEncoding: req.TransferEncoding,
		trailer:          req.Trailer,
	}
	signature, err := v.parse(candidate, snapshot)
	return signature, wrapSigreError(err)
}

// ParseResponse parses only the response Signature field and returns an
// immutable snapshot. Authorization and Signature-Input are ignored, and the
// response is not modified.
// If trailer is signed, call ParseResponse before Body reaches EOF because
// net/http then merges received fields and the declaration cannot be recovered.
func (v *CavageVerifier) ParseResponse(res *http.Response) (*CavageSignature, error) {
	if err := v.validateConstructed(); err != nil {
		return nil, wrapSigreError(err)
	}
	if res == nil {
		return nil, wrapSigreError(fmt.Errorf("%w: response is nil", ErrInvalidHTTPMessage))
	}
	candidate, err := signatureHeaderCandidate(res.Header)
	if err != nil {
		return nil, wrapSigreError(err)
	}
	if candidate.placement == 0 {
		return nil, wrapSigreError(ErrMissingSignature)
	}
	snapshot := cavageMessageSnapshot{
		header:           res.Header,
		transferEncoding: res.TransferEncoding,
		trailer:          res.Trailer,
	}
	if res.Request != nil {
		snapshot.method = res.Request.Method
		snapshot.resolveRequestTarget = func() (string, error) {
			return associatedRequestTarget(res.Request)
		}
	}
	signature, err := v.parse(candidate, snapshot)
	return signature, wrapSigreError(err)
}

// Verify checks snapshot with an asymmetric trusted key. The received KeyID
// and algorithm label are attacker-controlled inputs; callers must resolve the
// KeyID to trusted metadata before calling Verify. Verification does not read
// the original HTTP message and does not compare a Digest field with a body.
func (v *CavageVerifier) Verify(signature *CavageSignature, key VerificationKey) error {
	if err := v.validateSignature(signature); err != nil {
		return wrapSigreError(err)
	}
	algorithm, err := validateVerificationMetadata(signature, key.Metadata)
	if err != nil {
		return wrapSigreError(err)
	}
	if isMissingPublicKey(key.PublicKey) {
		return wrapSigreError(ErrMissingPublicKey)
	}
	if algorithm.keyKind == algorithmKeyHMAC {
		return wrapSigreError(fmt.Errorf("%w: HMAC AlgorithmID must be used with VerifyHMAC", ErrAlgorithmMismatch))
	}
	if err := validateVerificationPublicKey(key.PublicKey, algorithm.keyKind); err != nil {
		return wrapSigreError(err)
	}
	if err := v.validateTrustedAlgorithm(signature, key.Metadata.Algorithm); err != nil {
		return wrapSigreError(err)
	}
	return wrapSigreError(verifyAsymmetric(key.PublicKey, algorithm, signature.signature, signature.signingString))
}

// VerifyHMAC checks snapshot with trusted HMAC metadata and a shared secret.
// It does not read the original HTTP message and never calls the verifier clock.
func (v *CavageVerifier) VerifyHMAC(signature *CavageSignature, key HMACVerificationKey) error {
	if err := v.validateSignature(signature); err != nil {
		return wrapSigreError(err)
	}
	algorithm, err := validateVerificationMetadata(signature, key.Metadata)
	if err != nil {
		return wrapSigreError(err)
	}
	if len(key.Secret) == 0 {
		return wrapSigreError(ErrMissingSharedSecret)
	}
	if algorithm.keyKind != algorithmKeyHMAC {
		return wrapSigreError(fmt.Errorf("%w: asymmetric AlgorithmID must be used with Verify", ErrAlgorithmMismatch))
	}
	if err := v.validateTrustedAlgorithm(signature, key.Metadata.Algorithm); err != nil {
		return wrapSigreError(err)
	}
	return wrapSigreError(verifyHMAC(key.Secret, signature.signature, signature.signingString, algorithm.hash))
}

// KeyID returns the opaque, attacker-controlled keyId parameter.
func (s *CavageSignature) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// Placement returns the actual field from which the Cavage signature was parsed.
func (s *CavageSignature) Placement() CavageSignaturePlacement {
	if s == nil {
		return 0
	}
	return s.placement
}

// AlgorithmLabel returns the exact, case-sensitive wire algorithm label and
// whether the algorithm parameter was present.
func (s *CavageSignature) AlgorithmLabel() (string, bool) {
	if s == nil {
		return "", false
	}
	return s.algorithmLabel, s.algorithmPresent
}

// Created returns the parsed created time and whether the parameter was present.
func (s *CavageSignature) Created() (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	return s.created, s.createdPresent
}

// Expires returns the parsed expires time and whether the parameter was present.
func (s *CavageSignature) Expires() (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	return s.expires, s.expiresPresent
}

// SignedHeaders returns a copy of the effective signed-header list. If the
// headers parameter was omitted, the returned list contains only (created).
func (s *CavageSignature) SignedHeaders() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.signedHeaders...)
}

// HeadersExplicit reports whether the wire signature contained a headers parameter.
func (s *CavageSignature) HeadersExplicit() bool {
	return s != nil && s.headersExplicit
}

func newCavageVerificationConfig(opts *CavageVerificationOptions) (cavageVerificationConfig, error) {
	options := CavageVerificationOptions{}
	if opts != nil {
		options = *opts
	}
	if options.RequestSignatureSource > CavageRequestSignatureSourceSignatureOrAuthorization {
		return cavageVerificationConfig{}, fmt.Errorf("%w: unsupported RequestSignatureSource %d", ErrInvalidVerificationOptions, options.RequestSignatureSource)
	}
	if options.MaxSignatureAge < 0 {
		return cavageVerificationConfig{}, fmt.Errorf("%w: MaxSignatureAge must not be negative", ErrInvalidVerificationOptions)
	}
	if options.MaxDateAge < 0 {
		return cavageVerificationConfig{}, fmt.Errorf("%w: MaxDateAge must not be negative", ErrInvalidVerificationOptions)
	}

	config := cavageVerificationConfig{
		requestSource:          options.RequestSignatureSource,
		requireAlgorithm:       options.RequireAlgorithm,
		requireExplicitHeaders: options.RequireExplicitHeaders,
		maxSignatureAge:        options.MaxSignatureAge,
		maxDateAge:             options.MaxDateAge,
		now:                    options.Now,
	}
	for _, configuredName := range options.RequiredHeaders {
		name, err := normalizeCavageSignedHeaderName(configuredName)
		if err != nil {
			return cavageVerificationConfig{}, fmt.Errorf("%w: invalid RequiredHeaders entry %q: %v", ErrInvalidVerificationOptions, configuredName, err)
		}
		config.requiredHeaders = append(config.requiredHeaders, name)
	}

	allowed := options.AllowedAlgorithms
	if len(allowed) == 0 {
		allowed = defaultCavageVerificationAlgorithms
	}
	config.allowedAlgorithms = make(map[AlgorithmID]struct{}, len(allowed))
	for _, id := range allowed {
		if _, err := algorithmDefinitionFor(id); err != nil {
			return cavageVerificationConfig{}, fmt.Errorf("%w: AllowedAlgorithms contains AlgorithmID %d", ErrInvalidVerificationOptions, id)
		}
		config.allowedAlgorithms[id] = struct{}{}
	}

	if options.Compatibility == nil {
		return config, nil
	}
	compatibility := *options.Compatibility
	if compatibility.AllowedCreatedFutureSkew < 0 {
		return cavageVerificationConfig{}, fmt.Errorf("%w: AllowedCreatedFutureSkew must not be negative", ErrInvalidVerificationOptions)
	}
	if compatibility.AllowedExpiredSkew < 0 {
		return cavageVerificationConfig{}, fmt.Errorf("%w: AllowedExpiredSkew must not be negative", ErrInvalidVerificationOptions)
	}
	config.allowedCreatedFutureSkew = compatibility.AllowedCreatedFutureSkew
	config.allowedExpiredSkew = compatibility.AllowedExpiredSkew
	config.allowHS2019WithSHA256 = compatibility.AllowHS2019WithSHA256
	config.allowedLegacyAlgorithms = make(map[AlgorithmID]struct{}, len(compatibility.AllowedLegacyAlgorithms))
	for _, id := range compatibility.AllowedLegacyAlgorithms {
		if !isLegacyCavageAlgorithm(id) {
			return cavageVerificationConfig{}, fmt.Errorf("%w: AllowedLegacyAlgorithms contains non-legacy AlgorithmID %d", ErrInvalidVerificationOptions, id)
		}
		config.allowedLegacyAlgorithms[id] = struct{}{}
	}
	config.extensionAlgorithms = make(map[string]AlgorithmID, len(compatibility.ExtensionAlgorithms))
	for label, id := range compatibility.ExtensionAlgorithms {
		if label == "" {
			return cavageVerificationConfig{}, fmt.Errorf("%w: ExtensionAlgorithms contains an empty label", ErrInvalidVerificationOptions)
		}
		if err := validateCavageQuotedStringValue("algorithm", label); err != nil {
			return cavageVerificationConfig{}, fmt.Errorf("%w: invalid extension label %q: %v", ErrInvalidVerificationOptions, label, err)
		}
		if isReservedCavageAlgorithmLabel(label) {
			return cavageVerificationConfig{}, fmt.Errorf("%w: ExtensionAlgorithms must not override known label %q", ErrInvalidVerificationOptions, label)
		}
		if _, err := algorithmDefinitionFor(id); err != nil {
			return cavageVerificationConfig{}, fmt.Errorf("%w: extension label %q maps to unsupported AlgorithmID %d", ErrInvalidVerificationOptions, label, id)
		}
		config.extensionAlgorithms[label] = id
	}
	return config, nil
}

func (v *CavageVerifier) validateConstructed() error {
	if v == nil || v.identity == nil {
		return fmt.Errorf("%w: CavageVerifier was not created by NewCavageVerifier", ErrInvalidVerificationOptions)
	}
	return nil
}

func (v *CavageVerifier) validateSignature(signature *CavageSignature) error {
	if err := v.validateConstructed(); err != nil {
		return err
	}
	if signature == nil || signature.origin == nil || signature.origin != v.identity {
		return fmt.Errorf("%w: CavageSignature was not parsed by this CavageVerifier", ErrInvalidHTTPMessage)
	}
	return nil
}

type cavageMessageSnapshot struct {
	isRequest            bool
	host                 string
	method               string
	resolveRequestTarget func() (string, error)
	header               http.Header
	transferEncoding     []string
	trailer              http.Header
}

func (v *CavageVerifier) parse(candidate cavageSignatureCandidate, message cavageMessageSnapshot) (*CavageSignature, error) {
	params, err := parseCavageParams(candidate.value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignatureParameters, err)
	}
	decodedSignature, err := base64.StdEncoding.Strict().DecodeString(params.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature Base64: %v", ErrInvalidSignatureParameters, err)
	}

	var created, expires time.Time
	if params.CreatedPresent {
		created, err = parseCavageCreated(params.Created)
		if err != nil {
			return nil, err
		}
	}
	if params.ExpiresPresent {
		expires, err = parseCavageExpires(params.Expires)
		if err != nil {
			return nil, err
		}
	}

	headers, err := effectiveCavageSignedHeaders(params)
	if err != nil {
		return nil, err
	}
	if v.config.requireExplicitHeaders && !params.HeadersPresent {
		return nil, fmt.Errorf("%w: headers parameter is required", ErrRequiredHeaderMissing)
	}
	if err := requireCavageHeaders(headers, v.config.requiredHeaders); err != nil {
		return nil, err
	}
	if v.config.maxSignatureAge > 0 && !slices.Contains(headers, Created) {
		return nil, fmt.Errorf("%w: MaxSignatureAge requires %s", ErrRequiredHeaderMissing, Created)
	}
	if v.config.maxDateAge > 0 && !slices.Contains(headers, "date") {
		return nil, fmt.Errorf("%w: MaxDateAge requires date", ErrRequiredHeaderMissing)
	}

	if slices.Contains(headers, Created) && !params.CreatedPresent {
		return nil, fmt.Errorf("%w: %s requires a created parameter", ErrInvalidCreationTime, Created)
	}
	if slices.Contains(headers, Expires) && !params.ExpiresPresent {
		return nil, fmt.Errorf("%w: %s requires an expires parameter", ErrInvalidExpirationTime, Expires)
	}

	if err := v.validateWireAlgorithmBeforeKey(params, headers); err != nil {
		return nil, err
	}
	ownedHeaders, err := snapshotCavageSignedFields(message, headers, v.config.maxDateAge > 0)
	if err != nil {
		return nil, err
	}
	requestTarget := ""
	if slices.Contains(headers, RequestTarget) {
		if message.method == "" {
			return nil, fmt.Errorf("%w: method is required by %s", ErrInvalidHTTPMessage, RequestTarget)
		}
		if message.resolveRequestTarget != nil {
			requestTarget, err = message.resolveRequestTarget()
			if err != nil {
				return nil, err
			}
		}
		if requestTarget == "" {
			return nil, fmt.Errorf("%w: request-target is required by %s", ErrInvalidHTTPMessage, RequestTarget)
		}
	}

	var parsedDate time.Time
	if v.config.maxDateAge > 0 {
		dateValues := message.header.Values("Date")
		if len(dateValues) != 1 {
			return nil, fmt.Errorf("%w: MaxDateAge requires exactly one Date value, got %d", ErrInvalidDate, len(dateValues))
		}
		parsedDate, err = http.ParseTime(dateValues[0])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidDate, err)
		}
		ownedHeaders["Date"] = append([]string(nil), dateValues...)
	}

	createdText, expiresText := "", ""
	if params.CreatedPresent {
		createdText = params.Created
	}
	if params.ExpiresPresent {
		expiresText = params.Expires
	}
	buf, err := generateSignatureStringBuffer(
		headers,
		message.host,
		message.method,
		requestTarget,
		ownedHeaders,
		createdText,
		expiresText,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create signing string: %v", ErrInvalidHTTPMessage, err)
	}

	if params.CreatedPresent || params.ExpiresPresent || v.config.maxDateAge > 0 {
		now := v.currentTime()
		if params.CreatedPresent {
			if timeAfterDuration(created, now, v.config.allowedCreatedFutureSkew) {
				return nil, fmt.Errorf("%w: created is after the permitted future boundary", ErrInvalidCreationTime)
			}
			if v.config.maxSignatureAge > 0 && timeAfterDuration(now, created, v.config.maxSignatureAge) {
				return nil, fmt.Errorf("%w: signature age exceeds MaxSignatureAge", ErrInvalidCreationTime)
			}
		}
		if params.ExpiresPresent && timeAfterDuration(now, expires, v.config.allowedExpiredSkew) {
			return nil, fmt.Errorf("%w: expires is before the permitted past boundary", ErrSignatureExpired)
		}
		if v.config.maxDateAge > 0 && (timeAfterDuration(parsedDate, now, v.config.maxDateAge) || timeAfterDuration(now, parsedDate, v.config.maxDateAge)) {
			return nil, fmt.Errorf("%w: Date differs from current time by more than MaxDateAge", ErrInvalidDate)
		}
	}

	return &CavageSignature{
		origin:            v.identity,
		keyID:             params.KeyID,
		placement:         candidate.placement,
		algorithmLabel:    params.Algorithm,
		algorithmPresent:  params.AlgorithmPresent,
		created:           created,
		createdPresent:    params.CreatedPresent,
		expires:           expires,
		expiresPresent:    params.ExpiresPresent,
		signedHeaders:     append([]string(nil), headers...),
		headersExplicit:   params.HeadersPresent,
		signature:         append([]byte(nil), decodedSignature...),
		signingString:     append([]byte(nil), buf.Bytes()...),
		method:            message.method,
		requestTarget:     requestTarget,
		host:              message.host,
		signedFieldValues: cloneHeaderValues(ownedHeaders),
	}, nil
}

func effectiveCavageSignedHeaders(params *cavageParams) ([]string, error) {
	configured := params.Headers
	if !params.HeadersPresent {
		configured = []string{Created}
	}
	headers := make([]string, 0, len(configured))
	for _, configuredName := range configured {
		name, err := normalizeCavageSignedHeaderName(configuredName)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid signed header %q: %v", ErrInvalidSignatureParameters, configuredName, err)
		}
		headers = append(headers, name)
	}
	return headers, nil
}

func requireCavageHeaders(signed, required []string) error {
	for _, name := range required {
		if !slices.Contains(signed, name) {
			return fmt.Errorf("%w: %q is not in the effective signed-header list", ErrRequiredHeaderMissing, name)
		}
	}
	return nil
}

func (v *CavageVerifier) validateWireAlgorithmBeforeKey(params *cavageParams, headers []string) error {
	if !params.AlgorithmPresent {
		if v.config.requireAlgorithm {
			return fmt.Errorf("%w: algorithm parameter is required", ErrInvalidSignatureAlgorithm)
		}
		return nil
	}
	label := params.Algorithm
	if label == "" {
		return fmt.Errorf("%w: algorithm label is empty", ErrInvalidSignatureAlgorithm)
	}

	switch label {
	case hs2019:
		for id := range v.config.allowedAlgorithms {
			if isStrictCavageAlgorithm(id) || id == AlgorithmRSAPKCS1v15SHA256 && v.config.allowHS2019WithSHA256 {
				return nil
			}
		}
		return fmt.Errorf("%w: hs2019 has no permitted trusted algorithm", ErrInvalidSignatureAlgorithm)
	default:
		if legacyID, ok := legacyAlgorithmID(label); ok {
			if _, ok := v.config.allowedLegacyAlgorithms[legacyID]; !ok {
				return fmt.Errorf("%w: deprecated algorithm %q is not enabled", ErrInvalidSignatureAlgorithm, label)
			}
			if !v.isAlgorithmAllowed(legacyID) {
				return fmt.Errorf("%w: AlgorithmID %d is not permitted", ErrInvalidSignatureAlgorithm, legacyID)
			}
		} else {
			extensionID, ok := v.config.extensionAlgorithms[label]
			if !ok {
				return fmt.Errorf("%w: unregistered algorithm label %q", ErrInvalidSignatureAlgorithm, label)
			}
			if !v.isAlgorithmAllowed(extensionID) {
				return fmt.Errorf("%w: extension AlgorithmID %d is not permitted", ErrInvalidSignatureAlgorithm, extensionID)
			}
		}
	}
	if family := legacyAlgorithmFamily(label); family != "" {
		if err := validateCreatedExpiresWithAlgorithm(headers, family); err != nil {
			return err
		}
	}
	return nil
}

func snapshotCavageSignedFields(message cavageMessageSnapshot, signedHeaders []string, deferDate bool) (http.Header, error) {
	owned := make(http.Header)
	for _, name := range signedHeaders {
		switch name {
		case RequestTarget, Created, Expires:
			continue
		case "host":
			if message.isRequest {
				if message.host == "" {
					return nil, fmt.Errorf("%w: host", ErrSignedHeaderMissing)
				}
				owned["Host"] = []string{message.host}
				continue
			}
		case "transfer-encoding":
			if len(message.transferEncoding) == 0 {
				return nil, fmt.Errorf("%w: transfer-encoding", ErrSignedHeaderMissing)
			}
			owned["Transfer-Encoding"] = append([]string(nil), message.transferEncoding...)
			continue
		case "trailer":
			if len(message.trailer) > 0 {
				if cavageTrailerValuesReceived(message.trailer) {
					return nil, fmt.Errorf("%w: trailer", ErrSignedHeaderMissing)
				}
				owned["Trailer"] = []string{cavageTrailerDeclaration(message.trailer)}
				continue
			}
		}

		values, ok := message.header[http.CanonicalHeaderKey(name)]
		if !ok || len(values) == 0 {
			if deferDate && name == "date" {
				continue
			}
			return nil, fmt.Errorf("%w: %s", ErrSignedHeaderMissing, name)
		}
		owned[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
	return owned, nil
}

func cavageTrailerValuesReceived(trailer http.Header) bool {
	for _, values := range trailer {
		if values != nil {
			return true
		}
	}
	return false
}

func cavageTrailerDeclaration(trailer http.Header) string {
	keys := make([]string, 0, len(trailer))
	for key := range trailer {
		keys = append(keys, http.CanonicalHeaderKey(key))
	}
	slices.Sort(keys)
	return strings.Join(keys, ",")
}

func cloneHeaderValues(header http.Header) map[string][]string {
	cloned := make(map[string][]string, len(header))
	for name, values := range header {
		cloned[name] = append([]string(nil), values...)
	}
	return cloned
}

func parseCavageCreated(value string) (time.Time, error) {
	if !isSignedDecimalInteger(value) {
		return time.Time{}, fmt.Errorf("%w: created must be -?[0-9]+", ErrInvalidCreationTime)
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: created is outside the int64 range", ErrInvalidCreationTime)
	}
	created := time.Unix(seconds, 0)
	if created.Unix() != seconds || created.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("%w: created is outside the time.Time range", ErrInvalidCreationTime)
	}
	return created, nil
}

func parseCavageExpires(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%w: expires is empty", ErrInvalidExpirationTime)
	}
	negative := value[0] == '-'
	digits := value
	if negative {
		digits = value[1:]
	}
	whole, fraction, hasFraction := strings.Cut(digits, ".")
	if whole == "" || !allDecimalDigits(whole) || hasFraction && (fraction == "" || !allDecimalDigits(fraction)) {
		return time.Time{}, fmt.Errorf("%w: expires must be -?[0-9]+ or -?[0-9]+\\.[0-9]+", ErrInvalidExpirationTime)
	}
	fraction = strings.TrimRight(fraction, "0")
	if len(fraction) > 9 {
		return time.Time{}, fmt.Errorf("%w: expires must have at most 9 fractional digits after trailing zeros are removed", ErrInvalidExpirationTime)
	}
	magnitude, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: expires is outside the int64 range", ErrInvalidExpirationTime)
	}
	var fractionalNanoseconds int64
	if hasFraction {
		padded := fraction + strings.Repeat("0", 9-len(fraction))
		fractionalNanoseconds, _ = strconv.ParseInt(padded, 10, 32)
	}

	var seconds, nanoseconds int64
	if !negative {
		if magnitude > uint64(^uint64(0)>>1) {
			return time.Time{}, fmt.Errorf("%w: expires is outside the int64 range", ErrInvalidExpirationTime)
		}
		seconds = int64(magnitude)
		nanoseconds = fractionalNanoseconds
	} else if fractionalNanoseconds == 0 {
		if magnitude > uint64(^uint64(0)>>1)+1 {
			return time.Time{}, fmt.Errorf("%w: expires is outside the int64 range", ErrInvalidExpirationTime)
		}
		if magnitude == uint64(^uint64(0)>>1)+1 {
			seconds = -1 << 63
		} else {
			seconds = -int64(magnitude)
		}
	} else {
		if magnitude > uint64(^uint64(0)>>1) {
			return time.Time{}, fmt.Errorf("%w: expires is outside the int64 range", ErrInvalidExpirationTime)
		}
		seconds = -int64(magnitude) - 1
		nanoseconds = int64(time.Second) - fractionalNanoseconds
	}

	expires := time.Unix(seconds, nanoseconds)
	if expires.Unix() != seconds || int64(expires.Nanosecond()) != nanoseconds {
		return time.Time{}, fmt.Errorf("%w: expires is outside the time.Time range", ErrInvalidExpirationTime)
	}
	return expires, nil
}

func isSignedDecimalInteger(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '-' {
		value = value[1:]
	}
	return value != "" && allDecimalDigits(value)
}

func allDecimalDigits(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// timeAfterDuration reports whether value is strictly later than base plus
// duration without converting the difference to time.Duration. All callers
// provide a non-negative duration validated by NewCavageVerifier.
func timeAfterDuration(value, base time.Time, duration time.Duration) bool {
	boundarySeconds := base.Unix()
	boundaryNanoseconds := int64(base.Nanosecond()) + int64(duration%time.Second)
	secondsToAdd := int64(duration / time.Second)
	if boundaryNanoseconds >= int64(time.Second) {
		boundaryNanoseconds -= int64(time.Second)
		secondsToAdd++
	}
	if boundarySeconds > math.MaxInt64-secondsToAdd {
		return false
	}
	boundarySeconds += secondsToAdd

	valueSeconds := value.Unix()
	if valueSeconds != boundarySeconds {
		return valueSeconds > boundarySeconds
	}
	return int64(value.Nanosecond()) > boundaryNanoseconds
}

func (v *CavageVerifier) currentTime() time.Time {
	if v.config.now == nil {
		return time.Now().UTC()
	}
	return v.config.now().UTC()
}

func validateVerificationMetadata(signature *CavageSignature, metadata TrustedKeyMetadata) (algorithmDefinition, error) {
	if metadata.KeyID == "" {
		return algorithmDefinition{}, fmt.Errorf("%w: KeyID is empty", ErrInvalidKeyMetadata)
	}
	algorithm, err := algorithmDefinitionFor(metadata.Algorithm)
	if err != nil {
		return algorithmDefinition{}, err
	}
	if signature.keyID != metadata.KeyID {
		return algorithmDefinition{}, fmt.Errorf("%w: received %q, trusted %q", ErrKeyIDMismatch, signature.keyID, metadata.KeyID)
	}
	return algorithm, nil
}

func (v *CavageVerifier) validateTrustedAlgorithm(signature *CavageSignature, id AlgorithmID) error {
	if !v.isAlgorithmAllowed(id) {
		return fmt.Errorf("%w: trusted AlgorithmID %d is not permitted", ErrInvalidSignatureAlgorithm, id)
	}
	if !signature.algorithmPresent {
		return nil
	}
	label := signature.algorithmLabel
	if label == hs2019 {
		if isStrictCavageAlgorithm(id) || id == AlgorithmRSAPKCS1v15SHA256 && v.config.allowHS2019WithSHA256 {
			return nil
		}
		return fmt.Errorf("%w: algorithm %q does not identify trusted AlgorithmID %d", ErrAlgorithmMismatch, label, id)
	}
	if legacyID, ok := legacyAlgorithmID(label); ok {
		if legacyID != id {
			return fmt.Errorf("%w: algorithm %q identifies AlgorithmID %d, trusted metadata specifies %d", ErrAlgorithmMismatch, label, legacyID, id)
		}
		return nil
	}
	extensionID, ok := v.config.extensionAlgorithms[label]
	if !ok || extensionID != id {
		return fmt.Errorf("%w: extension label %q does not identify trusted AlgorithmID %d", ErrAlgorithmMismatch, label, id)
	}
	return nil
}

func (v *CavageVerifier) isAlgorithmAllowed(id AlgorithmID) bool {
	_, ok := v.config.allowedAlgorithms[id]
	return ok
}

func isMissingPublicKey(key crypto.PublicKey) bool {
	if key == nil {
		return true
	}
	switch publicKey := key.(type) {
	case *rsa.PublicKey:
		return publicKey == nil
	case *ecdsa.PublicKey:
		return publicKey == nil
	case ed25519.PublicKey:
		return len(publicKey) == 0
	case *ed25519.PublicKey:
		return publicKey == nil || len(*publicKey) == 0
	default:
		return false
	}
}

func validateVerificationPublicKey(key crypto.PublicKey, expected algorithmKeyKind) error {
	switch expected {
	case algorithmKeyRSA:
		publicKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires RSA, public key is %T", ErrAlgorithmMismatch, key)
		}
		if publicKey.N == nil || publicKey.N.Sign() <= 0 || publicKey.N.Bit(0) == 0 || publicKey.E < 2 || publicKey.E&1 == 0 || publicKey.E > math.MaxInt32 {
			return fmt.Errorf("%w: invalid RSA public key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyECDSA:
		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: AlgorithmID requires ECDSA, public key is %T", ErrAlgorithmMismatch, key)
		}
		if publicKey.Curve == nil || publicKey.X == nil || publicKey.Y == nil || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
			return fmt.Errorf("%w: invalid ECDSA public key", ErrUnsupportedKeyFormat)
		}
	case algorithmKeyEd25519:
		switch publicKey := key.(type) {
		case ed25519.PublicKey:
			if len(publicKey) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: invalid Ed25519 public key length %d", ErrUnsupportedKeyFormat, len(publicKey))
			}
		case *ed25519.PublicKey:
			if len(*publicKey) != ed25519.PublicKeySize {
				return fmt.Errorf("%w: invalid Ed25519 public key length %d", ErrUnsupportedKeyFormat, len(*publicKey))
			}
		default:
			return fmt.Errorf("%w: AlgorithmID requires Ed25519, public key is %T", ErrAlgorithmMismatch, key)
		}
	default:
		return fmt.Errorf("%w: asymmetric verification received a non-public-key AlgorithmID", ErrAlgorithmMismatch)
	}
	return nil
}

func verifyAsymmetric(key crypto.PublicKey, algorithm algorithmDefinition, sig, data []byte) error {
	switch algorithm.keyKind {
	case algorithmKeyRSA:
		return verifyRSA(key.(*rsa.PublicKey), sig, data, algorithm.hash)
	case algorithmKeyECDSA:
		return verifyECDSA(key.(*ecdsa.PublicKey), sig, data, algorithm.hash)
	case algorithmKeyEd25519:
		switch publicKey := key.(type) {
		case ed25519.PublicKey:
			return verifyEd25519(publicKey, sig, data)
		case *ed25519.PublicKey:
			return verifyEd25519(*publicKey, sig, data)
		}
	}
	return fmt.Errorf("%w: unsupported asymmetric AlgorithmID %d", ErrAlgorithmMismatch, algorithm.id)
}

func verifyRSA(publicKey *rsa.PublicKey, sig, data []byte, hashID crypto.Hash) error {
	digest, err := hashMessage(hashID, data)
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(publicKey, hashID, digest, sig); err != nil {
		return fmt.Errorf("%w: RSA PKCS #1 v1.5 verification failed: %v", ErrVerification, err)
	}
	return nil
}

func verifyECDSA(publicKey *ecdsa.PublicKey, sig, data []byte, hashID crypto.Hash) error {
	digest, err := hashMessage(hashID, data)
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
		return nil, fmt.Errorf("unsupported trusted hash %v", hashID)
	}
}

func hmacHash(hashID crypto.Hash) (func() hash.Hash, error) {
	switch hashID {
	case crypto.SHA256:
		return sha256.New, nil
	case crypto.SHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported trusted HMAC hash %v", hashID)
	}
}
