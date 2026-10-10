package sigre

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

type cavageVerifierIdentity struct {
	// value keeps the struct's size nonzero, so distinct verifiers have distinct
	// identity pointers. Pointers to separate zero-size variables may be equal.
	// Keep this field even if static analysis reports it as unused.
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
// Methods on a verifier not created by [NewCavageVerifier], including a zero
// value or nil, fail with [ErrInvalidVerificationOptions].
type CavageVerifier struct {
	identity *cavageVerifierIdentity
	config   cavageVerificationConfig
}

// CavageSignature is an immutable snapshot returned by [CavageVerifier.ParseRequest]
// or [CavageVerifier.ParseResponse]. It holds copies of the parsed parameters and
// of the signed message content, so changing the HTTP message after parsing does
// not affect verification. A snapshot can be verified only by the [CavageVerifier]
// that parsed it; any other snapshot is rejected with [ErrInvalidHTTPMessage].
type CavageSignature struct {
	origin           *cavageVerifierIdentity
	keyID            string
	placement        CavageSignaturePlacement
	algorithmLabel   string
	algorithmPresent bool
	created          time.Time
	createdPresent   bool
	expires          time.Time
	expiresPresent   bool
	signedHeaders    []string
	headersExplicit  bool
	signature        []byte
	signingString    []byte
}

// NewCavageVerifier validates and copies opts, so later changes to opts do not
// affect the verifier. Passing nil selects the strict zero-value policy. Invalid
// or conflicting options cause [ErrInvalidVerificationOptions]. The constructor
// does not call opts.Now.
func NewCavageVerifier(opts *CavageVerificationOptions) (*CavageVerifier, error) {
	config, err := newCavageVerificationConfig(opts)
	if err != nil {
		return nil, wrapError(err)
	}
	return &CavageVerifier{
		identity: &cavageVerifierIdentity{},
		config:   config,
	}, nil
}

// ParseRequest parses the signature selected by
// [CavageVerificationOptions.RequestSignatureSource] from a request received by
// a net/http server and returns an immutable snapshot. The default source is only
// the Signature field; RFC 9421 Signature-Input is always ignored. The request is
// not modified and Body is not read. If the selected sources contain no Cavage
// signature candidate, ParseRequest fails with [ErrMissingSignature]; if they
// contain more than one, it fails with [ErrSignatureSourceConflict].
//
// ParseRequest enforces every policy in [CavageVerificationOptions] that does not
// depend on the trusted key: parameter syntax, the algorithm label, required
// signed fields, and the created, expires, and Date time limits. [CavageVerifier.Verify]
// and [CavageVerifier.VerifyHMAC] then check the key binding and the
// cryptographic signature.
//
// Signed fields are read as net/http stores a received request: host from
// req.Host, transfer-encoding from req.TransferEncoding, trailer from the keys
// of req.Trailer when net/http has moved the declaration there, and every other
// field, including content-length, from Header using canonical map keys.
//
// (request-target) uses the lower-case req.Method and req.RequestURI. A target
// that starts with "/" or equals "*" is used as received. An absolute-form target
// uses the escaped path and raw query of a non-opaque req.URL, using "/" for an
// empty path and keeping a "?" required by ForceQuery. An HTTP or HTTPS OPTIONS
// target with no path or query uses "*". When (request-target) is signed, an
// empty method or RequestURI, a CONNECT request, or a target that defines no
// path, such as the authority form or an opaque URL, causes [ErrInvalidHTTPMessage].
// To verify a request built with [http.NewRequest] instead of received by a
// server, set RequestURI to req.URL.RequestURI() first.
//
// If trailer is signed, call ParseRequest before Body reaches EOF because
// net/http then merges received fields and the declaration cannot be recovered.
func (v *CavageVerifier) ParseRequest(req *http.Request) (*CavageSignature, error) {
	if err := v.validateConstructed(); err != nil {
		return nil, wrapError(err)
	}
	if req == nil {
		return nil, wrapError(fmt.Errorf("%w: request is nil", ErrInvalidHTTPMessage))
	}
	candidate, err := requestCavageSignatureCandidate(req.Header, v.config.requestSource)
	if err != nil {
		return nil, wrapError(err)
	}
	if candidate.placement == 0 {
		return nil, wrapError(ErrMissingSignature)
	}
	snapshot := cavageMessageSnapshot{
		isRequest: true,
		host:      req.Host,
		method:    req.Method,
		resolveRequestTarget: func() (string, error) {
			return receivedCavageRequestTarget(req)
		},
		header:           req.Header,
		transferEncoding: req.TransferEncoding,
		trailer:          req.Trailer,
	}
	signature, err := v.parse(candidate, snapshot)
	return signature, wrapError(err)
}

// ParseResponse parses the response Signature field and returns an immutable
// snapshot. Authorization and Signature-Input are ignored, the response is not
// modified, and Body is not read. Missing and conflicting signatures and the
// verifier policies are handled as described for [CavageVerifier.ParseRequest].
// Signed fields, including host, are read from Header, except transfer-encoding
// and trailer, which are read from res.TransferEncoding and res.Trailer as
// described for [CavageVerifier.ParseRequest]. (request-target) is resolved from
// res.Request by the rules described for [CavageSigner.SignResponse].
// If res.Request is nil and (request-target) is signed, ParseResponse fails with
// [ErrInvalidHTTPMessage].
//
// If trailer is signed, call ParseResponse before Body reaches EOF because
// net/http then merges received fields and the declaration cannot be recovered.
func (v *CavageVerifier) ParseResponse(res *http.Response) (*CavageSignature, error) {
	if err := v.validateConstructed(); err != nil {
		return nil, wrapError(err)
	}
	if res == nil {
		return nil, wrapError(fmt.Errorf("%w: response is nil", ErrInvalidHTTPMessage))
	}
	candidate, err := cavageSignatureHeaderCandidate(res.Header)
	if err != nil {
		return nil, wrapError(err)
	}
	if candidate.placement == 0 {
		return nil, wrapError(ErrMissingSignature)
	}
	snapshot := cavageMessageSnapshot{
		header:           res.Header,
		transferEncoding: res.TransferEncoding,
		trailer:          res.Trailer,
	}
	if res.Request != nil {
		snapshot.method = associatedRequestMethod(res.Request)
		snapshot.resolveRequestTarget = func() (string, error) {
			return associatedCavageRequestTarget(res.Request)
		}
	}
	signature, err := v.parse(candidate, snapshot)
	return signature, wrapError(err)
}

// Verify checks signature with an asymmetric trusted key. The KeyID and
// algorithm label of signature are attacker-controlled; resolve KeyID to trusted
// metadata before calling Verify. Verify fails with [ErrInvalidHTTPMessage] if
// signature was not parsed by v, [ErrKeyIDMismatch] if key.Metadata.KeyID
// differs from the received keyId, [ErrInvalidSignatureAlgorithm] if
// key.Metadata.Algorithm is not allowed by [CavageVerificationOptions.AllowedAlgorithms],
// [ErrAlgorithmMismatch] if a received algorithm label identifies a different
// algorithm, and [ErrVerification] if the signature does not match. Errors in
// key itself are described for [VerificationKey].
//
// A received hs2019 label identifies any of the four strict algorithms in
// [CavageVerificationOptions], and also [AlgorithmRSAPKCS1v15SHA256] when
// [CavageVerificationCompatibility.AllowHS2019WithSHA256] is set. A deprecated
// label identifies its SHA-256 algorithm, an extension label identifies the
// [AlgorithmID] mapped by [CavageVerificationCompatibility.ExtensionAlgorithms],
// and an omitted algorithm parameter accepts any allowed algorithm.
//
// Verify does not read the original HTTP message, does not compare a Digest
// field with a body, and does not call the verifier's clock.
func (v *CavageVerifier) Verify(signature *CavageSignature, key VerificationKey) error {
	if err := v.validateSignature(signature); err != nil {
		return wrapError(err)
	}
	algorithm, err := validateVerificationMetadata(signature, key.Metadata)
	if err != nil {
		return wrapError(err)
	}
	publicKey := normalizeEd25519PublicKey(key.PublicKey)
	if isMissingPublicKey(publicKey) {
		return wrapError(ErrMissingPublicKey)
	}
	if algorithm.keyKind == algorithmKeyHMAC {
		return wrapError(fmt.Errorf("%w: HMAC AlgorithmID must be used with VerifyHMAC", ErrAlgorithmMismatch))
	}
	if err := validateVerificationPublicKey(publicKey, algorithm.keyKind); err != nil {
		return wrapError(err)
	}
	if err := v.validateCavageTrustedAlgorithm(signature, key.Metadata.Algorithm); err != nil {
		return wrapError(err)
	}
	return wrapError(verifyAsymmetric(publicKey, algorithm, signature.signature, signature.signingString))
}

// VerifyHMAC is like [CavageVerifier.Verify] but checks signature with trusted
// HMAC metadata and a shared secret. Errors in key itself are described for
// [HMACVerificationKey].
func (v *CavageVerifier) VerifyHMAC(signature *CavageSignature, key HMACVerificationKey) error {
	if err := v.validateSignature(signature); err != nil {
		return wrapError(err)
	}
	algorithm, err := validateVerificationMetadata(signature, key.Metadata)
	if err != nil {
		return wrapError(err)
	}
	if len(key.Secret) == 0 {
		return wrapError(ErrMissingSharedSecret)
	}
	if algorithm.keyKind != algorithmKeyHMAC {
		return wrapError(fmt.Errorf("%w: asymmetric AlgorithmID must be used with Verify", ErrAlgorithmMismatch))
	}
	if err := v.validateCavageTrustedAlgorithm(signature, key.Metadata.Algorithm); err != nil {
		return wrapError(err)
	}
	return wrapError(verifyHMAC(key.Secret, signature.signature, signature.signingString, algorithm.hash))
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
// Fractional seconds are preserved.
func (s *CavageSignature) Expires() (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	return s.expires, s.expiresPresent
}

// SignedHeaders returns a copy of the effective signed-header list, with names
// normalized to lower case. If the headers parameter was omitted, the returned
// list contains only (created).
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
		if _, ok := config.allowedAlgorithms[id]; !ok {
			return cavageVerificationConfig{}, fmt.Errorf("%w: AllowedLegacyAlgorithms contains AlgorithmID %d that is not allowed", ErrInvalidVerificationOptions, id)
		}
		config.allowedLegacyAlgorithms[id] = struct{}{}
	}
	config.extensionAlgorithms = make(map[string]AlgorithmID, len(compatibility.ExtensionAlgorithms))
	for label, id := range compatibility.ExtensionAlgorithms {
		if err := validateCavageExtensionAlgorithm(label, id); err != nil {
			return cavageVerificationConfig{}, fmt.Errorf("%w: ExtensionAlgorithms label %q: %v", ErrInvalidVerificationOptions, label, err)
		}
		if _, ok := config.allowedAlgorithms[id]; !ok {
			return cavageVerificationConfig{}, fmt.Errorf("%w: ExtensionAlgorithms label %q maps to AlgorithmID %d that is not allowed", ErrInvalidVerificationOptions, label, id)
		}
		config.extensionAlgorithms[label] = id
	}
	if compatibility.AllowHS2019WithSHA256 {
		if _, ok := config.allowedAlgorithms[AlgorithmRSAPKCS1v15SHA256]; !ok {
			return cavageVerificationConfig{}, fmt.Errorf("%w: AllowHS2019WithSHA256 requires AlgorithmRSAPKCS1v15SHA256 to be allowed", ErrInvalidVerificationOptions)
		}
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
	if signature == nil || signature.origin != v.identity {
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
	// parseCavageParams validates the encoding but keeps the text form.
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
	if err := v.checkCavageParameterPolicy(params, headers); err != nil {
		return nil, err
	}
	parsedDate, err := v.parseCavageDateForPolicy(message.header)
	if err != nil {
		return nil, err
	}
	ownedHeaders, err := snapshotCavageSignedFields(message, headers)
	if err != nil {
		return nil, err
	}
	requestTarget, err := resolveCavageRequestTarget(message, headers)
	if err != nil {
		return nil, err
	}

	buf, err := generateCavageSigningString(
		headers,
		message.method,
		requestTarget,
		ownedHeaders,
		params.Created,
		params.Expires,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create signing string: %v", ErrInvalidHTTPMessage, err)
	}

	// Check time last, so that Now is called only after every check that does
	// not depend on the current time has passed.
	if err := v.checkCavageTimePolicy(params, created, expires, parsedDate); err != nil {
		return nil, err
	}

	return &CavageSignature{
		origin:           v.identity,
		keyID:            params.KeyID,
		placement:        candidate.placement,
		algorithmLabel:   params.Algorithm,
		algorithmPresent: params.AlgorithmPresent,
		created:          created,
		createdPresent:   params.CreatedPresent,
		expires:          expires,
		expiresPresent:   params.ExpiresPresent,
		signedHeaders:    headers,
		headersExplicit:  params.HeadersPresent,
		signature:        decodedSignature,
		signingString:    append([]byte(nil), buf.Bytes()...),
	}, nil
}

func (v *CavageVerifier) checkCavageParameterPolicy(params *cavageParams, headers []string) error {
	if v.config.requireExplicitHeaders && !params.HeadersPresent {
		return fmt.Errorf("%w: headers parameter is required", ErrRequiredHeaderMissing)
	}
	if err := requireCavageHeaders(headers, v.config.requiredHeaders); err != nil {
		return err
	}
	if v.config.maxSignatureAge > 0 && !slices.Contains(headers, CavageCreated) {
		return fmt.Errorf("%w: MaxSignatureAge requires %s", ErrRequiredHeaderMissing, CavageCreated)
	}
	if v.config.maxDateAge > 0 && !slices.Contains(headers, "date") {
		return fmt.Errorf("%w: MaxDateAge requires date", ErrRequiredHeaderMissing)
	}

	if slices.Contains(headers, CavageCreated) && !params.CreatedPresent {
		return fmt.Errorf("%w: %s requires a created parameter", ErrInvalidCreationTime, CavageCreated)
	}
	if slices.Contains(headers, CavageExpires) && !params.ExpiresPresent {
		return fmt.Errorf("%w: %s requires an expires parameter", ErrInvalidExpirationTime, CavageExpires)
	}

	return v.validateCavageAlgorithmLabelPolicy(params, headers)
}

func (v *CavageVerifier) parseCavageDateForPolicy(header http.Header) (time.Time, error) {
	if v.config.maxDateAge == 0 {
		return time.Time{}, nil
	}
	dateValues := header.Values("Date")
	if len(dateValues) != 1 {
		return time.Time{}, fmt.Errorf("%w: MaxDateAge requires exactly one Date value, got %d", ErrInvalidDate, len(dateValues))
	}
	parsedDate, err := http.ParseTime(dateValues[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrInvalidDate, err)
	}
	return parsedDate, nil
}

func resolveCavageRequestTarget(message cavageMessageSnapshot, headers []string) (string, error) {
	if !slices.Contains(headers, CavageRequestTarget) {
		return "", nil
	}
	if message.method == "" {
		return "", fmt.Errorf("%w: method is required by %s", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	var requestTarget string
	if message.resolveRequestTarget != nil {
		var err error
		requestTarget, err = message.resolveRequestTarget()
		if err != nil {
			return "", err
		}
	}
	if requestTarget == "" {
		return "", fmt.Errorf("%w: request-target is required by %s", ErrInvalidHTTPMessage, CavageRequestTarget)
	}
	return requestTarget, nil
}

func (v *CavageVerifier) checkCavageTimePolicy(params *cavageParams, created, expires, date time.Time) error {
	if !params.CreatedPresent && !params.ExpiresPresent && v.config.maxDateAge == 0 {
		return nil
	}
	now := v.currentTime()
	if params.CreatedPresent {
		if timeAfterDuration(created, now, v.config.allowedCreatedFutureSkew) {
			return fmt.Errorf("%w: created is after the permitted future boundary", ErrInvalidCreationTime)
		}
		if v.config.maxSignatureAge > 0 && timeAfterDuration(now, created, v.config.maxSignatureAge) {
			return fmt.Errorf("%w: signature age exceeds MaxSignatureAge", ErrInvalidCreationTime)
		}
	}
	if params.ExpiresPresent && timeAfterDuration(now, expires, v.config.allowedExpiredSkew) {
		return fmt.Errorf("%w: expires is before the permitted past boundary", ErrSignatureExpired)
	}
	if v.config.maxDateAge > 0 && (timeAfterDuration(date, now, v.config.maxDateAge) || timeAfterDuration(now, date, v.config.maxDateAge)) {
		return fmt.Errorf("%w: Date differs from current time by more than MaxDateAge", ErrInvalidDate)
	}
	return nil
}

func effectiveCavageSignedHeaders(params *cavageParams) ([]string, error) {
	configured := params.Headers
	if !params.HeadersPresent {
		configured = []string{CavageCreated}
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

func (v *CavageVerifier) validateCavageAlgorithmLabelPolicy(params *cavageParams, headers []string) error {
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
			if v.hs2019Permits(id) {
				return nil
			}
		}
		return fmt.Errorf("%w: hs2019 has no permitted trusted algorithm", ErrInvalidSignatureAlgorithm)
	default:
		if legacyID, ok := legacyCavageAlgorithmID(label); ok {
			if _, ok := v.config.allowedLegacyAlgorithms[legacyID]; !ok {
				return fmt.Errorf("%w: deprecated algorithm %q is not enabled", ErrInvalidSignatureAlgorithm, label)
			}
		} else {
			_, ok := v.config.extensionAlgorithms[label]
			if !ok {
				return fmt.Errorf("%w: unregistered algorithm label %q", ErrInvalidSignatureAlgorithm, label)
			}
		}
	}
	return validateCavagePseudoHeadersForAlgorithmLabel(label, headers)
}

func (v *CavageVerifier) hs2019Permits(id AlgorithmID) bool {
	return isStrictCavageAlgorithm(id) || id == AlgorithmRSAPKCS1v15SHA256 && v.config.allowHS2019WithSHA256
}

// net/http's HTTP/1 reader removes Host from a received request's Header and
// uses Request.Host instead. It removes Transfer-Encoding from received
// headers, records chunked encoding in TransferEncoding, and ignores
// Transfer-Encoding in HTTP/1.0. It moves the Trailer declaration into the
// Trailer keys only for chunked messages; otherwise Trailer stays in Header.
// Its HTTP/2 support moves the declaration into the Trailer keys without
// chunked encoding.
func snapshotCavageSignedFields(message cavageMessageSnapshot, signedHeaders []string) (http.Header, error) {
	owned := make(http.Header)
	for _, name := range signedHeaders {
		switch name {
		case CavageRequestTarget, CavageCreated, CavageExpires:
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

		canonicalName := http.CanonicalHeaderKey(name)
		values, ok := message.header[canonicalName]
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrSignedHeaderMissing, name)
		}
		owned[canonicalName] = append([]string(nil), values...)
	}
	return owned, nil
}

// After Body reaches EOF, net/http merges the received trailer fields into
// Trailer, so its keys no longer show only the declaration.
func cavageTrailerValuesReceived(trailer http.Header) bool {
	for _, values := range trailer {
		if values != nil {
			return true
		}
	}
	return false
}

// The map keys do not keep the original order. Request.Write and Response.Write
// send the declaration as sorted canonical keys joined by ",", so that form is
// reconstructed here.
func cavageTrailerDeclaration(trailer http.Header) string {
	keys := make([]string, 0, len(trailer))
	for key := range trailer {
		keys = append(keys, http.CanonicalHeaderKey(key))
	}
	slices.Sort(keys)
	return strings.Join(keys, ",")
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

func (v *CavageVerifier) validateCavageTrustedAlgorithm(signature *CavageSignature, id AlgorithmID) error {
	if !v.isAlgorithmAllowed(id) {
		return fmt.Errorf("%w: trusted AlgorithmID %d is not permitted", ErrInvalidSignatureAlgorithm, id)
	}
	if !signature.algorithmPresent {
		return nil
	}
	label := signature.algorithmLabel
	if label == hs2019 {
		if v.hs2019Permits(id) {
			return nil
		}
		return fmt.Errorf("%w: algorithm %q does not identify trusted AlgorithmID %d", ErrAlgorithmMismatch, label, id)
	}
	if legacyID, ok := legacyCavageAlgorithmID(label); ok {
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
