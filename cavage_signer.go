package sigre

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Default header lists used when CavageSignOptions.Headers is empty.
var (
	// CavageLegacyDefaultHeaders applies to rsa, hmac, and ecdsa algorithms.
	CavageLegacyDefaultHeaders = []string{RequestTarget, "date", "digest", "host"}
	// CavageNonLegacyDefaultHeaders applies to non-legacy algorithms (ed25519, hs2019).
	// Uses (created) instead of date per draft-cavage-http-signatures-12 Section 2.3.
	CavageNonLegacyDefaultHeaders = []string{RequestTarget, Created, "digest", "host"}
	// CavageDefaultResponseHeaders is the default list for response signing.
	CavageDefaultResponseHeaders = []string{"date", "digest"}
)

// CavageSignOptions configures how a Cavage HTTP signature is created.
type CavageSignOptions struct {
	// Headers lists the header names (and pseudo-headers such as "(request-target)")
	// to include in the signature. When empty, a default list is chosen based on the algorithm.
	Headers []string
	// HashAlgorithm is the hash function for RSA, ECDSA, and HMAC. Ignored for Ed25519.
	HashAlgorithm crypto.Hash
	// Expiry is the signature lifetime in seconds from creation.
	// Uses defaultExpirySeconds when zero or negative.
	Expiry int64
	// UseHS2019 emits algorithm="hs2019" in the signature parameters instead of the
	// key-type specific identifier (e.g. "rsa-sha256"), and lifts the restriction on
	// (created)/(expires) pseudo-headers for rsa/hmac/ecdsa keys.
	UseHS2019 bool
	// SignatureHeader is the header name where the signature is written.
	// Use the [Signature] or [Authorization] constant. Defaults to [Signature] when empty.
	SignatureHeader string
}

// CavageSigner creates HTTP signatures following draft-cavage-http-signatures-12.
type CavageSigner struct {
	// Now overrides the time source used for (created) and (expires). Uses time.Now when nil.
	Now func() time.Time
}

// NewCavageSigner returns a new [CavageSigner].
func NewCavageSigner() *CavageSigner {
	return &CavageSigner{
		Now: time.Now,
	}
}

// SignRequest signs req using privateKey and appends the Cavage signature header.
// keyId identifies the signing key in the signature parameters.
func (s *CavageSigner) SignRequest(req *http.Request, privateKey crypto.PrivateKey, keyId string, opts *CavageSignOptions) error {
	if privateKey == nil {
		return ErrMissingPrivateKey
	}

	expiry := opts.Expiry
	if expiry <= 0 {
		expiry = defaultExpirySeconds
	}

	isLegacy := !opts.UseHS2019 && keyTypeFromPrivateKey(privateKey) != "ed25519"
	headers := s.resolveHeaders(opts.Headers, req.Header, isLegacy)

	effectiveKeyType := keyTypeFromPrivateKey(privateKey)
	if opts.UseHS2019 {
		effectiveKeyType = hs2019
	}
	if err := validateCreatedExpiresWithAlgorithm(headers, effectiveKeyType); err != nil {
		return err
	}

	buf, created, expires, err := s.buildSigningString(req.Host, req.Method, req.URL, req.Header, headers, expiry, opts)
	if err != nil {
		return fmt.Errorf("failed to create sign string: %w", err)
	}

	sig, keyType, err := s.signBytes(privateKey, opts, buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	algoStr, err := s.algorithmString(opts.UseHS2019, keyType, opts.HashAlgorithm)
	if err != nil {
		return err
	}

	s.setSignatureHeader(req.Header, opts.SignatureHeader, cavageParams{
		KeyId:     keyId,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Algorithm: algoStr,
		Created:   created,
		Expires:   expires,
		Headers:   headers,
	})
	return nil
}

// SignRequestWithHMAC signs req using a shared HMAC secret and appends the Cavage signature header.
func (s *CavageSigner) SignRequestWithHMAC(req *http.Request, secret []byte, keyId string, opts *CavageSignOptions) error {
	if secret == nil {
		return ErrMissingPrivateKey
	}

	expiry := opts.Expiry
	if expiry <= 0 {
		expiry = defaultExpirySeconds
	}

	isLegacy := !opts.UseHS2019
	headers := s.resolveHeaders(opts.Headers, req.Header, isLegacy)

	hmacKeyType := "hmac"
	if opts.UseHS2019 {
		hmacKeyType = hs2019
	}
	if err := validateCreatedExpiresWithAlgorithm(headers, hmacKeyType); err != nil {
		return err
	}

	buf, created, expires, err := s.buildSigningString(req.Host, req.Method, req.URL, req.Header, headers, expiry, opts)
	if err != nil {
		return fmt.Errorf("failed to create sign string: %w", err)
	}

	sig, err := s.signHMAC(secret, buf.Bytes(), opts.HashAlgorithm)
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	algoStr, err := s.hmacAlgorithmString(opts.UseHS2019, opts.HashAlgorithm)
	if err != nil {
		return err
	}

	s.setSignatureHeader(req.Header, opts.SignatureHeader, cavageParams{
		KeyId:     keyId,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Algorithm: algoStr,
		Created:   created,
		Expires:   expires,
		Headers:   headers,
	})
	return nil
}

// SignResponse signs res using privateKey and appends the Cavage signature header.
func (s *CavageSigner) SignResponse(res *http.Response, privateKey crypto.PrivateKey, keyId string, opts *CavageSignOptions) error {
	if privateKey == nil {
		return ErrMissingPrivateKey
	}

	expiry := opts.Expiry
	if expiry <= 0 {
		expiry = defaultExpirySeconds
	}

	isLegacy := !opts.UseHS2019 && keyTypeFromPrivateKey(privateKey) != "ed25519"
	headers := s.resolveHeaders(opts.Headers, res.Header, isLegacy)

	effectiveKeyType := keyTypeFromPrivateKey(privateKey)
	if opts.UseHS2019 {
		effectiveKeyType = hs2019
	}
	if err := validateCreatedExpiresWithAlgorithm(headers, effectiveKeyType); err != nil {
		return err
	}

	var reqHost, reqMethod string
	var reqURL *url.URL
	if res.Request != nil {
		reqHost = res.Request.Host
		reqMethod = res.Request.Method
		reqURL = res.Request.URL
	}

	buf, created, expires, err := s.buildSigningString(reqHost, reqMethod, reqURL, res.Header, headers, expiry, opts)
	if err != nil {
		return fmt.Errorf("failed to create sign string for response: %w", err)
	}

	sig, keyType, err := s.signBytes(privateKey, opts, buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create signature for response: %w", err)
	}

	algoStr, err := s.algorithmString(opts.UseHS2019, keyType, opts.HashAlgorithm)
	if err != nil {
		return err
	}

	s.setSignatureHeader(res.Header, opts.SignatureHeader, cavageParams{
		KeyId:     keyId,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Algorithm: algoStr,
		Created:   created,
		Expires:   expires,
		Headers:   headers,
	})
	return nil
}

// SignResponseWithHMAC signs res using a shared HMAC secret and appends the Cavage signature header.
func (s *CavageSigner) SignResponseWithHMAC(res *http.Response, secret []byte, keyId string, opts *CavageSignOptions) error {
	if secret == nil {
		return ErrMissingPrivateKey
	}

	expiry := opts.Expiry
	if expiry <= 0 {
		expiry = defaultExpirySeconds
	}

	isLegacy := !opts.UseHS2019
	headers := s.resolveHeaders(opts.Headers, res.Header, isLegacy)

	hmacKeyType := "hmac"
	if opts.UseHS2019 {
		hmacKeyType = hs2019
	}
	if err := validateCreatedExpiresWithAlgorithm(headers, hmacKeyType); err != nil {
		return err
	}

	var reqHost, reqMethod string
	var reqURL *url.URL
	if res.Request != nil {
		reqHost = res.Request.Host
		reqMethod = res.Request.Method
		reqURL = res.Request.URL
	}

	if opts.HashAlgorithm == 0 {
		return fmt.Errorf("hash algorithm must be specified for HMAC")
	}

	buf, created, expires, err := s.buildSigningString(reqHost, reqMethod, reqURL, res.Header, headers, expiry, opts)
	if err != nil {
		return fmt.Errorf("failed to create sign string for response: %w", err)
	}

	sig, err := s.signHMAC(secret, buf.Bytes(), opts.HashAlgorithm)
	if err != nil {
		return fmt.Errorf("failed to create signature for response: %w", err)
	}

	algoStr, err := s.hmacAlgorithmString(opts.UseHS2019, opts.HashAlgorithm)
	if err != nil {
		return err
	}

	s.setSignatureHeader(res.Header, opts.SignatureHeader, cavageParams{
		KeyId:     keyId,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Algorithm: algoStr,
		Created:   created,
		Expires:   expires,
		Headers:   headers,
	})
	return nil
}

// resolveHeaders returns opts.Headers when non-empty, otherwise picks a default list
// based on whether the algorithm is considered legacy.
func (s *CavageSigner) resolveHeaders(optsHeaders []string, h http.Header, isLegacy bool) []string {
	if len(optsHeaders) > 0 {
		return normalizeHeaders(optsHeaders)
	}

	defaults := CavageNonLegacyDefaultHeaders
	if isLegacy {
		defaults = CavageLegacyDefaultHeaders
	}

	out := make([]string, 0, len(defaults))
	for _, name := range defaults {
		switch name {
		case RequestTarget, Created, Expires, "host":
			out = append(out, name)
		default:
			if _, ok := h[http.CanonicalHeaderKey(name)]; ok {
				out = append(out, name)
			}
		}
	}
	return out
}

func normalizeHeaders(headers []string) []string {
	out := make([]string, len(headers))
	for i, h := range headers {
		out[i] = strings.ToLower(h)
	}
	return out
}

func (s *CavageSigner) buildSigningString(
	host, method string,
	reqURL *url.URL,
	header http.Header,
	headers []string,
	expiry int64,
	opts *CavageSignOptions,
) (buf *bytes.Buffer, created, expires string, err error) {
	var now int64
	if s.Now == nil {
		now = time.Now().UTC().Unix()
	} else {
		now = s.Now().Unix()
	}

	if slices.Contains(headers, Created) {
		created = strconv.FormatInt(now, 10)
	}
	if slices.Contains(headers, Expires) {
		expires = strconv.FormatInt(now+expiry, 10)
	}

	path := ""
	query := ""
	if reqURL != nil {
		path = reqURL.Path
		if path == "" {
			path = "/"
		}
		query = reqURL.RawQuery
	}

	buf, err = generateSignatureStringBuffer(headers, host, strings.ToLower(method), path, query, header, created, expires)
	return
}

func (s *CavageSigner) algorithmString(useHS2019 bool, keyType string, hash crypto.Hash) (string, error) {
	if useHS2019 {
		return hs2019, nil
	}
	if keyType == "ed25519" {
		return "ed25519", nil
	}
	hashName, err := hashName(hash)
	if err != nil {
		return "", fmt.Errorf("failed to get hash name for algorithm: %w", err)
	}
	return keyType + "-" + hashName, nil
}

func (s *CavageSigner) hmacAlgorithmString(useHS2019 bool, hash crypto.Hash) (string, error) {
	if useHS2019 {
		return hs2019, nil
	}
	name, err := hashName(hash)
	if err != nil {
		return "", fmt.Errorf("HMAC requires a valid hash algorithm: %w", err)
	}
	return "hmac-" + name, nil
}

func (s *CavageSigner) setSignatureHeader(h http.Header, signatureHeader string, p cavageParams) {
	if signatureHeader == "" {
		signatureHeader = Signature
	}
	if http.CanonicalHeaderKey(signatureHeader) == Authorization {
		h.Set(Authorization, "Signature "+p.String())
	} else {
		h.Set(signatureHeader, p.String())
	}
}

func (s *CavageSigner) signBytes(privateKey crypto.PrivateKey, opts *CavageSignOptions, data []byte) ([]byte, string, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if opts.HashAlgorithm == 0 {
			return nil, "", fmt.Errorf("hash algorithm must be specified for RSA")
		}
		return signRSA(key, data, opts.HashAlgorithm)
	case *ecdsa.PrivateKey:
		if opts.HashAlgorithm == 0 {
			return nil, "", fmt.Errorf("hash algorithm must be specified for ECDSA")
		}
		return signECDSA(key, data, opts.HashAlgorithm)
	case ed25519.PrivateKey:
		return signEd25519(key, data)
	case *ed25519.PrivateKey:
		return signEd25519(*key, data)
	default:
		return nil, "", fmt.Errorf("unknown or unsupported private key type: %T", privateKey)
	}
}

func (s *CavageSigner) signHMAC(secret, data []byte, hash crypto.Hash) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrMissingSharedSecret
	}
	if !hash.Available() {
		return nil, ErrUnsupportedHashAlgorithm
	}
	mac := hmac.New(hash.New, secret)
	if _, err := mac.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write to HMAC: %w", err)
	}
	return mac.Sum(nil), nil
}

func signRSA(key *rsa.PrivateKey, data []byte, hash crypto.Hash) ([]byte, string, error) {
	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, "", fmt.Errorf("failed to hash data for RSA: %w", err)
	}
	b, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
	if err != nil {
		return nil, "", fmt.Errorf("RSA signing failed: %w", err)
	}
	return b, "rsa", nil
}

func signECDSA(key *ecdsa.PrivateKey, data []byte, hash crypto.Hash) ([]byte, string, error) {
	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, "", fmt.Errorf("failed to hash data for ECDSA: %w", err)
	}
	b, err := ecdsa.SignASN1(rand.Reader, key, h.Sum(nil))
	if err != nil {
		return nil, "", fmt.Errorf("ECDSA signing failed: %w", err)
	}
	return b, "ecdsa", nil
}

func signEd25519(key ed25519.PrivateKey, data []byte) ([]byte, string, error) {
	return ed25519.Sign(key, data), "ed25519", nil
}

func keyTypeFromPrivateKey(privateKey crypto.PrivateKey) string {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return "rsa"
	case *ecdsa.PrivateKey:
		return "ecdsa"
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return "ed25519"
	default:
		return ""
	}
}

func hashName(hash crypto.Hash) (string, error) {
	switch hash {
	case crypto.SHA256:
		return "sha256", nil
	case crypto.SHA512:
		return "sha512", nil
	default:
		if hash == 0 {
			return "", fmt.Errorf("hash algorithm not specified or unsupported")
		}
		return "", fmt.Errorf("unsupported hash type: %s", hash.String())
	}
}
