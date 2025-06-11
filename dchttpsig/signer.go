package dchttpsig

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

	"github.com/MitarashiDango/sigre/common"
)

var (
	DefaultRequestHeaderNames  = []string{RequestTarget, "date", "digest", "host"}
	DefaultResponseHeaderNames = []string{"date", "digest"}
)

type SignOptions = common.SignOptions

type signer struct{}

func NewSigner() *signer {
	return &signer{}
}

func (s *signer) SignRequest(req *http.Request, signOptions *SignOptions) error {
	if signOptions == nil {
		return fmt.Errorf("signOptions is nil")
	}

	if signOptions.PrivateKey == nil && signOptions.SharedSecret == nil {
		return ErrMissingPrivateKey
	}

	if signOptions.Expiry <= 0 {
		signOptions.Expiry = DefaultExpiryTime
	}

	userSignTargetNames := signOptions.SignTargetHeaders
	if len(userSignTargetNames) == 0 {
		userSignTargetNames = make([]string, 0, len(DefaultRequestHeaderNames))
		for _, headerName := range DefaultRequestHeaderNames {
			switch {
			case headerName == RequestTarget || headerName == Created || headerName == Expires || headerName == "host":
				userSignTargetNames = append(userSignTargetNames, headerName)
				break
			default:
				if _, ok := req.Header[http.CanonicalHeaderKey(headerName)]; ok {
					userSignTargetNames = append(userSignTargetNames, headerName)
				}
			}
		}
	}

	// Normalize userSignTargetNames to lowercase
	normalizedSignTargetNames := make([]string, 0, len(userSignTargetNames))
	for _, name := range userSignTargetNames {
		normalizedSignTargetNames = append(normalizedSignTargetNames, strings.ToLower(name))
	}

	hashForAlgo := signOptions.HashAlgorithm

	signTargetBuf, created, expires, err := s.createSignString(req.Host, req.Method, req.URL, req.Header, normalizedSignTargetNames, signOptions)
	if err != nil {
		return fmt.Errorf("failed to create sign string: %w", err)
	}

	signedTarget, keyType, err := createSignature(signOptions, signTargetBuf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	var algorithmString string
	if keyType == "ed25519" {
		algorithmString = "ed25519"
	} else if keyType == "hmac" {
		hashName, errHmacHash := s.getHashName(hashForAlgo)
		if errHmacHash != nil {
			return fmt.Errorf("HMAC requires a valid hash algorithm: %w", errHmacHash)
		}
		algorithmString = keyType + "-" + hashName
	} else {
		hashName, errKeyHash := s.getHashName(hashForAlgo)
		if errKeyHash != nil {
			return fmt.Errorf("failed to get hash name for algorithm: %w", errKeyHash)
		}
		algorithmString = keyType + "-" + hashName
	}

	sp := signaturesParameters{
		KeyId:             signOptions.KeyId,
		Signature:         base64.StdEncoding.EncodeToString(signedTarget),
		Algorithm:         algorithmString,
		Created:           created,
		Expires:           expires,
		SignTargetHeaders: normalizedSignTargetNames,
	}

	signatureHeader := common.Signature
	if signOptions.SignatureHeader != "" {
		signatureHeader = signOptions.SignatureHeader
	}

	if http.CanonicalHeaderKey(signatureHeader) == common.Authorization {
		req.Header.Set(common.Authorization, "Signature "+sp.String())
	} else {
		req.Header.Set(signatureHeader, sp.String())
	}

	return nil
}

func (s *signer) SignResponse(res *http.Response, signOptions *SignOptions) error {
	if signOptions == nil {
		return fmt.Errorf("signOptions is nil")
	}

	if signOptions.PrivateKey == nil && signOptions.SharedSecret == nil {
		return ErrMissingPrivateKey
	}

	if signOptions.Expiry <= 0 {
		signOptions.Expiry = DefaultExpiryTime
	}

	userSignTargetNames := signOptions.SignTargetHeaders
	if len(userSignTargetNames) == 0 {
		userSignTargetNames = make([]string, 0, len(DefaultRequestHeaderNames))
		for _, headerName := range DefaultResponseHeaderNames {
			switch {
			case headerName == RequestTarget || headerName == Created || headerName == Expires || headerName == "host":
				userSignTargetNames = append(userSignTargetNames, headerName)
				break
			default:
				if _, ok := res.Header[http.CanonicalHeaderKey(headerName)]; ok {
					userSignTargetNames = append(userSignTargetNames, headerName)
				}
			}
		}
	}

	// Normalize userSignTargetNames to lowercase
	normalizedSignTargetNames := make([]string, 0, len(userSignTargetNames))
	for _, name := range userSignTargetNames {
		normalizedSignTargetNames = append(normalizedSignTargetNames, strings.ToLower(name))
	}

	hashForAlgo := signOptions.HashAlgorithm

	var reqHost, reqMethodHttp string
	var reqURLVal *url.URL
	if res.Request != nil {
		reqHost = res.Request.Host
		reqMethodHttp = res.Request.Method
		reqURLVal = res.Request.URL
	}

	signTargetBuf, created, expires, err := s.createSignString(reqHost, reqMethodHttp, reqURLVal, res.Header, normalizedSignTargetNames, signOptions)
	if err != nil {
		return fmt.Errorf("failed to create sign string for response: %w", err)
	}

	signedTarget, keyType, err := createSignature(signOptions, signTargetBuf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create signature for response: %w", err)
	}

	var algorithmString string
	if keyType == "ed25519" {
		algorithmString = "ed25519"
	} else if keyType == "hmac" {
		hashName, errHmacHash := s.getHashName(hashForAlgo)
		if errHmacHash != nil {
			return fmt.Errorf("HMAC requires a valid hash algorithm for response: %w", errHmacHash)
		}
		algorithmString = keyType + "-" + hashName
	} else {
		hashName, errKeyHash := s.getHashName(hashForAlgo)
		if errKeyHash != nil {
			return fmt.Errorf("failed to get hash name for algorithm for response: %w", errKeyHash)
		}
		algorithmString = keyType + "-" + hashName
	}

	sp := signaturesParameters{
		KeyId:             signOptions.KeyId,
		Signature:         base64.StdEncoding.EncodeToString(signedTarget),
		Algorithm:         algorithmString,
		Created:           created,
		Expires:           expires,
		SignTargetHeaders: normalizedSignTargetNames,
	}

	signatureHeader := common.Signature
	if signOptions.SignatureHeader != "" {
		signatureHeader = signOptions.SignatureHeader
	}

	if http.CanonicalHeaderKey(signatureHeader) == common.Authorization {
		res.Header.Set(common.Authorization, "Signature "+sp.String())
	} else {
		res.Header.Set(signatureHeader, sp.String())
	}

	return nil
}

func (s *signer) createSignString(host string, methodFromReq string, requestURL *url.URL, header http.Header, signTargetNames []string, signOptions *SignOptions) (buf *bytes.Buffer, createdString, expiresString string, err error) {
	var startedAt int64
	if signOptions.NowFunc == nil {
		startedAt = time.Now().UTC().Unix()
	} else {
		startedAt = signOptions.NowFunc().Unix()
	}

	// (created) and (expires) are included in the string if they are in signTargetNames
	if slices.Contains(signTargetNames, Created) {
		createdString = strconv.FormatInt(startedAt, 10)
	}

	if slices.Contains(signTargetNames, Expires) {
		expiresString = strconv.FormatInt(startedAt+signOptions.Expiry, 10)
	}

	var reqPath, reqQuery string
	methodLowercase := strings.ToLower(methodFromReq)

	if requestURL != nil {
		reqPath = requestURL.Path
		if reqPath == "" { // Path should be at least "/"
			reqPath = "/"
		}
		reqQuery = requestURL.RawQuery
	}

	stringToSignBuf, err := generateSignatureStringBuffer(signTargetNames, host, methodLowercase, reqPath, reqQuery, header, createdString, expiresString)
	if err != nil {
		return nil, "", "", err
	}

	return stringToSignBuf, createdString, expiresString, nil
}

func (s *signer) getHashName(hash crypto.Hash) (string, error) {
	switch hash {
	case crypto.SHA256:
		return "sha256", nil
	case crypto.SHA512:
		return "sha512", nil
	default:
		if hash == 0 { // if HashAlgorithm was not set for HMAC/RSA/ECDSA
			return "", fmt.Errorf("hash algorithm not specified or unsupported")
		}
		return "", fmt.Errorf("unsupported hash type: %s", hash.String())
	}
}

func createSignature(signOpts *SignOptions, signTarget []byte) ([]byte, string, error) {
	// HMAC signature
	if signOpts.SharedSecret != nil {
		if signOpts.HashAlgorithm == 0 {
			return nil, "", fmt.Errorf("hash algorithm must be specified for HMAC")
		}
		return createHmacSignature(signOpts.SharedSecret, signTarget, signOpts.HashAlgorithm)
	}

	// Asymmetric key signature
	if signOpts.PrivateKey == nil {
		return nil, "", ErrMissingPrivateKey
	}

	switch key := signOpts.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if signOpts.HashAlgorithm == 0 {
			return nil, "", fmt.Errorf("hash algorithm must be specified for RSA")
		}
		return createRsaSignature(key, signTarget, signOpts.HashAlgorithm)
	case *ecdsa.PrivateKey:
		if signOpts.HashAlgorithm == 0 {
			return nil, "", fmt.Errorf("hash algorithm must be specified for ECDSA")
		}
		return createEcdsaSignature(key, signTarget, signOpts.HashAlgorithm)
	case ed25519.PrivateKey:
		return createEd25519Signature(key, signTarget)
	case *ed25519.PrivateKey:
		return createEd25519Signature(*key, signTarget)
	default:
		return nil, "", fmt.Errorf("unknown or unsupported private key type: %T", signOpts.PrivateKey)
	}
}

func createRsaSignature(privateKey *rsa.PrivateKey, signTarget []byte, hash crypto.Hash) ([]byte, string, error) {
	h := hash.New()
	if _, err := h.Write(signTarget); err != nil {
		return nil, "", fmt.Errorf("failed to write to hash for RSA: %w", err)
	}
	hashed := h.Sum(nil)

	b, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	if err != nil {
		return nil, "", fmt.Errorf("RSA signing failed: %w", err)
	}
	return b, "rsa", nil
}

func createEcdsaSignature(privateKey *ecdsa.PrivateKey, signTarget []byte, hash crypto.Hash) ([]byte, string, error) {
	h := hash.New()
	if _, err := h.Write(signTarget); err != nil {
		return nil, "", fmt.Errorf("failed to write to hash for ECDSA: %w", err)
	}
	hashed := h.Sum(nil)

	b, err := ecdsa.SignASN1(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, "", fmt.Errorf("ECDSA signing failed: %w", err)
	}
	return b, "ecdsa", nil
}

func createEd25519Signature(privateKey ed25519.PrivateKey, signTarget []byte) ([]byte, string, error) {

	b := ed25519.Sign(privateKey, signTarget)
	return b, "ed25519", nil
}

func createHmacSignature(secret []byte, signTarget []byte, hash crypto.Hash) ([]byte, string, error) {
	if len(secret) == 0 {
		return nil, "", ErrMissingSharedSecret
	}
	if !hash.Available() {
		return nil, "", ErrUnsupportedHashAlgorithm
	}
	mac := hmac.New(hash.New, secret)
	if _, err := mac.Write(signTarget); err != nil {
		return nil, "", fmt.Errorf("failed to write to HMAC: %w", err)
	}
	return mac.Sum(nil), "hmac", nil
}
