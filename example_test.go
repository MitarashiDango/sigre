package sigre_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MitarashiDango/sigre"
)

func exampleEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func ExampleCavageSigner_SignRequest() {
	_, privateKey := exampleEd25519Key()
	req, err := http.NewRequest(http.MethodPost, "https://example.test/inbox?view=full", nil)
	if err != nil {
		panic(err)
	}

	signer := sigre.NewCavageSigner()
	signer.Now = func() time.Time { return time.Unix(1_735_689_600, 0) }
	err = signer.SignRequest(
		req,
		sigre.SigningKey{
			Metadata: sigre.TrustedKeyMetadata{
				KeyID:     "https://example.test/actor#main-key",
				Algorithm: sigre.AlgorithmEd25519,
			},
			PrivateKey: privateKey,
		},
		sigre.CavageSignaturePlacementSignature,
		nil,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("Signature header written:", req.Header.Get(sigre.Signature) != "")
	// Output:
	// Signature header written: true
}

func ExampleCavageVerifier_Verify() {
	publicKey, privateKey := exampleEd25519Key()
	metadata := sigre.TrustedKeyMetadata{
		KeyID:     "https://example.test/actor#main-key",
		Algorithm: sigre.AlgorithmEd25519,
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.test/resource?a=1", nil)
	if err != nil {
		panic(err)
	}
	signer := sigre.NewCavageSigner()
	signer.Now = func() time.Time { return time.Unix(1_735_689_600, 0) }
	if err := signer.SignRequest(
		req,
		sigre.SigningKey{Metadata: metadata, PrivateKey: privateKey},
		sigre.CavageSignaturePlacementSignature,
		nil,
	); err != nil {
		panic(err)
	}

	// A server-side request carries the escaped path and raw query in RequestURI.
	req.RequestURI = req.URL.RequestURI()
	verifier, err := sigre.NewCavageVerifier(nil)
	if err != nil {
		panic(err)
	}
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		panic(err)
	}
	// keyId is attacker-controlled input. A real resolver must constrain its
	// scheme and origin, redirects, DNS/IP destinations, timeouts, response size,
	// concurrency, cache behavior, and TLS validation.
	trustedKeys := map[string]sigre.VerificationKey{
		metadata.KeyID: {Metadata: metadata, PublicKey: publicKey},
	}
	verificationKey, ok := trustedKeys[signature.KeyID()]
	if !ok {
		panic("untrusted keyId did not resolve to the expected trusted key")
	}
	// Digest/body validation, replay prevention, principal binding,
	// authorization, and transport security remain caller responsibilities.
	// RFC 9421 is a separate protocol and is not implemented by this API.
	err = verifier.Verify(signature, verificationKey)
	if err != nil {
		panic(err)
	}

	fmt.Println("verified:", true)
	// Output:
	// verified: true
}

func ExampleCavageSigner_SignRequest_compatibility() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	metadata := sigre.TrustedKeyMetadata{
		KeyID:     "https://social.example/actor#main-key",
		Algorithm: sigre.AlgorithmRSAPKCS1v15SHA256,
	}
	req, err := http.NewRequest(http.MethodPost, "https://peer.example/inbox", nil)
	if err != nil {
		panic(err)
	}
	now := time.Unix(1_735_689_600, 0).UTC()
	req.Header.Set("Date", now.Format(http.TimeFormat))

	signer := sigre.NewCavageSigner()
	signer.Now = func() time.Time { return now }
	err = signer.SignRequest(
		req,
		sigre.SigningKey{Metadata: metadata, PrivateKey: privateKey},
		sigre.CavageSignaturePlacementSignature,
		&sigre.CavageSigningOptions{
			Compatibility: &sigre.CavageSigningCompatibility{
				AlgorithmField: sigre.AlgorithmFieldLegacy,
				ExactHeaders:   []string{"(request-target)", "date"},
			},
		},
	)
	if err != nil {
		panic(err)
	}

	req.RequestURI = req.URL.RequestURI()
	verifier, err := sigre.NewCavageVerifier(&sigre.CavageVerificationOptions{
		RequiredHeaders:   []string{"(request-target)", "date"},
		AllowedAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
		MaxDateAge:        time.Minute,
		Now:               func() time.Time { return now },
		Compatibility: &sigre.CavageVerificationCompatibility{
			AllowedLegacyAlgorithms: []sigre.AlgorithmID{sigre.AlgorithmRSAPKCS1v15SHA256},
		},
	})
	if err != nil {
		panic(err)
	}
	signature, err := verifier.ParseRequest(req)
	if err != nil {
		panic(err)
	}
	err = verifier.Verify(signature, sigre.VerificationKey{Metadata: metadata, PublicKey: &privateKey.PublicKey})
	if err != nil {
		panic(err)
	}

	fmt.Println("legacy rsa-sha256 verified:", true)
	// Output:
	// legacy rsa-sha256 verified: true
}

func ExampleSigreError() {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/unsigned", nil)
	if err != nil {
		panic(err)
	}
	verifier, err := sigre.NewCavageVerifier(nil)
	if err != nil {
		panic(err)
	}
	_, err = verifier.ParseRequest(req)

	var sigreError *sigre.SigreError
	fmt.Println("missing signature:", errors.Is(err, sigre.ErrMissingSignature))
	fmt.Println("package error:", errors.As(err, &sigreError))
	// Output:
	// missing signature: true
	// package error: true
}
