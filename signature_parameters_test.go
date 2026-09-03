package sigre_test

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/MitarashiDango/sigre"
)

func TestParseCavageParams(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expected      *sigre.ExportForTesting_cavageParams
		errorContains string
	}{
		{
			name:  "all parameters",
			input: `keyId="test-key-1",algorithm="rsa-sha256",created=1618952679,expires=1618952739,headers="(created) (expires) host date digest",signature="c2ln"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:            "test-key-1",
				Algorithm:        "rsa-sha256",
				AlgorithmPresent: true,
				Created:          "1618952679",
				CreatedPresent:   true,
				Expires:          "1618952739",
				ExpiresPresent:   true,
				Headers:          []string{"(created)", "(expires)", "host", "date", "digest"},
				Signature:        "c2ln",
				HeadersPresent:   true,
			},
		},
		{
			name:  "case insensitive names token values and whitespace",
			input: "\tKEYID \t= token-key \t, ALGORITHM=hs2019, CREATED = 1618952679 , EXPIRES\t=\t1618952739, HEADERS = \"Host Date\" , SIGNATURE = c2ln\t",
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:            "token-key",
				Algorithm:        "hs2019",
				AlgorithmPresent: true,
				Created:          "1618952679",
				CreatedPresent:   true,
				Expires:          "1618952739",
				ExpiresPresent:   true,
				Headers:          []string{"host", "date"},
				Signature:        "c2ln",
				HeadersPresent:   true,
			},
		},
		{
			name:  "quoted-pair unescapes double quote and backslash",
			input: `keyId="key\"quote\\slash",signature="c2ln"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "key\"quote\\slash",
				Signature: "c2ln",
			},
		},
		{
			name:  "different parameter order",
			input: `signature=c2ln,headers=date,keyId=key-4`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:          "key-4",
				Headers:        []string{"date"},
				Signature:      "c2ln",
				HeadersPresent: true,
			},
		},
		{
			name:  "unknown token and quoted-string parameters are ignored",
			input: `unknown=token,extension="value,with,commas",keyId=key-5,signature=c2ln`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "key-5",
				Signature: "c2ln",
			},
		},
		{
			name:  "malformed known optional parameter is ignored",
			input: `keyId="k",signature="AA==",algorithm=@`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "k",
				Signature: "AA==",
			},
		},
		{
			name:  "malformed required parameter before valid parameter is ignored",
			input: `keyId,keyId="k",signature="AA=="`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "k",
				Signature: "AA==",
			},
		},
		{
			name:  "malformed required parameter after valid parameter is ignored",
			input: `keyId="k",keyId,signature="AA=="`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "k",
				Signature: "AA==",
			},
		},
		{
			name:  "malformed optional parameter before valid parameter is ignored",
			input: `keyId="k",signature="AA==",algorithm=@,algorithm=hs2019`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:            "k",
				Signature:        "AA==",
				Algorithm:        "hs2019",
				AlgorithmPresent: true,
			},
		},
		{
			name:  "malformed optional parameter after valid parameter is ignored",
			input: `keyId="k",signature="AA==",algorithm=hs2019,algorithm=@`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:            "k",
				Signature:        "AA==",
				Algorithm:        "hs2019",
				AlgorithmPresent: true,
			},
		},
		{
			name:  "malformed created after valid parameter is ignored",
			input: `keyId=one,signature=c2ln,created=1,created=@`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:          "one",
				Signature:      "c2ln",
				Created:        "1",
				CreatedPresent: true,
			},
		},
		{
			name:  "two malformed optional parameters remain absent",
			input: `keyId="k",signature="AA==",algorithm=@,algorithm=@`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "k",
				Signature: "AA==",
			},
		},
		{
			name:  "malformed headers parameter remains absent",
			input: `keyId="k",signature="AA==",headers=@`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "k",
				Signature: "AA==",
			},
		},
		{
			name:  "malformed unknown parameter is ignored",
			input: `keyId="k",signature="AA==",bogus=@`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "k",
				Signature: "AA==",
			},
		},
		{
			name:  "malformed parameters with safe boundaries are ignored",
			input: `bad=@,missing-equals value,keyId=key-6,signature=c2ln`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:     "key-6",
				Signature: "c2ln",
			},
		},
		{
			name:  "time syntax is retained for verifier policy validation",
			input: `created=not-a-number,keyId=key-7,signature=c2ln`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:          "key-7",
				Signature:      "c2ln",
				Created:        "not-a-number",
				CreatedPresent: true,
			},
		},
		{
			name:  "expires syntax is retained for verifier policy validation",
			input: `expires=not-a-number,keyId=key-8,signature=c2ln`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyID:          "key-8",
				Signature:      "c2ln",
				Expires:        "not-a-number",
				ExpiresPresent: true,
			},
		},
		{
			name:          "two malformed required parameters remain missing",
			input:         `keyId,keyId,signature="AA=="`,
			errorContains: "missing required parameter: keyId",
		},
		{
			name:          "missing keyId",
			input:         `algorithm=hs2019,signature=c2ln`,
			errorContains: "missing required parameter: keyId",
		},
		{
			name:          "empty keyId",
			input:         `keyId="",signature=c2ln`,
			errorContains: "missing required parameter: keyId",
		},
		{
			name:          "missing signature",
			input:         `keyId=key-1`,
			errorContains: "missing required parameter: signature",
		},
		{
			name:          "empty signature",
			input:         `keyId=key-1,signature=""`,
			errorContains: "missing required parameter: signature",
		},
		{
			name:          "invalid base64",
			input:         `keyId=key-1,signature="not@base64"`,
			errorContains: "invalid 'signature' value",
		},
		{
			name:          "unclosed quoted-string",
			input:         `keyId="unterminated,signature=c2ln`,
			errorContains: "unclosed quoted-string",
		},
		{
			name:          "incomplete quoted-pair",
			input:         `keyId="unterminated\`,
			errorContains: "incomplete quoted-pair",
		},
		{
			name:          "invalid quoted-pair",
			input:         "keyId=\"invalid\\\x01pair\",signature=c2ln",
			errorContains: "invalid quoted-pair",
		},
		{
			name:          "forbidden control byte",
			input:         "keyId=\"line\nbreak\",signature=c2ln",
			errorContains: "forbidden control byte",
		},
		{
			name:          "empty headers",
			input:         `keyId=key-1,signature=c2ln,headers=""`,
			errorContains: "must specify a non-empty value",
		},
		{
			name:          "missing comma does not recover a hidden parameter",
			input:         `keyId=key-1 signature=c2ln`,
			errorContains: "missing required parameter: keyId",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := sigre.ExportForTesting_parseCavageParams(tc.input)
			if tc.errorContains != "" {
				if err == nil {
					t.Fatal("expected an error, but got none")
				}
				if !strings.Contains(err.Error(), tc.errorContains) {
					t.Fatalf("error = %q, want it to contain %q", err, tc.errorContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Fatalf("parsed parameters do not match\ngot:  %+v\nwant: %+v", actual, tc.expected)
			}
		})
	}
}

func TestParseCavageParamsRejectsDuplicateKnownParameters(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{name: "keyId", input: `keyId="first",keyId="second",signature="AA=="`},
		{name: "signature", input: `keyId=one,signature=c2ln,signature=c2ln`},
		{name: "algorithm", input: `keyId=one,algorithm=hs2019,algorithm=hs2019,signature=c2ln`},
		{name: "headers", input: `keyId=one,headers=host,headers=date,signature=c2ln`},
		{name: "created at end", input: `keyId=one,signature=c2ln,created=1,created=2`},
		{name: "expires at end", input: `keyId=one,signature=c2ln,expires=1,expires=2`},
		{name: "case only difference", input: `keyId=one,signature=c2ln,created=1,CREATED=2`},
		{name: "unknown content cannot hide duplicate", input: `unknown="created=1,created=2",created=1,CREATED=2,keyId=one,signature=c2ln`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sigre.ExportForTesting_parseCavageParams(tc.input)
			if err == nil || !strings.Contains(err.Error(), "duplicate parameter name") {
				t.Fatalf("expected duplicate parameter error, got: %v", err)
			}
		})
	}
}

func TestCavageVerifierRejectsSemanticallyInvalidParameters(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantError error
	}{
		{
			name:      "created is not a number",
			input:     `keyId="k",signature="AA==",headers="x-test",created=not-a-number`,
			wantError: sigre.ErrInvalidCreationTime,
		},
		{
			name:      "expires is not a number",
			input:     `keyId="k",signature="AA==",headers="x-test",expires=not-a-number`,
			wantError: sigre.ErrInvalidExpirationTime,
		},
		{
			name:      "algorithm is not allowed",
			input:     `keyId="k",signature="AA==",headers="x-test",algorithm=unknown-algorithm`,
			wantError: sigre.ErrInvalidSignatureAlgorithm,
		},
		{
			name:      "headers is empty",
			input:     `keyId="k",signature="AA==",headers=""`,
			wantError: sigre.ErrInvalidSignatureParameters,
		},
		{
			name:      "signature is not Base64",
			input:     `keyId="k",signature="not@base64",headers="x-test"`,
			wantError: sigre.ErrInvalidSignatureParameters,
		},
		{
			name:      "keyId is empty",
			input:     `keyId="",signature="AA==",headers="x-test"`,
			wantError: sigre.ErrInvalidSignatureParameters,
		},
		{
			name:      "signature is empty",
			input:     `keyId="k",signature="",headers="x-test"`,
			wantError: sigre.ErrInvalidSignatureParameters,
		},
	}

	verifier, err := sigre.NewCavageVerifier(nil)
	if err != nil {
		t.Fatalf("NewCavageVerifier() failed: %v", err)
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{
				Method:     http.MethodGet,
				RequestURI: "/",
				Host:       "example.test",
				Header: http.Header{
					"Signature": {tc.input},
					"X-Test":    {"test value"},
				},
			}
			_, err := verifier.ParseRequest(req)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("ParseRequest() error = %v, want errors.Is(_, %v)", err, tc.wantError)
			}
		})
	}
}

func TestSerializeCavageParamsRoundTrip(t *testing.T) {
	want := &sigre.ExportForTesting_cavageParams{
		KeyID:            "key\"quote\\slash",
		Signature:        "c2ln",
		Algorithm:        "hs2019",
		AlgorithmPresent: true,
		Created:          "1618952679",
		CreatedPresent:   true,
		Expires:          "1618952739.123456789",
		ExpiresPresent:   true,
		Headers:          []string{"(created)", "(expires)", "host", "date"},
		HeadersPresent:   true,
	}

	wire, err := sigre.ExportForTesting_serializeCavageParams(want)
	if err != nil {
		t.Fatalf("serialization failed: %v", err)
	}
	if !strings.Contains(wire, `keyId="key\"quote\\slash"`) {
		t.Fatalf("serialized keyId is not correctly escaped: %s", wire)
	}

	got, err := sigre.ExportForTesting_parseCavageParams(wire)
	if err != nil {
		t.Fatalf("failed to parse serialized parameters: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed parameter meaning\ngot:  %+v\nwant: %+v", got, want)
	}
}

func TestSerializeCavageParamsRejectsUnsafeValues(t *testing.T) {
	testCases := []struct {
		name   string
		params *sigre.ExportForTesting_cavageParams
	}{
		{name: "nil parameters", params: nil},
		{name: "empty keyId", params: &sigre.ExportForTesting_cavageParams{Signature: "c2ln"}},
		{name: "empty signature", params: &sigre.ExportForTesting_cavageParams{KeyID: "key"}},
		{name: "invalid base64", params: &sigre.ExportForTesting_cavageParams{KeyID: "key", Signature: "not@base64"}},
		{name: "newline in keyId", params: &sigre.ExportForTesting_cavageParams{KeyID: "key\nvalue", Signature: "c2ln"}},
		{name: "carriage return in keyId", params: &sigre.ExportForTesting_cavageParams{KeyID: "key\rvalue", Signature: "c2ln"}},
		{name: "NUL in keyId", params: &sigre.ExportForTesting_cavageParams{KeyID: "key\x00value", Signature: "c2ln"}},
		{name: "DEL in keyId", params: &sigre.ExportForTesting_cavageParams{KeyID: "key\x7fvalue", Signature: "c2ln"}},
		{name: "control in algorithm", params: &sigre.ExportForTesting_cavageParams{KeyID: "key", Signature: "c2ln", Algorithm: "hs2019\n"}},
		{name: "invalid created", params: &sigre.ExportForTesting_cavageParams{KeyID: "key", Signature: "c2ln", Created: "invalid"}},
		{name: "invalid expires", params: &sigre.ExportForTesting_cavageParams{KeyID: "key", Signature: "c2ln", Expires: "1.1234567890"}},
		{name: "empty header name", params: &sigre.ExportForTesting_cavageParams{KeyID: "key", Signature: "c2ln", Headers: []string{""}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sigre.ExportForTesting_serializeCavageParams(tc.params); err == nil {
				t.Fatal("expected serialization to fail")
			}
		})
	}
}

func TestParseCavageParamsAllocationsDoNotScaleWithIgnoredParameters(t *testing.T) {
	input := strings.Repeat("unknown=value,", 4096) + "keyId=key,signature=c2ln"
	allocations := testing.AllocsPerRun(20, func() {
		if _, err := sigre.ExportForTesting_parseCavageParams(input); err != nil {
			panic(err)
		}
	})
	if allocations > 32 {
		t.Fatalf("parse allocated %.0f objects for safely ignored parameters, want at most 32", allocations)
	}
}

func TestParseCavageParamsAllocationsDoNotScaleWithIgnoredQuotedPairs(t *testing.T) {
	const ignoredParameter = `unknown="a\"b",`
	smallInput := ignoredParameter + "keyId=key,signature=c2ln"
	largeInput := strings.Repeat(ignoredParameter, 4096) + "keyId=key,signature=c2ln"

	parse := func(input string) {
		params, err := sigre.ExportForTesting_parseCavageParams(input)
		if err != nil {
			panic(err)
		}
		if params.KeyID != "key" || params.Signature != "c2ln" {
			panic("parser did not preserve the known parameters")
		}
	}

	parse(largeInput)
	smallAllocations := testing.AllocsPerRun(20, func() { parse(smallInput) })
	largeAllocations := testing.AllocsPerRun(20, func() { parse(largeInput) })
	t.Logf("allocations with one ignored quoted-pair parameter: %.0f; with 4096: %.0f", smallAllocations, largeAllocations)
	if largeAllocations > smallAllocations+4 {
		t.Fatalf("allocations scaled with ignored quoted-pair parameters: one allocated %.0f objects, 4096 allocated %.0f", smallAllocations, largeAllocations)
	}
}

func FuzzParseCavageParams(f *testing.F) {
	seeds := []string{
		`keyId="test-key-1",algorithm="rsa-sha256",created=1618952679,expires=1618952739,headers="(created) (expires) host date digest",signature="c2ln"`,
		"\tKEYID = token-key, SIGNATURE = c2ln\t",
		`keyId="key\"quote\\slash",signature=c2ln`,
		`unknown=token,extension="value,with,commas",keyId=key,signature=c2ln`,
		`bad=@,keyId=key,signature=c2ln`,
		`keyId="k",signature="AA==",algorithm=@`,
		`keyId,keyId="k",signature="AA=="`,
		`keyId="k",keyId,signature="AA=="`,
		`keyId="first",keyId="second",signature="AA=="`,
		`keyId="k",signature="AA==",bogus=@`,
		`created=@,created=1,keyId=key,signature=c2ln`,
		`created=1,created=@,keyId=key,signature=c2ln`,
		`keYId="0",0,eXpires="",signAture="0000"`,
		`keyId="unterminated,signature=c2ln`,
		`keyId="unterminated\`,
		"keyId=\"line\nbreak\",signature=c2ln",
		`keyId=key,signature="not@base64"`,
		``,
		`,`,
		`=`,
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		params, err := sigre.ExportForTesting_parseCavageParams(input)
		if err != nil {
			return
		}
		if params == nil || params.KeyID == "" || params.Signature == "" {
			t.Fatal("parser returned incomplete parameters with nil error")
		}

		wire, err := sigre.ExportForTesting_serializeCavageParams(params)
		if err != nil {
			// parseCavageParams preserves raw created and expires values so that
			// the public parser can return the phase-specific time sentinel.
			// The serializer intentionally rejects values it would not emit.
			return
		}
		roundTripped, err := sigre.ExportForTesting_parseCavageParams(wire)
		if err != nil {
			t.Fatalf("parser rejected serializer output: %v", err)
		}
		if !reflect.DeepEqual(roundTripped, params) {
			t.Fatalf("parser and serializer changed parameter meaning")
		}
	})
}
