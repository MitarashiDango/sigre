package sigre_test

import (
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
				KeyId:     "test-key-1",
				Algorithm: "rsa-sha256",
				Created:   "1618952679",
				Expires:   "1618952739",
				Headers:   []string{"(created)", "(expires)", "host", "date", "digest"},
				Signature: "c2ln",
			},
		},
		{
			name:  "case insensitive names token values and whitespace",
			input: "\tKEYID \t= token-key \t, ALGORITHM=hs2019, CREATED = 1618952679 , EXPIRES\t=\t1618952739, HEADERS = \"Host Date\" , SIGNATURE = c2ln\t",
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "token-key",
				Algorithm: "hs2019",
				Created:   "1618952679",
				Expires:   "1618952739",
				Headers:   []string{"host", "date"},
				Signature: "c2ln",
			},
		},
		{
			name:  "quoted-pair unescapes double quote and backslash",
			input: `keyId="key\"quote\\slash",signature="c2ln"`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "key\"quote\\slash",
				Signature: "c2ln",
			},
		},
		{
			name:  "different parameter order",
			input: `signature=c2ln,headers=date,keyId=key-4`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "key-4",
				Headers:   []string{"date"},
				Signature: "c2ln",
			},
		},
		{
			name:  "unknown token and quoted-string parameters are ignored",
			input: `unknown=token,extension="value,with,commas",keyId=key-5,signature=c2ln`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "key-5",
				Signature: "c2ln",
			},
		},
		{
			name:  "malformed parameters with safe boundaries are ignored",
			input: `bad=@,missing-equals value,keyId=key-6,signature=c2ln`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "key-6",
				Signature: "c2ln",
			},
		},
		{
			name:  "invalid optional parameter with safe boundary is ignored",
			input: `created=not-a-number,keyId=key-7,signature=c2ln`,
			expected: &sigre.ExportForTesting_cavageParams{
				KeyId:     "key-7",
				Signature: "c2ln",
			},
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
			errorContains: "missing required parameter",
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
		{name: "keyId", input: `keyId=one,keyId=two,signature=c2ln`},
		{name: "signature", input: `keyId=one,signature=c2ln,signature=c2ln`},
		{name: "algorithm", input: `keyId=one,algorithm=hs2019,algorithm=hs2019,signature=c2ln`},
		{name: "headers", input: `keyId=one,headers=host,headers=date,signature=c2ln`},
		{name: "created at end", input: `keyId=one,signature=c2ln,created=1,created=2`},
		{name: "expires at end", input: `keyId=one,signature=c2ln,expires=1,expires=2`},
		{name: "case only difference", input: `keyId=one,signature=c2ln,created=1,CREATED=2`},
		{name: "malformed first value", input: `keyId=one,signature=c2ln,created=@,created=2`},
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

func TestSerializeCavageParamsRoundTrip(t *testing.T) {
	want := &sigre.ExportForTesting_cavageParams{
		KeyId:     "key\"quote\\slash",
		Signature: "c2ln",
		Algorithm: "hs2019",
		Created:   "1618952679",
		Expires:   "1618952739",
		Headers:   []string{"(created)", "(expires)", "host", "date"},
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
		{name: "empty signature", params: &sigre.ExportForTesting_cavageParams{KeyId: "key"}},
		{name: "invalid base64", params: &sigre.ExportForTesting_cavageParams{KeyId: "key", Signature: "not@base64"}},
		{name: "newline in keyId", params: &sigre.ExportForTesting_cavageParams{KeyId: "key\nvalue", Signature: "c2ln"}},
		{name: "carriage return in keyId", params: &sigre.ExportForTesting_cavageParams{KeyId: "key\rvalue", Signature: "c2ln"}},
		{name: "NUL in keyId", params: &sigre.ExportForTesting_cavageParams{KeyId: "key\x00value", Signature: "c2ln"}},
		{name: "DEL in keyId", params: &sigre.ExportForTesting_cavageParams{KeyId: "key\x7fvalue", Signature: "c2ln"}},
		{name: "control in algorithm", params: &sigre.ExportForTesting_cavageParams{KeyId: "key", Signature: "c2ln", Algorithm: "hs2019\n"}},
		{name: "invalid created", params: &sigre.ExportForTesting_cavageParams{KeyId: "key", Signature: "c2ln", Created: "invalid"}},
		{name: "empty header name", params: &sigre.ExportForTesting_cavageParams{KeyId: "key", Signature: "c2ln", Headers: []string{""}}},
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
		if params.KeyId != "key" || params.Signature != "c2ln" {
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
		`created=@,created=1,keyId=key,signature=c2ln`,
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
		if params == nil || params.KeyId == "" || params.Signature == "" {
			t.Fatal("parser returned incomplete parameters with nil error")
		}

		wire, err := sigre.ExportForTesting_serializeCavageParams(params)
		if err != nil {
			t.Fatalf("parser accepted parameters that serializer rejected: %v", err)
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
