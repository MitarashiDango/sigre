package sigre

import (
	"testing"
	"time"
)

func TestSigningTimestampsPreservesExpiration(t *testing.T) {
	tests := []struct {
		name         string
		now          time.Time
		expiresAfter time.Duration
		wantCreated  string
		wantExpires  string
	}{
		{name: "within same second", now: time.Unix(100, 900_000_000), expiresAfter: 50 * time.Millisecond, wantCreated: "100", wantExpires: "100.95"},
		{name: "at integer second", now: time.Unix(100, 900_000_000), expiresAfter: 100 * time.Millisecond, wantCreated: "100", wantExpires: "101"},
		{name: "across integer second", now: time.Unix(100, 900_000_000), expiresAfter: 200 * time.Millisecond, wantCreated: "100", wantExpires: "101.1"},
		{name: "more than one second", now: time.Unix(100, 900_000_000), expiresAfter: 1250 * time.Millisecond, wantCreated: "100", wantExpires: "102.15"},
		{name: "nanosecond precision trims trailing zero", now: time.Unix(100, 123_456_789), expiresAfter: time.Nanosecond, wantCreated: "100", wantExpires: "100.12345679"},
		{name: "leading fractional zeros", now: time.Unix(0, 0), expiresAfter: time.Nanosecond, wantCreated: "0", wantExpires: "0.000000001"},
		{name: "negative fractional deadline", now: time.Unix(-1, 100_000_000), expiresAfter: 50 * time.Millisecond, wantCreated: "-1", wantExpires: "-0.85"},
		{name: "immediately before epoch", now: time.Unix(-1, 999_999_998), expiresAfter: time.Nanosecond, wantCreated: "-1", wantExpires: "-0.000000001"},
		{name: "at epoch", now: time.Unix(-1, 950_000_000), expiresAfter: 50 * time.Millisecond, wantCreated: "-1", wantExpires: "0"},
		{name: "after epoch", now: time.Unix(-1, 950_000_000), expiresAfter: 100 * time.Millisecond, wantCreated: "-1", wantExpires: "0.05"},
		{name: "negative integer deadline", now: time.Unix(-2, 950_000_000), expiresAfter: 50 * time.Millisecond, wantCreated: "-2", wantExpires: "-1"},
		{name: "negative whole and fraction", now: time.Unix(-2, 900_000_000), expiresAfter: 50 * time.Millisecond, wantCreated: "-2", wantExpires: "-1.05"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deadline := tt.now.Add(tt.expiresAfter)
			if formatted := formatCavageExpires(deadline); formatted != tt.wantExpires {
				t.Fatalf("formatCavageExpires() = %q, want %q", formatted, tt.wantExpires)
			}

			created, expires := signingTimestamps(tt.now, []string{Created, Expires}, tt.expiresAfter)
			if created != tt.wantCreated {
				t.Fatalf("created = %q, want %q", created, tt.wantCreated)
			}
			if expires != tt.wantExpires {
				t.Fatalf("expires = %q, want %q", expires, tt.wantExpires)
			}

			parsed, err := parseCavageExpires(expires)
			if err != nil {
				t.Fatalf("parseCavageExpires(%q) failed: %v", expires, err)
			}
			if !parsed.Equal(deadline) {
				t.Fatalf("parsed expires = %v, want deadline %v", parsed, deadline)
			}
		})
	}
}
