package sigre

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// maxCavageUnixSeconds is the largest Unix second for which time.Unix's
// internal addition of the offset from year 1 to 1970 does not overflow int64.
var maxCavageUnixSeconds = math.MaxInt64 + time.Time{}.Unix()

func parseCavageCreated(value string) (time.Time, error) {
	if !isSignedDecimalInteger(value) {
		return time.Time{}, fmt.Errorf("%w: created must be -?[0-9]+", ErrInvalidCreationTime)
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: created is outside the int64 range", ErrInvalidCreationTime)
	}
	if seconds > maxCavageUnixSeconds {
		return time.Time{}, fmt.Errorf("%w: created is outside the time.Time range", ErrInvalidCreationTime)
	}
	return time.Unix(seconds, 0), nil
}

func parseCavageExpires(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%w: expires is empty", ErrInvalidExpirationTime)
	}
	whole, fraction, hasFraction := strings.Cut(value, ".")
	if !isSignedDecimalInteger(whole) || hasFraction && (fraction == "" || !allDecimalDigits(fraction)) {
		return time.Time{}, fmt.Errorf("%w: expires must be -?[0-9]+ or -?[0-9]+\\.[0-9]+", ErrInvalidExpirationTime)
	}
	fraction = strings.TrimRight(fraction, "0")
	if len(fraction) > 9 {
		return time.Time{}, fmt.Errorf("%w: expires must have at most 9 fractional digits after trailing zeros are removed", ErrInvalidExpirationTime)
	}
	seconds, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: expires is outside the int64 range", ErrInvalidExpirationTime)
	}
	var nanoseconds int64
	if hasFraction {
		padded := fraction + strings.Repeat("0", 9-len(fraction))
		nanoseconds, _ = strconv.ParseInt(padded, 10, 32)
		if whole[0] == '-' {
			nanoseconds = -nanoseconds
		}
	}

	if seconds > maxCavageUnixSeconds || seconds == math.MinInt64 && nanoseconds < 0 {
		return time.Time{}, fmt.Errorf("%w: expires is outside the time.Time range", ErrInvalidExpirationTime)
	}
	return time.Unix(seconds, nanoseconds), nil
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
// duration. If Add clamps the seconds at time.Time's upper limit, no
// representable value can exceed the true boundary. All callers provide a
// non-negative duration validated by NewCavageVerifier.
func timeAfterDuration(value, base time.Time, duration time.Duration) bool {
	boundary := base.Add(duration)
	if boundary.Sub(base) < duration {
		return false
	}
	return value.After(boundary)
}

func cavageSigningTimestamps(now time.Time, headers []string, expiresAfter time.Duration) (created, expires string) {
	if slices.Contains(headers, CavageCreated) {
		created = strconv.FormatInt(now.Unix(), 10)
	}
	if slices.Contains(headers, CavageExpires) {
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
