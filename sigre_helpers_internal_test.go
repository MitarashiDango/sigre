package sigre

import (
	"errors"
	"testing"
)

func assertPackageError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	var packageError *SigreError
	if !errors.As(err, &packageError) {
		t.Fatalf("error %v is not wrapped by *SigreError", err)
	}
}
