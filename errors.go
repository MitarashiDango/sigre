package sigre

import (
	"errors"
	"fmt"
)

var (
	ErrMissingSignature = errors.New("missing signature")
)

type SigreError struct {
	Err error
}

func (e *SigreError) Unwrap() error {
	return e.Err
}

func (e *SigreError) Error() string {
	return fmt.Sprintf("sigre error: %s", e.Err)
}
