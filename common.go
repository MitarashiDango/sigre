package sigre

import (
	"fmt"
	"strconv"
)

func isValidUnixTime(s string) error {
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return fmt.Errorf("invalid integer format: %w", err)
	}
	return nil
}
