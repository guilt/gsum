package streebog

import (
	"fmt"
	"github.com/guilt/gsum/pkg/common"
	"io"
)

// Compute is a placeholder for the Streebog hash computation.
func Compute(reader io.Reader, rs common.RangeSpec, key string) (string, error) {
	return "", fmt.Errorf("Streebog-256 and Streebog-512 are not yet implemented in Go; please provide a Go implementation or use another algorithm")
}
