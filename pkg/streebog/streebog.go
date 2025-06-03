package streebog

import (
	"fmt"
	"io"

	gfile "github.com/guilt/gsum/pkg/file"
)

func ComputeHash(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	return "", fmt.Errorf("Streebog-256 and Streebog-512 not implemented in Go; use another algorithm")
}
