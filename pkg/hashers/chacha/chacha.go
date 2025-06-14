package chacha

import (
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/hashers/std"
)

func Compute(reader io.Reader, key string, rs common.FileAndRangeSpec) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("key must be at least 32 bytes")
	}

	aead, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())

	r, err := std.PrepareRangeReader(reader, rs)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	tag := aead.Seal(nil, nonce, data, nil)
	return fmt.Sprintf("%x:%x", nonce, tag), nil
}
