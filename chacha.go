package chacha

import (
	"encoding/hex"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

func Compute(reader io.Reader, rs RangeSpec, key string) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("chacha20-poly1305 requires a 32-byte key")
	}
	aead, err := chacha20poly1305.New([]byte(key)[:32])
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(io.LimitReader(reader, rs.end-rs.start))
	if err != nil {
		return "", err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	tag := aead.Seal(nil, nonce, data, nil)
	return hex.EncodeToString(tag), nil
}