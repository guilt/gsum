package chacha

import (
	"fmt"
	"io"

	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/log"

	"golang.org/x/crypto/chacha20poly1305"
)

var logger = log.NewLogger()

func Compute(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
	if len(key) < 32 {
		return "", fmt.Errorf("key must be at least 32 bytes")
	}

	aead, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	data := make([]byte, 0)

	if rs.Start > 0 {
		if seeker, ok := reader.(io.Seeker); ok {
			_, err := seeker.Seek(rs.Start, io.SeekStart)
			if err != nil {
				return "", err
			}
		} else {
			_, err := io.CopyN(io.Discard, reader, rs.Start)
			if err != nil {
				return "", err
			}
		}
	}

	var r io.Reader = reader
	if rs.End != -1 {
		length := rs.End - rs.Start
		r = io.LimitReader(reader, length)
	}

	data, err = io.ReadAll(r)
	if err != nil {
		return "", err
	}

	tag := aead.Seal(nil, nonce, data, nil)
	return fmt.Sprintf("%x:%x", nonce, tag), nil
}
