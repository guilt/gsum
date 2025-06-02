package chacha

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/log"

	"golang.org/x/crypto/chacha20poly1305"
)

// logger is the package-level logger for debug and error messages.
var logger = log.NewLogger()

// Compute computes a ChaCha20-Poly1305 authenticated tag for the given reader.
func Compute(reader io.Reader, rs common.RangeSpec, key string) (string, error) {
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

// ParseChaChaHash parses a ChaCha20-Poly1305 hash string in the format <nonce>:<tag>.
func ParseChaChaHash(hash string) (nonce, tag []byte, err error) {
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid chacha20-poly1305 hash format: %s", hash)
	}

	nonce, err = hex.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid nonce: %s", parts[0])
	}

	tag, err = hex.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid tag: %s", parts[1])
	}

	return nonce, tag, nil
}

// ParseChecksumLine parses a ChaCha20-Poly1305 checksum line.
func ParseChecksumLine(line string) (hashValue, filePath string, rs common.RangeSpec, err error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		logger.Errorf("Invalid checksum format: line=%s", line)
		return "", "", common.RangeSpec{}, fmt.Errorf("invalid checksum format: %s", line)
	}

	hashValue = parts[0]
	if len(parts) == 2 {
		filePath = parts[1]
		rs = common.RangeSpec{Start: 0, End: -1}
	} else {
		rangeVal, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			logger.Errorf("Invalid range value: range=%s, error=%v", parts[1], err)
			return "", "", common.RangeSpec{}, fmt.Errorf("invalid range value: %s", parts[1])
		}
		filePath = strings.Join(parts[2:], " ")
		rs = common.RangeSpec{Start: 0, End: rangeVal}
	}

	if strings.Contains(filePath, "#") {
		filePath, rs, err = file.ParseFilePath(filePath)
		if err != nil {
			logger.Errorf("Invalid file path: path=%s, error=%v", filePath, err)
			return "", "", common.RangeSpec{}, fmt.Errorf("invalid file path: %v", err)
		}
	}

	_, _, err = ParseChaChaHash(hashValue)
	if err != nil {
		logger.Errorf("Invalid chacha20-poly1305 hash: hash=%s, error=%v", hashValue, err)
		return "", "", common.RangeSpec{}, fmt.Errorf("invalid chacha20-poly1305 hash: %v", err)
	}

	return hashValue, filePath, rs, nil
}
