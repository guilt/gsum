package chacha

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

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

func ParseChecksumValue(hash string) (nonce, tag []byte, err error) {
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

func ParseChecksumLine(line string) (hashValue string, fileAndRange gfile.FileAndRangeSpec, byteCount int64, err error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		logger.Errorf("Invalid checksum format: line=%s", line)
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid checksum format: %s", line)
	}

	hashValue = parts[0]
	fileStart := 1
	if len(parts) > 2 {
		if count, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			byteCount = count
			fileStart = 2
		}
	}

	filePath := strings.Join(parts[fileStart:], " ")
	if err := fileAndRange.Parse(filePath); err != nil {
		logger.Errorf("Invalid file path: path=%s, error=%s", filePath, err)
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file path: %s", err)
	}

	_, _, err = ParseChecksumValue(hashValue)
	if err != nil {
		logger.Errorf("Invalid chacha hash: hash=%s, error=%s", hashValue, err)
		return "", gfile.FileAndRangeSpec{}, 0, fmt.Errorf("invalid chacha hash: %s", err)
	}

	return hashValue, fileAndRange, byteCount, nil
}
