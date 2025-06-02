package shake

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"io"
)

func Compute(reader io.Reader, rs RangeSpec, key string) (string, error) {
	hashFunc, err := getHasherByName("").hashFunc(key)
	if err != nil {
		return "", err
	}

	if rs.end != -1 {
		reader = io.LimitReader(reader, rs.end-rs.start)
	}

	buf := make([]byte, 32) // 256-bit output
	_, err = io.Copy(hashFunc, reader)
	if err != nil {
		return "", err
	}
	hashFunc.(sha3.ShakeSum).Read(buf)
	return hex.EncodeToString(buf), nil
}