package hashers

import (
	"bufio"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"

	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"

	"github.com/cespare/xxhash"
	"github.com/guilt/gsum/pkg/bsdcksum"
	"github.com/guilt/gsum/pkg/chacha"
	"github.com/guilt/gsum/pkg/common"
	gfile "github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/ktwelve"
	"github.com/guilt/gsum/pkg/log"
	"github.com/guilt/gsum/pkg/shake"
	"github.com/guilt/gsum/pkg/siphash"
	"github.com/guilt/gsum/pkg/std"
	"github.com/guilt/gsum/pkg/streebog"
	"github.com/zeebo/blake3"
	"github.com/zentures/cityhash"
)

var logger = log.NewLogger()

func init() {
	hashers := map[common.Algorithm]common.Hasher{
		common.CRC32: {
			Algo:      common.CRC32,
			Name:      "crc32",
			Extension: ".crc32",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return crc32.NewIEEE(), nil }, rs)
			},
			OutputLen: 8,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "crc32sum" || strings.ToLower(filepath.Ext(fileName)) == ".crc32"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.BSDCKSUM: {
			Algo:      common.BSDCKSUM,
			Name:      "bsd-cksum",
			Extension: ".cksum",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) {
					return crc32.New(crc32.MakeTable(crc32.Castagnoli)), nil
				}, rs)
			},
			OutputLen: 8,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "cksum" || strings.ToLower(filepath.Ext(fileName)) == ".cksum"
			},
			ParseChecksumLine: bsdcksum.ParseChecksumLine,
		},
		common.MD4: {
			Algo:      common.MD4,
			Name:      "md4",
			Extension: ".md4",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return md4.New(), nil }, rs)
			},
			OutputLen: 32,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "md4sum" || strings.ToLower(filepath.Ext(fileName)) == ".md4"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.MD5: {
			Algo:      common.MD5,
			Name:      "md5",
			Extension: ".md5",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return md5.New(), nil }, rs)
			},
			OutputLen: 32,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "md5sum" || strings.ToLower(filepath.Base(fileName)) == "md5sums" || strings.ToLower(filepath.Ext(fileName)) == ".md5"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA1: {
			Algo:      common.SHA1,
			Name:      "sha1",
			Extension: ".sha1",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return sha1.New(), nil }, rs)
			},
			OutputLen: 40,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha1sum" || strings.ToLower(filepath.Base(fileName)) == "sha1sums" || strings.ToLower(filepath.Base(fileName)) == "shasum" || strings.ToLower(filepath.Ext(fileName)) == ".sha1"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA256: {
			Algo:      common.SHA256,
			Name:      "sha256",
			Extension: ".sha256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return sha256.New(), nil }, rs)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha256sum" || strings.ToLower(filepath.Base(fileName)) == "sha256sums" || strings.ToLower(filepath.Ext(fileName)) == ".sha256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA512: {
			Algo:      common.SHA512,
			Name:      "sha512",
			Extension: ".sha512",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return sha512.New(), nil }, rs)
			},
			OutputLen: 128,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha512sum" || strings.ToLower(filepath.Base(fileName)) == "sha512sums" || strings.ToLower(filepath.Ext(fileName)) == ".sha512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA3_256: {
			Algo:      common.SHA3_256,
			Name:      "sha3-256",
			Extension: ".sha3-256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return sha3.New256(), nil }, rs)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha3-256sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha3-256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHAKE128: {
			Algo:      common.SHAKE128,
			Name:      "shake128",
			Extension: ".shake128",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return shake.Compute(reader, key, func(_ string) (hash.Hash, error) { return sha3.NewShake128(), nil }, rs)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "shake128sum" || strings.ToLower(filepath.Ext(fileName)) == ".shake128"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHAKE256: {
			Algo:      common.SHAKE256,
			Name:      "shake256",
			Extension: ".shake256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return shake.Compute(reader, key, func(_ string) (hash.Hash, error) { return sha3.NewShake256(), nil }, rs)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "shake256sum" || strings.ToLower(filepath.Ext(fileName)) == ".shake256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.BLAKE2B: {
			Algo:      common.BLAKE2B,
			Name:      "blake2b",
			Extension: ".blake2b",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) {
					h, err := blake2b.New256(nil)
					return h, err
				}, rs)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "blake2bsum" || strings.ToLower(filepath.Ext(fileName)) == ".blake2b"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.BLAKE3: {
			Algo:      common.BLAKE3,
			Name:      "blake3",
			Extension: ".blake3",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return blake3.New(), nil }, rs)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "blake3sum" || strings.ToLower(filepath.Ext(fileName)) == ".blake3"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.HMACSHA1: {
			Algo:      common.HMACSHA1,
			Name:      "hmac-sha1",
			Extension: ".hmac-sha1",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(sha1.New, []byte(key)), nil
				}, rs)
			},
			OutputLen: 40,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("hmac-sha1 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "hmac-sha1sum" || strings.ToLower(filepath.Ext(fileName)) == ".hmac-sha1"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.HMACSHA256: {
			Algo:      common.HMACSHA256,
			Name:      "hmac-sha256",
			Extension: ".hmac-sha256",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(sha256.New, []byte(key)), nil
				}, rs)
			},
			OutputLen: 64,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("hmac-sha256 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "hmac-sha256sum" || strings.ToLower(filepath.Ext(fileName)) == ".hmac-sha256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.HMACSHA512: {
			Algo:      common.HMACSHA512,
			Name:      "hmac-sha512",
			Extension: ".hmac-sha512",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(sha512.New, []byte(key)), nil
				}, rs)
			},
			OutputLen: 128,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("hmac-sha512 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "hmac-sha512sum" || strings.ToLower(filepath.Ext(fileName)) == ".hmac-sha512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.CHACHA20POLY1305: {
			Algo:      common.CHACHA20POLY1305,
			Name:      "chacha20-poly1305",
			Extension: ".chacha20-poly1305",
			Keyed:     true,
			Compute:   chacha.Compute,
			OutputLen: 32,
			Validate: func(key string) error {
				if len(key) < 32 {
					return fmt.Errorf("chacha20-poly1305 requires a 32-byte key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "chacha20-poly1305sum" || strings.ToLower(filepath.Ext(fileName)) == ".chacha20-poly1305"
			},
			ParseChecksumLine: chacha.ParseChecksumLine,
		},
		common.XXHASH: {
			Algo:      common.XXHASH,
			Name:      "xxhash",
			Extension: ".xxhash",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return xxhash.New(), nil }, rs)
			},
			OutputLen: 16,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "xxhashsum" || strings.ToLower(filepath.Ext(fileName)) == ".xxhash"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SIPHASH: {
			Algo:      common.SIPHASH,
			Name:      "siphash",
			Extension: ".siphash",
			Keyed:     true,
			Compute:   siphash.ComputeHash,
			OutputLen: 16,
			Validate: func(key string) error {
				if len(key) != 16 {
					return fmt.Errorf("siphash requires a 16-byte key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "siphashsum" || strings.ToLower(filepath.Ext(fileName)) == ".siphash"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.CITYHASH: {
			Algo:      common.CITYHASH,
			Name:      "cityhash",
			Extension: ".cityhash",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, rs gfile.FileAndRangeSpec) (string, error) {
				return std.Compute(reader, key, func(_ string) (hash.Hash, error) { return cityhash.New64(), nil }, rs)
			},
			OutputLen: 16,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "cityhashsum" || strings.ToLower(filepath.Ext(fileName)) == ".cityhash"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.KANGAROOTWELVE: {
			Algo:      common.KANGAROOTWELVE,
			Name:      "kangaroo12",
			Extension: ".kangaroo12",
			Keyed:     false,
			Compute:   ktwelve.ComputeHash,
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "kangaroo12sum" || strings.ToLower(filepath.Ext(fileName)) == ".kangaroo12"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.STREEBOG256: {
			Algo:      common.STREEBOG256,
			Name:      "streebog256",
			Extension: ".streebog256",
			Keyed:     false,
			Compute:   streebog.ComputeHash,
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "streebog256sum" || strings.ToLower(filepath.Ext(fileName)) == ".streebog256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.STREEBOG512: {
			Algo:      common.STREEBOG512,
			Name:      "streebog512",
			Extension: ".streebog512",
			Keyed:     false,
			Compute:   streebog.ComputeHash,
			OutputLen: 128,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "streebog512sum" || strings.ToLower(filepath.Ext(fileName)) == ".streebog512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
	}

	for _, h := range hashers {
		common.AddHasher(h)
	}
}

func GetHashes(h common.Hasher, hashFiles []string) map[string]string {
	hashes := make(map[string]string)
	for _, hashFile := range hashFiles {
		file, err := os.Open(hashFile)
		if err != nil {
			logger.Errorf("Error opening hash file: file=%s, error=%s", hashFile, err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hashValue, fileAndRange, _, err := h.ParseChecksumLine(line)
			if err != nil {
				logger.Errorf("Invalid checksum line: file=%s, line=%s, error=%s", hashFile, line, err)
				os.Exit(1)
			}
			hashes[fileAndRange.FilePath] = hashValue
		}
		if err := scanner.Err(); err != nil {
			logger.Errorf("Error reading hash file: file=%s, error=%s", hashFile, err)
			os.Exit(1)
		}
	}
	return hashes
}
