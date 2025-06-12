package hashers

import (
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/cespare/xxhash"
	"github.com/emmansun/gmsm/sm3"
	"github.com/jzelinskie/whirlpool"
	"github.com/zeebo/blake3"
	"github.com/zentures/cityhash"

	"github.com/guilt/gsum/pkg/argon2"
	"github.com/guilt/gsum/pkg/bcrypt"
	"github.com/guilt/gsum/pkg/bsdcksum"
	"github.com/guilt/gsum/pkg/chacha"
	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/ktwelve"
	"github.com/guilt/gsum/pkg/pbkdf2"
	"github.com/guilt/gsum/pkg/scrypt"
	"github.com/guilt/gsum/pkg/siphash"
	"github.com/guilt/gsum/pkg/ssdeep"
	"github.com/guilt/gsum/pkg/std"
	"github.com/guilt/gsum/pkg/streebog"
	"github.com/guilt/gsum/pkg/tth"
)

// Hasher represents a hash function.
type Hasher struct {
	Algorithm         common.Algorithm
	Name              string
	Extension         string
	Keyed             bool
	Compute           func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error)
	OutputLen         int
	Validate          func(key string) error
	AcceptsFile       func(fileName string) bool
	ParseChecksumLine func(line string) (hashValue string, fileAndRangeSpec common.FileAndRangeSpec, byteCount int64, err error)
}

// _hashers is a map of _hashers by algorithm.
var _hashers = make(map[common.Algorithm]Hasher)

// GetHasher returns a Hasher for the given algorithm name.
func GetHasher(name string) (Hasher, error) {
	// First try to find by exact match
	for _, h := range _hashers {
		if strings.EqualFold(h.Name, name) {
			return h, nil
		}
	}
	// If not found, try without any dashes or underscores
	simplifiedName := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "-", ""), "_", ""))
	for _, h := range _hashers {
		hashName := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(h.Name, "-", ""), "_", ""))
		if hashName == simplifiedName {
			return h, nil
		}
	}
	return Hasher{}, fmt.Errorf("unsupported algorithm: %s (available: %s)", name, strings.Join(GetAllHasherNames(), ", "))
}

// GetDefaultHashAlgorithm returns the default hash algorithm.
func GetDefaultHashAlgorithm() string {
	return "sha256"
}

// GetAllHasherNames returns a list of all available hash algorithms.
func GetAllHasherNames() []string {
	names := make([]string, 0, len(_hashers))
	for _, h := range _hashers {
		names = append(names, h.Name)
	}
	sort.Strings(names)
	return names
}

// GetAllHashers returns a list of all available hashers.
func GetAllHashers() []Hasher {
	hashersList := make([]Hasher, 0, len(_hashers))
	for _, h := range _hashers {
		hashersList = append(hashersList, h)
	}
	return hashersList
}

// AddHasher adds a new hash algorithm to the list.
func AddHasher(h Hasher) {
	_hashers[h.Algorithm] = h
}

// init registers all hashers.
func init() {
	hashers := map[common.Algorithm]Hasher{
		common.STREEBOG256: {
			Algorithm: common.STREEBOG256,
			Name:      "streebog256",
			Extension: ".streebog256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				if key != "" {
					return "", fmt.Errorf("streebog256: keyed hashing not supported")
				}
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return streebog.New256(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64, // 32 bytes = 64 hex
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "streebog256sum" || strings.ToLower(filepath.Ext(fileName)) == ".streebog256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.STREEBOG512: {
			Algorithm: common.STREEBOG512,
			Name:      "streebog512",
			Extension: ".streebog512",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				if key != "" {
					return "", fmt.Errorf("streebog512: keyed hashing not supported")
				}
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return streebog.New512(), nil }, fileAndRangeSpec)
			},
			OutputLen: 128, // 64 bytes = 128 hex
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "streebog512sum" || strings.ToLower(filepath.Ext(fileName)) == ".streebog512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.CRC32: {
			Algorithm: common.CRC32,
			Name:      "crc32",
			Extension: ".crc32",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return crc32.NewIEEE(), nil }, fileAndRangeSpec)
			},
			OutputLen: 8,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "crc32sum" || strings.ToLower(filepath.Ext(fileName)) == ".crc32"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.ARGON2_SHA512: {
			Algorithm: common.ARGON2_SHA512,
			Name:      "argon2-sha512",
			Extension: ".argon2-sha512",
			Keyed:     true,
			Compute:   argon2.ComputeHash,
			OutputLen: 64,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("argon2-sha512 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "argon2-sha512sum" || strings.ToLower(filepath.Ext(fileName)) == ".argon2-sha512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.BSDCKSUM: {
			Algorithm: common.BSDCKSUM,
			Name:      "bsd-cksum",
			Extension: ".cksum",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) {
					return crc32.New(crc32.MakeTable(crc32.Castagnoli)), nil
				}, fileAndRangeSpec)
			},
			OutputLen: 8,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "cksum" || strings.ToLower(filepath.Ext(fileName)) == ".cksum"
			},
			ParseChecksumLine: bsdcksum.ParseChecksumLine,
		},
		common.BCRYPT_SHA512: {
			Algorithm: common.BCRYPT_SHA512,
			Name:      "bcrypt-sha512",
			Extension: ".bcrypt-sha512",
			Keyed:     true,
			Compute:   bcrypt.ComputeHash,
			OutputLen: 60,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("bcrypt-sha512 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "bcrypt-sha512sum" || strings.ToLower(filepath.Ext(fileName)) == ".bcrypt-sha512"
			},
			ParseChecksumLine: bcrypt.ParseChecksumLine,
		},
		common.MD4: {
			Algorithm: common.MD4,
			Name:      "md4",
			Extension: ".md4",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return md4.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 32,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "md4sum" || strings.ToLower(filepath.Ext(fileName)) == ".md4"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.MD5: {
			Algorithm: common.MD5,
			Name:      "md5",
			Extension: ".md5",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return md5.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 32,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "md5sum" || strings.ToLower(filepath.Base(fileName)) == "md5sums" || strings.ToLower(filepath.Ext(fileName)) == ".md5"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA1: {
			Algorithm: common.SHA1,
			Name:      "sha1",
			Extension: ".sha1",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha1.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 40,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				base := strings.ToLower(filepath.Base(fileName))
				ext := strings.ToLower(filepath.Ext(fileName))
				return base == "sha1sum" || base == "sha1sums" || base == "shasum" || ext == ".sha1"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA224: {
			Algorithm: common.SHA224,
			Name:      "sha224",
			Extension: ".sha224",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha256.New224(), nil }, fileAndRangeSpec)
			},
			OutputLen: 56,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha224sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha224"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA256: {
			Algorithm: common.SHA256,
			Name:      "sha256",
			Extension: ".sha256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha256.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha256sum" || strings.ToLower(filepath.Base(fileName)) == "sha256sums" || strings.ToLower(filepath.Ext(fileName)) == ".sha256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA384: {
			Algorithm: common.SHA384,
			Name:      "sha384",
			Extension: ".sha384",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha512.New384(), nil }, fileAndRangeSpec)
			},
			OutputLen: 96,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha384sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha384"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA512: {
			Algorithm: common.SHA512,
			Name:      "sha512",
			Extension: ".sha512",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha512.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 128,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha512sum" || strings.ToLower(filepath.Base(fileName)) == "sha512sums" || strings.ToLower(filepath.Ext(fileName)) == ".sha512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA512_224: {
			Algorithm: common.SHA512_224,
			Name:      "sha512-224",
			Extension: ".sha512-224",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha512.New512_224(), nil }, fileAndRangeSpec)
			},
			OutputLen: 56,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha512-224sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha512-224"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA512_256: {
			Algorithm: common.SHA512_256,
			Name:      "sha512-256",
			Extension: ".sha512-256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha512.New512_256(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha512-256sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha512-256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA3_224: {
			Algorithm: common.SHA3_224,
			Name:      "sha3-224",
			Extension: ".sha3-224",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha3.New224(), nil }, fileAndRangeSpec)
			},
			OutputLen: 56,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha3-224sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha3-224"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA3_256: {
			Algorithm: common.SHA3_256,
			Name:      "sha3-256",
			Extension: ".sha3-256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha3.New256(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha3-256sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha3-256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA3_384: {
			Algorithm: common.SHA3_384,
			Name:      "sha3-384",
			Extension: ".sha3-384",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha3.New384(), nil }, fileAndRangeSpec)
			},
			OutputLen: 96,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha3-384sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha3-384"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHA3_512: {
			Algorithm: common.SHA3_512,
			Name:      "sha3-512",
			Extension: ".sha3-512",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha3.New512(), nil }, fileAndRangeSpec)
			},
			OutputLen: 128,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sha3-512sum" || strings.ToLower(filepath.Ext(fileName)) == ".sha3-512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.KECCAK256: {
			Algorithm: common.KECCAK256,
			Name:      "keccak256",
			Extension: ".keccak256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha3.NewLegacyKeccak256(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "keccak256sum" || strings.ToLower(filepath.Ext(fileName)) == ".keccak256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHAKE128: {
			Algorithm: common.SHAKE128,
			Name:      "shake128",
			Extension: ".shake128",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				if key != "" {
					return "", fmt.Errorf("shake128: keyed hashing not supported")
				}
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha3.NewShake128(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "shake128sum" || strings.ToLower(filepath.Ext(fileName)) == ".shake128"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SHAKE256: {
			Algorithm: common.SHAKE256,
			Name:      "shake256",
			Extension: ".shake256",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				if key != "" {
					return "", fmt.Errorf("shake256: keyed hashing not supported")
				}
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sha3.NewShake256(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "shake256sum" || strings.ToLower(filepath.Ext(fileName)) == ".shake256"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.RIPEMD160: {
			Algorithm: common.RIPEMD160,
			Name:      "ripemd160",
			Extension: ".ripemd160",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return ripemd160.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 40,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "ripemd160sum" || strings.ToLower(filepath.Ext(fileName)) == ".ripemd160"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.BLAKE2B: {
			Algorithm: common.BLAKE2B,
			Name:      "blake2b",
			Extension: ".blake2b",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) {
					h, err := blake2b.New256(nil)
					return h, err
				}, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "blake2bsum" || strings.ToLower(filepath.Ext(fileName)) == ".blake2b"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.BLAKE2S: {
			Algorithm: common.BLAKE2S,
			Name:      "blake2s",
			Extension: ".blake2s",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) {
					h, err := blake2s.New256(nil)
					return h, err
				}, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "blake2ssum" || strings.ToLower(filepath.Ext(fileName)) == ".blake2s"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.BLAKE3: {
			Algorithm: common.BLAKE3,
			Name:      "blake3",
			Extension: ".blake3",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return blake3.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "blake3sum" || strings.ToLower(filepath.Ext(fileName)) == ".blake3"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.HMACMD5: {
			Algorithm: common.HMACMD5,
			Name:      "hmac-md5",
			Extension: ".hmac-md5",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(md5.New, []byte(key)), nil
				}, fileAndRangeSpec)
			},
			OutputLen: 32,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("hmac-md5 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "hmac-md5sum" || strings.ToLower(filepath.Ext(fileName)) == ".hmac-md5"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.HMACSHA1: {
			Algorithm: common.HMACSHA1,
			Name:      "hmac-sha1",
			Extension: ".hmac-sha1",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(sha1.New, []byte(key)), nil
				}, fileAndRangeSpec)
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
			Algorithm: common.HMACSHA256,
			Name:      "hmac-sha256",
			Extension: ".hmac-sha256",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(sha256.New, []byte(key)), nil
				}, fileAndRangeSpec)
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
			Algorithm: common.HMACSHA512,
			Name:      "hmac-sha512",
			Extension: ".hmac-sha512",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(sha512.New, []byte(key)), nil
				}, fileAndRangeSpec)
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
		common.HMACRIPEMD160: {
			Algorithm: common.HMACRIPEMD160,
			Name:      "hmac-ripemd160",
			Extension: ".hmac-ripemd160",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(key string) (hash.Hash, error) {
					return hmac.New(ripemd160.New, []byte(key)), nil
				}, fileAndRangeSpec)
			},
			OutputLen: 40,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("hmac-ripemd160 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "hmac-ripemd160sum" || strings.ToLower(filepath.Ext(fileName)) == ".hmac-ripemd160"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.HMACBLAKE2B: {
			Algorithm: common.HMACBLAKE2B,
			Name:      "hmac-blake2b",
			Extension: ".hmac-blake2b",
			Keyed:     true,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(key string) (hash.Hash, error) {
					h, err := blake2b.New256([]byte(key))
					return h, err
				}, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("hmac-blake2b requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "hmac-blake2bsum" || strings.ToLower(filepath.Ext(fileName)) == ".hmac-blake2b"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.ADLER32: {
			Algorithm: common.ADLER32,
			Name:      "adler32",
			Extension: ".adler32",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return adler32.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 8,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "adler32sum" || strings.ToLower(filepath.Ext(fileName)) == ".adler32"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.CHACHA20POLY1305: {
			Algorithm: common.CHACHA20POLY1305,
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
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.XXHASH: {
			Algorithm: common.XXHASH,
			Name:      "xxhash",
			Extension: ".xxhash",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return xxhash.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 16,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "xxhashsum" || strings.ToLower(filepath.Ext(fileName)) == ".xxhash"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SIPHASH: {
			Algorithm: common.SIPHASH,
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
			Algorithm: common.CITYHASH,
			Name:      "cityhash",
			Extension: ".cityhash",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return cityhash.New64(), nil }, fileAndRangeSpec)
			},
			OutputLen: 16,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "cityhashsum" || strings.ToLower(filepath.Ext(fileName)) == ".cityhash"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.KANGAROOTWELVE: {
			Algorithm: common.KANGAROOTWELVE,
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
		common.SM3: {
			Algorithm: common.SM3,
			Name:      "sm3",
			Extension: ".sm3",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return sm3.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 64,
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "sm3sum" || strings.ToLower(filepath.Ext(fileName)) == ".sm3"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.TTH: {
			Algorithm: common.TTH,
			Name:      "tth",
			Extension: ".tth",
			Keyed:     false,
			Compute:   tth.ComputeHash,
			OutputLen: 48, // 24 bytes = 48 hex
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "tthsum" || strings.ToLower(filepath.Ext(fileName)) == ".tth"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.PBKDF2_SHA512: {
			Algorithm: common.PBKDF2_SHA512,
			Name:      "pbkdf2-sha512",
			Extension: ".pbkdf2-sha512",
			Keyed:     true,
			Compute:   pbkdf2.ComputeHash,
			OutputLen: 128,
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("pbkdf2-sha512 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "pbkdf2-sha512sum" || strings.ToLower(filepath.Ext(fileName)) == ".pbkdf2-sha512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SCRYPT_SHA512: {
			Algorithm: common.SCRYPT_SHA512,
			Name:      "scrypt-sha512",
			Extension: ".scrypt-sha512",
			Keyed:     true,
			Compute:   scrypt.ComputeHash,
			OutputLen: 128, // 64 bytes = 128 hex
			Validate: func(key string) error {
				if key == "" {
					return fmt.Errorf("scrypt-sha512 requires a key")
				}
				return nil
			},
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "scrypt-sha512sum" || strings.ToLower(filepath.Ext(fileName)) == ".scrypt-sha512"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.SSDEEP: {
			Algorithm: common.SSDEEP,
			Name:      "ssdeep",
			Extension: ".ssdeep",
			Keyed:     false,
			Compute:   ssdeep.ComputeHash,
			OutputLen: 128, // Approximate max length of ssdeep hash
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "ssdeepsum" || strings.ToLower(filepath.Ext(fileName)) == ".ssdeep"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
		common.WHIRLPOOL: {
			Algorithm: common.WHIRLPOOL,
			Name:      "whirlpool",
			Extension: ".whirlpool",
			Keyed:     false,
			Compute: func(reader io.Reader, key string, fileAndRangeSpec common.FileAndRangeSpec) (string, error) {
				return std.ComputeHash(reader, key, func(_ string) (hash.Hash, error) { return whirlpool.New(), nil }, fileAndRangeSpec)
			},
			OutputLen: 128, // 64 bytes = 128 hex
			Validate:  func(_ string) error { return nil },
			AcceptsFile: func(fileName string) bool {
				return strings.ToLower(filepath.Base(fileName)) == "whirlpoolsum" || strings.ToLower(filepath.Ext(fileName)) == ".whirlpool"
			},
			ParseChecksumLine: std.ParseChecksumLine,
		},
	}

	for _, h := range hashers {
		AddHasher(h)
	}
}
