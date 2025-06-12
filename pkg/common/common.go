package common

import (
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

// Algorithm represents a hash algorithm.
type Algorithm int

// Constants for hash algorithms.
const (
	CRC32 Algorithm = iota
	BSDCKSUM
	MD4
	MD5
	SHA1
	SHA256
	SHA512
	SHA3_256
	SHAKE128
	SHAKE256
	BLAKE2B
	BLAKE3
	HMACSHA1
	HMACSHA256
	HMACSHA512
	CHACHA20POLY1305
	XXHASH
	SIPHASH
	CITYHASH
	KANGAROOTWELVE
	STREEBOG256
	STREEBOG512
	SHA224
	SHA384
	SHA512_224
	SHA512_256
	SHA3_224
	SHA3_384
	SHA3_512
	RIPEMD160
	HMACMD5
	HMACRIPEMD160
	HMACBLAKE2B
	BLAKE2S
	ADLER32
	BCRYPT_SHA512
	ARGON2_SHA512
	SM3
	TTH
	KECCAK256
	PBKDF2_SHA512
	SCRYPT_SHA512
	SSDEEP
	WHIRLPOOL
)

// FormatPercent formats a percent value as a string without
// unnecessary trailing zeros (e.g. 95, 95.5)
func FormatPercent(p float64) string {
	str := fmt.Sprintf("%.15g", p)
	str = strings.TrimSuffix(str, ".0")
	return str
}

// ParsePercent parses a percent string (e.g., "50%") and returns its value as a float64.
func ParsePercent(s string) (float64, error) {
	if s == "" {
		return 0, fmt.Errorf("percentage cannot be empty")
	}
	s = strings.TrimSuffix(s, "%")
	percent, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid percentage: %s", s)
	}
	if percent < 0 || percent > 100 {
		return 0, fmt.Errorf("percentage must be in (0,100]: %s", s)
	}
	return percent, nil
}

// ParseInt64 parses a string as int64 and returns an error if invalid or negative.
func ParseInt64(s string) (int64, error) {
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil || val < 0 {
		return 0, fmt.Errorf("invalid int64: %s", s)
	}
	return val, nil
}

// FileAndRangeSpec represents a file path with an optional byte or percent range.
// FileAndRangeSpec represents a file path with an optional byte or percent range.
// When IsPercent is true, Start and End are stored as basis points (0-10000), where 10000 = 100%.
type FileAndRangeSpec struct {
	FilePath string
	// Start and End are stored as basis points (0-10000) when IsPercent is true.
	Start     int64
	End       int64
	IsPercent bool
}

// LessFileAndRange returns true if a comes before b by FilePath, then Start, then End.
func LessFileAndRange(a, b FileAndRangeSpec) bool {
	if a.FilePath != b.FilePath {
		return a.FilePath < b.FilePath
	}
	if a.Start != b.Start {
		return a.Start < b.Start
	}
	return a.End < b.End
}

// ToPercentRange converts a byte-based FileAndRangeSpec to a percent-based one (basis points), given the file size.
// If already percent, returns a copy. Debug output is printed.
func (rs *FileAndRangeSpec) ToPercentRange(fileSize int64) FileAndRangeSpec {
	if rs.IsPercent {
		return *rs
	}
	start := float64(rs.Start)
	end := float64(rs.End)
	if rs.Start == -1 {
		start = 0
	}
	if rs.End == -1 || rs.End > fileSize {
		end = float64(fileSize)
	}
	percentStart := int64((start / float64(fileSize)) * 10000)
	percentEnd := int64((end / float64(fileSize)) * 10000)
	converted := FileAndRangeSpec{
		FilePath:  rs.FilePath,
		Start:     percentStart,
		End:       percentEnd,
		IsPercent: true,
	}
	return converted
}

// getStartEndBytes returns the absolute byte offsets for the FileAndRangeSpec, regardless of IsPercent.
// Handles -1 for start/end, and prints debug output.
func (rs *FileAndRangeSpec) getStartEndBytes(fileSize int64) (int64, int64) {
	var start, end int64
	if rs.IsPercent {
		if rs.Start == -1 {
			start = 0
		} else {
			start = int64(float64(fileSize) * float64(rs.Start) / 10000)
		}
		if rs.End == -1 {
			end = fileSize
		} else {
			end = int64(float64(fileSize) * float64(rs.End) / 10000)
		}
	} else {
		if rs.Start == -1 {
			start = 0
		} else {
			start = rs.Start
		}
		if rs.End == -1 {
			end = fileSize
		} else {
			end = rs.End
		}
	}
	return start, end
}

// ToAbsoluteRange converts a percent-based FileAndRangeSpec to a byte-based one, given the file size.
// If already absolute, returns a copy.
func (rs *FileAndRangeSpec) ToAbsoluteRange(fileSize int64) FileAndRangeSpec {
	if !rs.IsPercent {
		return *rs
	}
	start, end := rs.getStartEndBytes(fileSize)
	converted := FileAndRangeSpec{
		FilePath:  rs.FilePath,
		Start:     start,
		End:       end,
		IsPercent: false,
	}
	return converted
}

// GetRangeSize returns the size of the range for this FileAndRangeSpec.
// If End == -1, it uses fileSize as the end.
func (rs *FileAndRangeSpec) GetRangeSize(fileSize int64) int64 {
	start, end := rs.getStartEndBytes(fileSize)
	return end - start
}

// String returns a string representation of the FileAndRangeSpec, including any range or percent info.
// When IsPercent is true, Start and End are stored as basis points (0-10000).
func (rs *FileAndRangeSpec) String() string {
	if rs.Start == -1 && rs.End == -1 || rs.Start == 0 && rs.End == -1 {
		return rs.FilePath
	}
	if rs.IsPercent {
		startPercent := float64(rs.Start) / 100.0
		endPercent := float64(rs.End) / 100.0
		if rs.Start == -1 {
			return fmt.Sprintf("%s#-%s%%", rs.FilePath, FormatPercent(endPercent))
		}
		if rs.End == -1 {
			return fmt.Sprintf("%s#%s%%-", rs.FilePath, FormatPercent(startPercent))
		}
		return fmt.Sprintf("%s#%s%%-%s%%", rs.FilePath, FormatPercent(startPercent), FormatPercent(endPercent))
	}
	if rs.Start == -1 {
		return fmt.Sprintf("%s#-%d", rs.FilePath, rs.End)
	}
	if rs.End == -1 {
		return fmt.Sprintf("%s#%d-", rs.FilePath, rs.Start)
	}
	return fmt.Sprintf("%s#%d-%d", rs.FilePath, rs.Start, rs.End)
}

// Parse populates the FileAndRangeSpec fields from a string of the form "file#start-end" or "file#start%-end%".
// When IsPercent is true, Start and End are stored as basis points (0-10000).
func (rs *FileAndRangeSpec) Parse(s string) error {
	parts := strings.SplitN(s, "#", 2)
	rs.FilePath = parts[0]
	rs.Start = 0
	rs.End = -1
	rs.IsPercent = false

	if len(parts) == 1 {
		return nil
	}

	rangeSpec := parts[1]

	if strings.Contains(rangeSpec, "%") {
		if strings.Contains(rangeSpec, "-") {
			percentParts := strings.Split(rangeSpec, "-")
			if len(percentParts) != 2 {
				return fmt.Errorf("invalid range format: %s", rangeSpec)
			}
			start, err := ParsePercent(percentParts[0])
			if err != nil {
				return fmt.Errorf("invalid start percent: %w", err)
			}
			end, err := ParsePercent(percentParts[1])
			if err != nil {
				return fmt.Errorf("invalid end percent: %w", err)
			}
			if end <= start {
				return fmt.Errorf("invalid percentage range: %v-%v (end <= start)", start, end)
			}
			rs.Start = int64(start * 100)
			rs.End = int64(end * 100)
			rs.IsPercent = true
		} else {
			percent, err := ParsePercent(rangeSpec)
			if err != nil {
				return fmt.Errorf("invalid percentage: %w", err)
			}
			rs.End = int64(percent * 100)
			rs.IsPercent = true
		}
		return nil
	}

	if strings.Contains(rangeSpec, "-") {
		rangeParts := strings.Split(rangeSpec, "-")
		if len(rangeParts) != 2 {
			return fmt.Errorf("invalid range format: %s", rangeSpec)
		}
		start, err := ParseInt64(rangeParts[0])
		if err != nil {
			return fmt.Errorf("invalid start range: %w", err)
		}
		var end int64 = -1
		if rangeParts[1] != "" {
			end, err = ParseInt64(rangeParts[1])
			if err != nil {
				return fmt.Errorf("invalid end range: %w", err)
			}
		}
		if end != -1 && end <= start {
			return fmt.Errorf("invalid range: %d-%d", start, end)
		}
		rs.Start = start
		rs.End = end
	} else {
		count, err := ParseInt64(rangeSpec)
		if err != nil || count <= 0 {
			return fmt.Errorf("invalid byte count: %s", rangeSpec)
		}
		rs.End = count
	}

	return nil
}

// ToBytes converts the FileAndRangeSpec's range (including percent) to absolute byte offsets for a file of the given size.
// When IsPercent is true, Start and End are stored as basis points (0-10000).
func (rs *FileAndRangeSpec) ToBytes() (start, end int64, err error) {
	fileInfo, err := os.Stat(rs.FilePath)
	if err != nil {
		return 0, 0, err
	}
	fileSize := fileInfo.Size()
	start, end = rs.getStartEndBytes(fileSize)
	if start > end {
		return 0, 0, fmt.Errorf("invalid range: %d-%d", start, end)
	}
	return start, end, nil
}

// IncrementalRanges generates a slice of FileAndRangeSpec representing incremental percent-based ranges for a file.
// filePath: the path to the file.
// fileSize: the size of the file in bytes.
// percent: the percentage increment (e.g., 10 for 10%).
// Returns a slice of FileAndRangeSpec, one for each increment.
// When IsPercent is true, Start and End are stored as basis points (0-10000).
func IncrementalRanges(filePath string, fileSize int64, percent float64) []FileAndRangeSpec {
	if percent <= 0 || percent > 100 {
		return nil
	}
	numIncrements := int(math.Ceil(100 / percent))
	result := make([]FileAndRangeSpec, 0, numIncrements)
	for i := 0; i < numIncrements; i++ {
		startPercent := float64(i) * percent
		endPercent := startPercent + percent
		if endPercent > 100 {
			endPercent = 100
		}
		// Store percent*100 as per FileAndRangeSpec convention for IsPercent
		start := int64(startPercent * 100)
		end := int64(endPercent * 100)
		rs := FileAndRangeSpec{
			FilePath:  filePath,
			Start:     start,
			End:       end,
			IsPercent: true,
		}
		result = append(result, rs)
	}
	return result
}

// FileLifecycle represents a lifecycle of a file being processed.
type FileLifecycle struct {
	OnStart func(offset1, offset2 int64)
	OnChunk func(bytes int64)
	OnEnd   func()
}

// LifecycleReader is a reader that tracks the lifecycle of a file being processed.
type LifecycleReader struct {
	Reader    io.Reader
	Lifecycle FileLifecycle
}

// Read implements io.Reader.
func (lr *LifecycleReader) Read(p []byte) (n int, err error) {
	n, err = lr.Reader.Read(p)
	if n > 0 {
		lr.Lifecycle.OnChunk(int64(n))
	}
	return n, err
}
