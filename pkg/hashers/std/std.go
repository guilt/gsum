package std

import (
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

// PrepareRangeReader returns an io.Reader limited to the specified range in rs.
// If rs.Start/End are zero or -1, it returns the original reader.
func PrepareRangeReader(reader io.Reader, rs common.FileAndRangeSpec) (io.Reader, error) {
	var r io.Reader = reader

	// Only handle if range is specified
	start, end, err := rs.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("invalid range: %v", err)
	}

	if start > 0 {
		if seeker, ok := reader.(io.Seeker); ok {
			_, err := seeker.Seek(start, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("seeking to start offset %d: %w", start, err)
			}
			// Do NOT assign seeker to r, since io.Seeker does not implement io.Reader
			// Just continue using the original reader after seeking
		} else {
			// If not seekable, skip bytes
			_, err := io.CopyN(io.Discard, r, start)
			if err != nil {
				return nil, fmt.Errorf("skipping to start offset %d: %w", start, err)
			}
		}
	}
	if end > start {
		length := end - start
		if length <= 0 {
			return nil, fmt.Errorf("invalid range: start=%d, end=%d", start, end)
		}
		r = io.LimitReader(r, length)
	}
	return r, nil
}

func ComputeHash(reader io.Reader, key string, hashFunc func(key string) (hash.Hash, error), rs common.FileAndRangeSpec) (string, error) {
	r, err := PrepareRangeReader(reader, rs)
	if err != nil {
		return "", err
	}

	h, err := hashFunc(key)
	if err != nil {
		return "", fmt.Errorf("cannot create hash: %s", err)
	}

	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing error: %s", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ParseChecksumLine(line string) (hashValue string, fileAndRange common.FileAndRangeSpec, byteCount int64, err error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid checksum: %s", line)
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
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file: %s", filePath)
	}
	// Debug logging removed (was: logger.Debugf("Parsed checksum: hash=%s, file=%s", hashValue, filePath))
	return hashValue, fileAndRange, byteCount, nil
}

// BytesToHex returns the hex encoding of a byte slice.
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}
