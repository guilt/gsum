package file

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

// FileAndRangeSpec represents a file path with an optional byte or percent range.
type FileAndRangeSpec struct {
	FilePath  string
	Start     int64
	End       int64
	IsPercent bool
}

// CheckSumSpec represents a parsed checksum line, including hash value, file range, and expected byte count.
type CheckSumSpec struct {
	HashValue         string
	FileAndRange      FileAndRangeSpec
	ExpectedByteCount int64
}

// ParseChecksumLineFunc defines a function type for parsing a checksum line.
// ParseChecksumLineFunc defines a function type for parsing a checksum line into its components.
type ParseChecksumLineFunc func(line string) (hashValue string, fileAndRange FileAndRangeSpec, byteCount int64, err error)

// GetHashes loads all checksums from the provided hash files using the given parse function.
// GetHashes loads all checksums from the provided hash files using the given parse function.
// Returns a slice of CheckSumSpec for all successfully parsed lines.
func GetHashes(parseLine ParseChecksumLineFunc, hashFiles []string) ([]CheckSumSpec, error) {
	var checksums []CheckSumSpec
	for _, hashFile := range hashFiles {
		fh, err := os.Open(hashFile)
		if err != nil {
			return nil, fmt.Errorf("error opening hash file %s: %w", hashFile, err)
		}
		defer fh.Close()

		scanner := bufio.NewScanner(fh)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hashValue, fileAndRange, byteCount, err := parseLine(line)
			if err != nil {
				return nil, fmt.Errorf("invalid checksum line in %s: %q: %w", hashFile, line, err)
			}
			checksums = append(checksums, CheckSumSpec{
				HashValue:         hashValue,
				FileAndRange:      fileAndRange,
				ExpectedByteCount: byteCount,
			})
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading hash file %s: %w", hashFile, err)
		}
	}
	return checksums, nil
}

// String returns a string representation of the FileAndRangeSpec, including any range or percent info.
func (f *FileAndRangeSpec) String() string {
	if f.End == -1 && f.Start == 0 && !f.IsPercent {
		return f.FilePath
	}
	if f.IsPercent {
		startPercent := float64(f.Start) / 100
		endPercent := float64(f.End) / 100
		s := fmt.Sprintf("%.2f", startPercent)
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
		e := fmt.Sprintf("%.2f", endPercent)
		e = strings.TrimRight(e, "0")
		e = strings.TrimRight(e, ".")
		return fmt.Sprintf("%s#%s%%-%s%%", f.FilePath, s, e)
	}
	return fmt.Sprintf("%s#%d-%d", f.FilePath, f.Start, f.End)
}

// Parse populates the FileAndRangeSpec fields from a string of the form "file#start-end" or "file#start%-end%".
func (f *FileAndRangeSpec) Parse(s string) error {
	parts := strings.SplitN(s, "#", 2)
	f.FilePath = parts[0]
	f.Start = 0
	f.End = -1
	f.IsPercent = false

	if len(parts) == 1 {
		return nil
	}

	rangeSpec := parts[1]
	logger.Debugf("Parsing range spec: %s", rangeSpec)

	if strings.Contains(rangeSpec, "%") {
		if strings.Contains(rangeSpec, "-") {
			percentParts := strings.Split(rangeSpec, "-")
			if len(percentParts) != 2 {
				return fmt.Errorf("invalid range format: %s", rangeSpec)
			}
			start, err := parsePercent(percentParts[0])
			if err != nil {
				return fmt.Errorf("invalid start percent: %w", err)
			}
			end, err := parsePercent(percentParts[1])
			if err != nil {
				return fmt.Errorf("invalid end percent: %w", err)
			}
			if end <= start {
				return fmt.Errorf("invalid percentage range: %v-%v (end <= start)", start, end)
			}
			f.Start = int64(start * 100)
			f.End = int64(end * 100)
			f.IsPercent = true
		} else {
			percent, err := parsePercent(rangeSpec)
			if err != nil {
				return fmt.Errorf("invalid percentage: %w", err)
			}
			f.End = int64(percent * 100)
			f.IsPercent = true
		}
		logger.Debugf("Parsed percentage range: %d%%-%d%%", f.Start/100, f.End/100)
		return nil
	}

	if strings.Contains(rangeSpec, "-") {
		rangeParts := strings.Split(rangeSpec, "-")
		if len(rangeParts) != 2 {
			return fmt.Errorf("invalid range format: %s", rangeSpec)
		}
		start, err := parseInt64(rangeParts[0])
		if err != nil {
			return fmt.Errorf("invalid start range: %w", err)
		}
		var end int64 = -1
		if rangeParts[1] != "" {
			end, err = parseInt64(rangeParts[1])
			if err != nil {
				return fmt.Errorf("invalid end range: %w", err)
			}
		}
		if end != -1 && end <= start {
			return fmt.Errorf("invalid range: %d-%d", start, end)
		}
		f.Start = start
		f.End = end
	} else {
		count, err := parseInt64(rangeSpec)
		if err != nil || count <= 0 {
			return fmt.Errorf("invalid byte count: %s", rangeSpec)
		}
		f.End = count
	}

	logger.Debugf("Parsed byte range: %d-%d", f.Start, f.End)
	return nil
}

// ToBytes converts the FileAndRangeSpec's range (including percent) to absolute byte offsets for a file of the given size.
func (f FileAndRangeSpec) ToBytes(fileSize int64) (start, end int64, err error) {
	start = f.Start
	end = f.End
	if f.IsPercent {
		start = int64(float64(fileSize) * float64(f.Start) / 10000)
		if f.End == -1 {
			end = fileSize
		} else {
			end = int64(float64(fileSize) * float64(f.End) / 10000)
		}
	} else if f.End == -1 {
		end = fileSize
	}
	if start >= end || start < 0 || end <= 0 {
		return 0, 0, fmt.Errorf("%d-%d", start, end)
	}
	return start, end, nil
}

// ParseFilePath parses a file path with an optional byte or percent range.
func ParseFilePath(path string) (FileAndRangeSpec, error) {
	var f FileAndRangeSpec
	if err := f.Parse(path); err != nil {
		return FileAndRangeSpec{}, err
	}
	return f, nil
}

// parsePercent parses a percent string (e.g., "50%") and returns its value as a float64.
func parsePercent(s string) (float64, error) {
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

// parseInt64 parses a string as int64 and returns an error if invalid or negative.
func parseInt64(s string) (int64, error) {
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil || val < 0 {
		return 0, fmt.Errorf("invalid int64: %s", s)
	}
	return val, nil
}
