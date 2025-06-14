package common

import (
	"fmt"
	"math"
	"os"
	"strings"
)

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
// If already percent, returns a copy.
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
// Handles -1 for start/end.
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

// String returns a string representation of the FileAndRangeSpec, including any range or percent info.
func (rs *FileAndRangeSpec) String() string {
	if rs.IsPercent {
		return fmt.Sprintf("%s#%d%%-%d%%", rs.FilePath, rs.Start/100, rs.End/100)
	}
	if rs.Start == 0 && (rs.End == -1 || rs.End == 0) {
		return rs.FilePath
	}
	if rs.End == -1 {
		return fmt.Sprintf("%s#%d-", rs.FilePath, rs.Start)
	}
	return fmt.Sprintf("%s#%d-%d", rs.FilePath, rs.Start, rs.End)
}

// Parse populates the FileAndRangeSpec fields from a string of the form "file#start-end" or "file#start%-end%".
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

// GetRangeSize returns the size of the range for this FileAndRangeSpec.
// If End == -1, it uses fileSize as the end.
func (rs *FileAndRangeSpec) GetRangeSize(fileSize int64) int64 {
	start, end := rs.getStartEndBytes(fileSize)
	return end - start
}

// IncrementalRanges generates a slice of FileAndRangeSpec representing incremental percent-based ranges for a file.
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
