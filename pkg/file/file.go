package file

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/log"
)

// logger is the package-level logger for debug and error messages.
var logger = log.NewLogger()

// ParseFilePath parses a file path with optional range spec (e.g., "file.txt#100-200", "file.txt#10%", "file.txt#10%-20%", "file.txt#100").
func ParseFilePath(path string) (filePath string, rs common.RangeSpec, err error) {
	parts := strings.SplitN(path, "#", 2)
	if len(parts) == 1 {
		return path, common.RangeSpec{Start: 0, End: -1}, nil
	}

	filePath = parts[0]
	rangeSpec := parts[1]
	logger.Debugf("Parsing range spec: %s", rangeSpec)

	// Check if range is percentage-based
	if strings.Contains(rangeSpec, "%") {
		if strings.Contains(rangeSpec, "-") {
			// Range like "10%-20%"
			percentParts := strings.Split(rangeSpec, "-")
			if len(percentParts) != 2 {
				logger.Errorf("Invalid range format: rangeSpec=%s", rangeSpec)
				return "", common.RangeSpec{}, fmt.Errorf("invalid range format: %s", rangeSpec)
			}

			startStr := strings.TrimSuffix(percentParts[0], "%")
			endStr := strings.TrimSuffix(percentParts[1], "%")

			start, err := strconv.ParseFloat(startStr, 64)
			if err != nil {
				logger.Errorf("Invalid start range: start=%s, error=%v", startStr, err)
				return "", common.RangeSpec{}, fmt.Errorf("invalid start range: %s", startStr)
			}
			end, err := strconv.ParseFloat(endStr, 64)
			if err != nil {
				logger.Errorf("Invalid end range: end=%s, error=%v", endStr, err)
				return "", common.RangeSpec{}, fmt.Errorf("invalid end range: %s", endStr)
			}

			// Validate percentage range
			if start < 0 || start > 100 || end <= start || end > 100 {
				logger.Errorf("Invalid percentage range: start=%s, end=%s, note=must be 0-100%%", startStr, endStr)
				return "", common.RangeSpec{}, fmt.Errorf("invalid percentage range: %s-%s (must be 0-100%%)", startStr, endStr)
			}

			rs = common.RangeSpec{
				Start:     int64(start * 100), // Store as basis points
				End:       int64(end * 100),
				IsPercent: true,
			}
		} else {
			// Single percentage like "10%"
			percentStr := strings.TrimSuffix(rangeSpec, "%")
			percent, err := strconv.ParseFloat(percentStr, 64)
			if err != nil {
				logger.Errorf("Invalid percentage: percent=%s, error=%v", percentStr, err)
				return "", common.RangeSpec{}, fmt.Errorf("invalid percentage: %s", percentStr)
			}
			if percent <= 0 || percent > 100 {
				logger.Errorf("Invalid percentage: percent=%s, note=must be 0-100%%", percentStr)
				return "", common.RangeSpec{}, fmt.Errorf("invalid percentage: %s (must be 0-100%%)", percentStr)
			}

			rs = common.RangeSpec{
				Start:     0,
				End:       int64(percent * 100),
				IsPercent: true,
			}
		}
		logger.Debugf("Parsed percentage range: %d%%-%d%%", rs.Start/100, rs.End/100)
		return filePath, rs, nil
	}

	// Handle byte-based range
	if strings.Contains(rangeSpec, "-") {
		// Range like "100-200"
		rangeParts := strings.Split(rangeSpec, "-")
		if len(rangeParts) != 2 {
			logger.Errorf("Invalid range format: rangeSpec=%s", rangeSpec)
			return "", common.RangeSpec{}, fmt.Errorf("invalid range format: %s", rangeSpec)
		}

		start, err := strconv.ParseInt(rangeParts[0], 10, 64)
		if err != nil {
			logger.Errorf("Invalid start range: start=%s, error=%v", rangeParts[0], err)
			return "", common.RangeSpec{}, fmt.Errorf("invalid start range: %s", rangeParts[0])
		}
		end, err := strconv.ParseInt(rangeParts[1], 10, 64)
		if err != nil {
			if rangeParts[1] == "" {
				end = -1
			} else {
				logger.Errorf("Invalid end range: end=%s, error=%v", rangeParts[1], err)
				return "", common.RangeSpec{}, fmt.Errorf("invalid end range: %s", rangeParts[1])
			}
		}

		if start < 0 || (end != -1 && end <= start) {
			logger.Errorf("Invalid range: start=%d, end=%d", start, end)
			return "", common.RangeSpec{}, fmt.Errorf("invalid range: %d-%d", start, end)
		}

		rs = common.RangeSpec{
			Start:     start,
			End:       end,
			IsPercent: false,
		}
	} else {
		// Single byte count like "100"
		count, err := strconv.ParseInt(rangeSpec, 10, 64)
		if err != nil {
			logger.Errorf("Invalid byte count: count=%s, error=%v", rangeSpec, err)
			return "", common.RangeSpec{}, fmt.Errorf("invalid byte count: %s", rangeSpec)
		}
		if count <= 0 {
			logger.Errorf("Invalid byte count: count=%d", count)
			return "", common.RangeSpec{}, fmt.Errorf("invalid byte count: %d", count)
		}

		rs = common.RangeSpec{
			Start:     0,
			End:       count,
			IsPercent: false,
		}
	}

	logger.Debugf("Parsed byte range: %d-%d", rs.Start, rs.End)
	return filePath, rs, nil
}
