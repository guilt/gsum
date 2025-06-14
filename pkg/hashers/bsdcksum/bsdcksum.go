package bsdcksum

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/common"
)

func ParseChecksumLine(line string) (hashValue string, fileAndRange common.FileAndRangeSpec, byteCount int64, err error) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		// Error logging removed (was: logger.Errorf("Invalid cksum format: line=%s", line))
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid cksum format: %s", line)
	}
	hashValue = parts[0]
	count, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		// Error logging removed (was: logger.Errorf("Invalid byte count: count=%s", parts[1]))
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid byte count: %s", parts[1])
	}
	filePath := strings.Join(parts[2:], " ")
	if err := fileAndRange.Parse(filePath); err != nil {
		// Error logging removed (was: logger.Errorf("Invalid file path: path=%s", filePath))
		return "", common.FileAndRangeSpec{}, 0, fmt.Errorf("invalid file path: %s", filePath)
	}
	fileAndRange.End = count
	return hashValue, fileAndRange, count, nil
}
