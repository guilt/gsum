package bsdcksum

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/log"
)

// logger is the package-level logger for debug and error messages.
var logger = log.NewLogger()

// ParseChecksumLine parses a checksum line for BSDCKSUM in the format "<hash> <byte_count> <file>".
func ParseChecksumLine(line string) (hashValue, filePath string, rs common.RangeSpec, err error) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		logger.Errorf("Invalid cksum format: line=%s", line)
		return "", "", common.RangeSpec{}, fmt.Errorf("invalid cksum format: %s", line)
	}
	hashValue = parts[0]
	count, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		logger.Errorf("Invalid byte count: count=%s, error=%v", parts[1], err)
		return "", "", common.RangeSpec{}, fmt.Errorf("invalid byte count: %s", parts[1])
	}
	filePath = strings.Join(parts[2:], " ")
	rs = common.RangeSpec{Start: 0, End: count}
	return hashValue, filePath, rs, nil
}
