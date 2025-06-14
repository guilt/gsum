// Package common provides shared types and helpers for file range, lifecycle, and algorithms.
package common

import (
	"fmt"
	"strconv"
	"strings"
)

// FormatPercent formats a percent value as a string without unnecessary trailing zeros (e.g. 95, 95.5)
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
