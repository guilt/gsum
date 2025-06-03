package file

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

type FileAndRangeSpec struct {
	FilePath  string
	Start     int64
	End       int64
	IsPercent bool
}

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
			startStr := strings.TrimSuffix(percentParts[0], "%")
			endStr := strings.TrimSuffix(percentParts[1], "%")
			start, err := strconv.ParseFloat(startStr, 64)
			if err != nil {
				return fmt.Errorf("invalid start range: %s", startStr)
			}
			end, err := strconv.ParseFloat(endStr, 64)
			if err != nil {
				return fmt.Errorf("invalid end range: %s", endStr)
			}
			if start < 0 || start > 100 || end <= start || end > 100 {
				return fmt.Errorf("invalid percentage range: %s-%s (must be 0-100%%)", startStr, endStr)
			}
			f.Start = int64(start * 100)
			f.End = int64(end * 100)
			f.IsPercent = true
		} else {
			percentStr := strings.TrimSuffix(rangeSpec, "%")
			percent, err := strconv.ParseFloat(percentStr, 64)
			if err != nil || percent <= 0 || percent > 100 {
				return fmt.Errorf("invalid percentage: %s (must be 0-100%%)", percentStr)
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
		start, err := strconv.ParseInt(rangeParts[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid start range: %s", rangeParts[0])
		}
		var end int64 = -1
		if rangeParts[1] != "" {
			end, err = strconv.ParseInt(rangeParts[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid end range: %s", rangeParts[1])
			}
		}
		if start < 0 || (end != -1 && end <= start) {
			return fmt.Errorf("invalid range: %d-%d", start, end)
		}
		f.Start = start
		f.End = end
	} else {
		count, err := strconv.ParseInt(rangeSpec, 10, 64)
		if err != nil || count <= 0 {
			return fmt.Errorf("invalid byte count: %s", rangeSpec)
		}
		f.End = count
	}

	logger.Debugf("Parsed byte range: %d-%d", f.Start, f.End)
	return nil
}

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

func ParseFilePath(path string) (FileAndRangeSpec, error) {
	var f FileAndRangeSpec
	if err := f.Parse(path); err != nil {
		logger.Errorf("Invalid file path: %s, error=%s", path, err)
		return FileAndRangeSpec{}, err
	}
	return f, nil
}

func ParsePercent(s string) (float64, error) {
	if s == "" {
		return 0, fmt.Errorf("increment percentage cannot be empty")
	}
	s = strings.TrimSuffix(s, "%")
	percent, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid increment percentage: %s", s)
	}
	if percent <= 0 || percent >= 100 {
		return 0, fmt.Errorf("increment percentage must be between 0%% and 100%%: %s", s)
	}
	return percent, nil
}
