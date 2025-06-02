package ktwelve

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/mimoo/GoKangarooTwelve/K12"

	"github.com/guilt/gsum/pkg/common"
)

// Compute calculates the KangarooTwelve hash for the given reader, respecting the RangeSpec.
func Compute(reader io.Reader, rs common.RangeSpec, key string) (string, error) {
	if rs.Start != 0 || rs.End != -1 {
		file, ok := reader.(*common.LifecycleReader).Reader.(*os.File)
		if !ok {
			return "", fmt.Errorf("range-based hashing requires a file reader")
		}

		var start, end int64
		if rs.IsPercent {
			fileInfo, err := file.Stat()
			if err != nil {
				return "", fmt.Errorf("cannot stat file: %v", err)
			}
			fileSize := fileInfo.Size()
			start = int64(float64(fileSize) * float64(rs.Start) / 10000)
			if rs.End == -1 {
				end = fileSize
			} else {
				end = int64(float64(fileSize) * float64(rs.End) / 10000)
			}
		} else {
			start = rs.Start
			if rs.End == -1 {
				fileInfo, err := file.Stat()
				if err != nil {
					return "", fmt.Errorf("cannot stat file: %v", err)
				}
				end = fileInfo.Size()
			} else {
				end = rs.End
			}
		}

		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("failed to seek to start position: %w", err)
		}

		reader = io.LimitReader(file, end-start)
	}

	// Read all data to avoid io.Writer pointer receiver issue
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read data: %w", err)
	}

	hasher := K12.NewK12(nil) // Returns *K12.treeState
	if _, err := hasher.Write(data); err != nil {
		return "", fmt.Errorf("failed to hash data: %w", err)
	}

	hash := make([]byte, 32)
	if _, err := hasher.Read(hash); err != nil {
		return "", fmt.Errorf("failed to read hash: %w", err)
	}

	return hex.EncodeToString(hash), nil
}
