package std

import (
	"encoding/hex"
	"io"
	"os"
)

func Compute(file *os.File, rs RangeSpec, key string) (string, error) {
	hashFunc, err := getHasherByName(file.Name()).hashFunc(key)
	if err != nil {
		return "", err
	}

	if rs.end != -1 || rs.start != 0 {
		if rs.isPercent {
			fileInfo, err := file.Stat()
			if err != nil {
				return "", err
			}
			fileSize := fileInfo.Size()
			rs.start = int64(float64(fileSize) * float64(rs.start) / 10000)
			if rs.end != -1 {
				rs.end = int64(float64(fileSize) * float64(rs.end) / 10000)
			}
		}
		if _, err := file.Seek(rs.start, io.SeekStart); err != nil {
			return "", err
		}
		if rs.end != -1 {
			hashFunc = io.LimitReader(hashFunc, rs.end-rs.start).(hash.Hash)
		}
	}

	_, err = io.Copy(hashFunc, file)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hashFunc.Sum(nil)), nil
}