package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guilt/gsum/pkg/common"
	gfile "github.com/guilt/gsum/pkg/file"
	ggpg "github.com/guilt/gsum/pkg/gpg"
	_ "github.com/guilt/gsum/pkg/hashers"
	glc "github.com/guilt/gsum/pkg/lifecycle"
	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

type config struct {
	algo      string
	verify    string
	gpg       string
	key       string
	increment string
	output    string
	progress  bool
	comment   bool
	args      []string
}

func main() {
	cfg := parseArgs()
	hasher, err := common.GetHasher(cfg.algo)
	if err != nil {
		logger.Fatalf("Invalid algorithm: %s", cfg.algo)
	}
	if err := hasher.Validate(cfg.key); err != nil {
		logger.Fatalf("Validation error: %s", err)
	}

	progressFunc := glc.MakeDefaultLifecycle
	if cfg.progress {
		progressFunc = glc.MakeProgressBars
	}

	inputFiles := getInputFiles(cfg, cfg.verify != "")
	if cfg.verify != "" {
		verifyFileHashes(hasher, inputFiles, progressFunc, cfg)
		if cfg.gpg != "" {
			ggpg.VerifyGPG(cfg.verify, cfg.gpg)
		}
		return
	}

	hashFiles := getOutputHashFiles(hasher, cfg)
	generateFileHashes(hasher, inputFiles, hashFiles, cfg, progressFunc)
	if cfg.gpg != "" {
		ggpg.GenerateGPG(hashFiles, cfg.gpg)
	}
}

func parseArgs() *config {
	defaultAlgo := common.GetDefaultHashAlgorithm()
	algo := flag.String("algo", defaultAlgo, "Hash algorithm ("+strings.Join(common.GetAllHasherNames(), ", ")+")")
	verify := flag.String("verify", "", "Verify hash or checksum file")
	gpg := flag.String("gpg", "", "GPG signature file")
	key := flag.String("key", "", "Key for keyed hashing")
	increment := flag.String("increment", "", "Incremental hashes (e.g., 10%)")
	output := flag.String("output", "", "Output file for hashes")
	progress := flag.Bool("progress", false, "Show progress bar")
	comment := flag.Bool("comment", false, "Include checksum file comments")
	flag.Parse()

	cfg := &config{
		algo:      strings.TrimSpace(*algo),
		verify:    *verify,
		gpg:       *gpg,
		key:       *key,
		increment: *increment,
		output:    *output,
		progress:  *progress,
		comment:   *comment,
		args:      flag.Args(),
	}

	if len(cfg.args) == 0 {
		logger.Fatalf("No input files provided")
	}
	if cfg.algo == "" {
		logger.Fatalf("Algorithm required")
	}
	return cfg
}

func getInputFiles(cfg *config, isVerify bool) []string {
	if isVerify {
		f, err := gfile.ParseFilePath(cfg.args[len(cfg.args)-1])
		if err != nil {
			logger.Fatalf("Invalid file path: %s", cfg.args[len(cfg.args)-1])
		}
		return []string{f.FilePath}
	}

	var files []string
	for _, arg := range cfg.args {
		f, err := gfile.ParseFilePath(arg)
		if err != nil {
			logger.Fatalf("Invalid file path: %s", arg)
		}
		files = append(files, f.FilePath)
	}
	return files
}

func getOutputHashFiles(hasher common.Hasher, cfg *config) []string {
	if cfg.output != "" {
		return []string{cfg.output}
	}
	inputFiles := getInputFiles(cfg, false)
	var hashFiles []string
	for _, file := range inputFiles {
		hashFiles = append(hashFiles, file+hasher.Extension)
	}
	return hashFiles
}

func verifyFileHashes(hasher common.Hasher, inputFiles []string, progressFunc func(string, int64, int64, int64) common.FileLifecycle, cfg *config) {
	for _, filePath := range inputFiles {
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			logger.Fatalf("Error accessing file: %s", filePath)
		}
		size := fileInfo.Size()

		var checksums []struct {
			hashValue         string
			fileAndRange      gfile.FileAndRangeSpec
			expectedByteCount int64
		}

		if _, err := os.Stat(cfg.verify); err == nil {
			file, err := os.Open(cfg.verify)
			if err != nil {
				logger.Fatalf("Error opening verify file: %s", cfg.verify)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				hashValue, fileAndRange, byteCount, err := hasher.ParseChecksumLine(line)
				if err != nil {
					logger.Fatalf("Invalid checksum line: file=%s, line=%s", cfg.verify, line)
				}
				if filepath.Base(fileAndRange.FilePath) == filepath.Base(filePath) {
					checksums = append(checksums, struct {
						hashValue         string
						fileAndRange      gfile.FileAndRangeSpec
						expectedByteCount int64
					}{hashValue, fileAndRange, byteCount})
				}
			}
			if err := scanner.Err(); err != nil {
				logger.Fatalf("Error reading verify file: %s", cfg.verify)
			}
			if len(checksums) == 0 {
				logger.Fatalf("No matching hashes: file=%s, verify=%s", filePath, cfg.verify)
			}
		} else if os.IsNotExist(err) && hasher.AcceptsFile(cfg.verify) {
			logger.Fatalf("Verification file not found: %s", cfg.verify)
		} else {
			if len(cfg.verify) != hasher.OutputLen {
				logger.Fatalf("Invalid hash length: expected=%d, got=%d", hasher.OutputLen, len(cfg.verify))
			}
			f := gfile.FileAndRangeSpec{FilePath: filePath}
			checksums = append(checksums, struct {
				hashValue         string
				fileAndRange      gfile.FileAndRangeSpec
				expectedByteCount int64
			}{cfg.verify, f, 0})
		}

		for _, c := range checksums {
			rs := c.fileAndRange
			if rs.IsPercent && rs.End != -1 {
				rs.Start = int64(float64(size) * float64(rs.Start) / 10000)
				rs.End = int64(float64(size) * float64(rs.End) / 10000)
				rs.IsPercent = false
			}
			rangeSize := rs.End - rs.Start
			if rs.End == -1 {
				rangeSize = size
			}
			if c.expectedByteCount != 0 && c.expectedByteCount != rangeSize {
				logger.Fatalf("Byte count mismatch: file=%s, expected=%d, got=%d", filePath, c.expectedByteCount, rangeSize)
			}

			lc := progressFunc(filePath, rangeSize, rs.Start, rs.End)
			hash, err := computeHash(filePath, hasher, rs, cfg.key, lc)
			if err != nil {
				logger.Fatalf("Error computing hash: file=%s, error=%s", filePath, err)
			}

			if !strings.EqualFold(c.hashValue, hash) {
				if rs.End != -1 {
					logger.Fatalf("Hash mismatch: file=%s, range=%s, expected=%s, got=%s", filePath, rs.String(), c.hashValue, hash)
				}
				logger.Fatalf("Hash mismatch: file=%s, expected=%s, got=%s", filePath, c.hashValue, hash)
			}
		}
	}
	fmt.Println("Hash verification successful")
}

func generateFileHashes(hasher common.Hasher, inputFiles, hashFiles []string, cfg *config, progressFunc func(string, int64, int64, int64) common.FileLifecycle) {
	if cfg.increment != "" {
		percent, err := gfile.ParsePercent(cfg.increment)
		if err != nil {
			logger.Fatalf("Invalid increment: %s", cfg.increment)
		}
		for i, file := range inputFiles {
			hashFile := hashFiles[i]
			if err := computeIncrementalHashes(hasher, file, percent, cfg.key, hashFile, cfg.comment, progressFunc); err != nil {
				logger.Fatalf("Error computing incremental hashes: file=%s, error=%s", file, err)
			}
		}
		return
	}

	for i, file := range inputFiles {
		f, err := gfile.ParseFilePath(cfg.args[i])
		if err != nil {
			logger.Fatalf("Invalid file path: %s", cfg.args[i])
		}
		fileInfo, err := os.Stat(file)
		if err != nil {
			logger.Fatalf("Error accessing file: %s", file)
		}
		size := fileInfo.Size()
		rs := f
		if rs.IsPercent && rs.End != -1 {
			rs.Start = int64(float64(size) * float64(rs.Start) / 10000)
			rs.End = int64(float64(size) * float64(rs.End) / 10000)
			rs.IsPercent = false
		}
		rangeSize := rs.End - rs.Start
		if rs.End == -1 {
			rangeSize = size
		}

		lc := progressFunc(file, rangeSize, rs.Start, rs.End)
		hash, err := computeHash(file, hasher, rs, cfg.key, lc)
		if err != nil {
			logger.Fatalf("Error computing hash: file=%s, error=%s", file, err)
		}

		fmt.Printf("%s %d %s\n", hash, rangeSize, f.String())
		if i < len(hashFiles) {
			outFile, err := os.Create(hashFiles[i])
			if err != nil {
				logger.Fatalf("Error creating hash file: %s", hashFiles[i])
			}
			if cfg.comment {
				fmt.Fprintf(outFile, "# Generated by gsum on %s\n# File: %s, Size: %d\n", time.Now().Format(time.RFC3339), file, size)
			}
			fmt.Fprintf(outFile, "%s %d %s\n", hash, rangeSize, filepath.Base(f.String()))
			outFile.Close()
		}
	}
}

func computeHash(filePath string, hasher common.Hasher, rs gfile.FileAndRangeSpec, key string, lc common.FileLifecycle) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	lc.OnStart(rs.Start, rs.End)
	reader := &common.LifecycleReader{Reader: file, Lifecycle: lc}
	defer lc.OnEnd()
	return hasher.Compute(reader, key, rs)
}

func computeIncrementalHashes(hasher common.Hasher, filePath string, percent float64, key, outputFile string, comment bool, progressFunc func(string, int64, int64, int64) common.FileLifecycle) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %s", err)
	}
	fileSize := fileInfo.Size()
	numIncrements := int(math.Ceil(100 / percent))
	results := make([]string, numIncrements)

	for i := 0; i < numIncrements; i++ {
		startPercent := float64(i) * percent
		endPercent := startPercent + percent
		if endPercent > 100 {
			endPercent = 100
		}
		start := int64(float64(fileSize) * startPercent / 100)
		end := int64(float64(fileSize) * endPercent / 100)
		if i == numIncrements-1 {
			end = fileSize
		}
		rs := gfile.FileAndRangeSpec{
			FilePath: filePath,
			Start:    start,
			End:      end,
		}
		rangeSize := end - start
		lc := progressFunc(filePath, rangeSize, start, end)
		hash, err := computeHash(filePath, hasher, rs, key, lc)
		if err != nil {
			return fmt.Errorf("failed to compute hash for range %d%%-%d%%: %s", int(startPercent), int(endPercent), err)
		}
		f := gfile.FileAndRangeSpec{
			FilePath:  filePath,
			Start:     int64(startPercent * 100),
			End:       int64(endPercent * 100),
			IsPercent: true,
		}
		results[i] = fmt.Sprintf("%s %d %s", hash, rangeSize, f.String())
	}

	output := outputFile
	if output == "" {
		output = filePath + hasher.Extension
	}
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create output file: %s", err)
	}
	defer f.Close()
	if comment {
		fmt.Fprintf(f, "# Generated by gsum on %s\n# File: %s, Size: %d\n", time.Now().Format(time.RFC3339), filePath, fileSize)
	}
	for _, result := range results {
		fmt.Fprintln(f, result)
		fmt.Println(result)
	}
	return nil
}
