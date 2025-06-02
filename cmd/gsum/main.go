package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/guilt/gsum/pkg/common"
	gfile "github.com/guilt/gsum/pkg/file"
	ggpg "github.com/guilt/gsum/pkg/gpg"
	_ "github.com/guilt/gsum/pkg/hashers" // Blank import to trigger init()
	"github.com/guilt/gsum/pkg/lifecycle"
	"github.com/guilt/gsum/pkg/log"
)

// logger is the package-level logger for debug and error messages.
var logger = log.NewLogger()

type config struct {
	algo      string
	verify    string
	gpg       string
	key       string
	increment string
	output    string
	progress  bool
	args      []string
}

type hashJob struct {
	filePath  string
	rs        common.RangeSpec
	hasher    common.Hasher
	key       string
	lifecycle common.FileLifecycle
	index     int
}

type hashResult struct {
	index     int
	hashValue string
	size      int64
	err       error
}

// formatPercent converts a percentage (in basis points) to a string with minimal precision.
func formatPercent(basisPoints int64) string {
	percent := float64(basisPoints) / 100
	// Convert to string with up to 2 decimal places, then trim trailing zeros and decimal point if unnecessary
	s := fmt.Sprintf("%.2f", percent)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

func main() {
	cfg := parseArgs()
	hasher, err := common.GetHasher(cfg.algo)
	if err != nil {
		logger.Errorf("Invalid algorithm: algo=%q, error=%v", cfg.algo, err)
		os.Exit(1)
	}
	if err := hasher.Validate(cfg.key); err != nil {
		logger.Errorf("Validation error: error=%v", err)
		os.Exit(1)
	}

	var progressFunc func(string, int64, int64, int64) common.FileLifecycle
	if cfg.progress {
		progressFunc = lifecycle.MakeProgressBars
	} else {
		progressFunc = lifecycle.MakeDefaultLifecycle
	}

	if cfg.verify != "" {
		inputFiles := getInputFiles(cfg, true)
		verifyFileHashes(hasher, inputFiles, progressFunc, cfg)
		if cfg.gpg != "" {
			ggpg.VerifyGPG(cfg.verify, cfg.gpg)
		}
	} else {
		inputFiles := getInputFiles(cfg, false)
		hashFiles := getOutputHashFiles(hasher, cfg)
		generateFileHashes(hasher, inputFiles, hashFiles, cfg, progressFunc)
		if cfg.gpg != "" {
			ggpg.GenerateGPG(hashFiles, cfg.gpg)
		}
	}
}

func parseArgs() *config {
	defaultAlgo := common.GetDefaultHashAlgorithm() // Default algorithm
	algo := flag.String("algo", defaultAlgo, "Hash algorithm ("+strings.Join(common.GetAllHasherNames(), ", ")+")")
	verify := flag.String("verify", "", "Verify hash against a provided hash value or checksum file (e.g., example.txt.sha1)")
	gpg := flag.String("gpg", "", "GPG signature file for verification or signing")
	key := flag.String("key", "", "Key for keyed hashing algorithms (e.g., hmac, chacha20-poly1305, siphash)")
	increment := flag.String("increment", "", "Compute incremental hashes (e.g., 10% for 0-10%, 10-20%, etc.)")
	output := flag.String("output", "", "Output file for hashes (default: <file>.<algo>)")
	progress := flag.Bool("progress", false, "Show progress bar during hashing")
	flag.Parse()

	cfg := &config{
		algo:      strings.TrimSpace(*algo),
		verify:    *verify,
		gpg:       *gpg,
		key:       *key,
		increment: *increment,
		output:    *output,
		progress:  *progress,
		args:      flag.Args(),
	}

	// Validate algo
	if cfg.algo == "" {
		logger.Errorf("Algorithm cannot be empty")
		os.Exit(1)
	}

	// Verify algorithm is supported
	if _, err := common.GetHasher(cfg.algo); err != nil {
		logger.Errorf("Invalid algorithm: algo=%q, error=%v, supported=%s", cfg.algo, err, strings.Join(common.GetAllHasherNames(), ", "))
		os.Exit(1)
	}

	return cfg
}

func getInputFiles(cfg *config, isVerify bool) []string {
	if len(cfg.args) == 0 {
		logger.Errorf("No input files provided")
		os.Exit(1)
	}

	if isVerify {
		if len(cfg.args) < 1 {
			logger.Errorf("Input file required for verification")
			os.Exit(1)
		}
		// For -verify, use the last argument as the input file
		filePath, _, err := gfile.ParseFilePath(cfg.args[len(cfg.args)-1])
		if err != nil {
			logger.Errorf("Error parsing file path: file=%s, error=%v", cfg.args[len(cfg.args)-1], err)
			os.Exit(1)
		}
		return []string{filePath}
	}

	// For non-verify, use all arguments as input files
	var inputFiles []string
	for _, arg := range cfg.args {
		filePath, _, err := gfile.ParseFilePath(arg)
		if err != nil {
			logger.Errorf("Error parsing file path: file=%s, error=%v", arg, err)
			os.Exit(1)
		}
		inputFiles = append(inputFiles, filePath)
	}
	return inputFiles
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
			logger.Errorf("Error accessing file: file=%s, error=%v", filePath, err)
			os.Exit(1)
		}

		// Collect all matching checksum entries
		var checksums []struct {
			hashValue         string
			rs                common.RangeSpec
			expectedByteCount int64
		}

		// Check if cfg.verify is an existing file
		if _, err := os.Stat(cfg.verify); err == nil {
			logger.Debugf("Treating verify argument as file: %s", cfg.verify)
			// cfg.verify is a file, parse it
			file, err := os.Open(cfg.verify)
			if err != nil {
				logger.Errorf("Error opening verify file: file=%s, error=%v", cfg.verify, err)
				os.Exit(1)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				hashValue, parsedFilePath, parsedRs, err := hasher.ParseChecksumLine(line)
				if err != nil {
					logger.Errorf("Invalid checksum line: file=%s, line=%s, error=%v", cfg.verify, line, err)
					os.Exit(1)
				}
				if filepath.Base(parsedFilePath) == filepath.Base(filePath) {
					var byteCount int64
					parts := strings.Fields(line)
					if len(parts) > 2 {
						if count, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
							byteCount = count
							if byteCount == -1 {
								byteCount = fileInfo.Size() // Use file size for -1
							}
						}
					}
					checksums = append(checksums, struct {
						hashValue         string
						rs                common.RangeSpec
						expectedByteCount int64
					}{hashValue, parsedRs, byteCount})
				}
			}
			if err := scanner.Err(); err != nil {
				logger.Errorf("Error reading verify file: file=%s, error=%v", cfg.verify, err)
				os.Exit(1)
			}
			if len(checksums) == 0 {
				logger.Errorf("No matching hashes found: file=%s, verify=%s", filePath, cfg.verify)
				os.Exit(1)
			}
		} else if os.IsNotExist(err) && hasher.AcceptsFile(cfg.verify) {
			logger.Debugf("Verify argument matches checksum file pattern but does not exist: %s", cfg.verify)
			logger.Errorf("Verification file not found: file=%s", cfg.verify)
			os.Exit(1)
		} else {
			logger.Debugf("Treating verify argument as hash value: %s", cfg.verify)
			// cfg.verify is a hash value, validate its length
			if len(cfg.verify) != hasher.OutputLen {
				logger.Errorf("Invalid hash value length: expected=%d, got=%d, value=%s", hasher.OutputLen, len(cfg.verify), cfg.verify)
				os.Exit(1)
			}
			checksums = append(checksums, struct {
				hashValue         string
				rs                common.RangeSpec
				expectedByteCount int64
			}{cfg.verify, common.RangeSpec{Start: 0, End: -1}, 0})
		}

		// Verify each checksum entry
		size := fileInfo.Size()
		for _, entry := range checksums {
			rs := entry.rs
			expectedHash := entry.hashValue
			expectedByteCount := entry.expectedByteCount

			logger.Debugf("Using RangeSpec: file=%s, start=%d, end=%d, isPercent=%v", filePath, rs.Start, rs.End, rs.IsPercent)

			var rangeSize, startPercent, endPercent int64
			if rs.IsPercent && rs.End != -1 {
				// Store original basis points for percentage display
				startPercent = rs.Start
				endPercent = rs.End
				// Convert basis points to bytes
				start := int64(float64(size) * float64(rs.Start) / 10000)
				end := int64(float64(size) * float64(rs.End) / 10000)
				rangeSize = end - start
				rs.Start = start
				rs.End = end
				rs.IsPercent = false // Normalize to byte-based range
			} else if rs.End != -1 && !rs.IsPercent {
				rangeSize = rs.End - rs.Start
			} else {
				rangeSize = size
			}

			// Validate byte count if provided
			if expectedByteCount != 0 && expectedByteCount != rangeSize {
				logger.Errorf("Byte count mismatch: file=%s, expected=%d, got=%d", filePath, expectedByteCount, rangeSize)
				os.Exit(1)
			}

			// Log RangeSpec if specified (End != -1)
			if rs.End != -1 {
				logger.Debugf("Hashing range for %s: bytes %d-%d", filePath, rs.Start, rs.End)
			}

			lc := progressFunc(filePath, rangeSize, rs.Start, rs.End)

			computedHash, err := computeHash(filePath, hasher, rs, cfg.key, lc)
			if err != nil {
				logger.Errorf("Error computing hash: file=%s, error=%v", filePath, err)
				os.Exit(1)
			}

			if !strings.EqualFold(expectedHash, computedHash) {
				if rs.End != -1 {
					if startPercent != 0 || endPercent != 0 {
						logger.Errorf("Hash mismatch: file=%s, range=%d%%-%d%% (bytes %d-%d), expected=%s, got=%s",
							filePath, startPercent/100, endPercent/100, rs.Start, rs.End, expectedHash, computedHash)
					} else {
						logger.Errorf("Hash mismatch: file=%s, range=bytes %d-%d, expected=%s, got=%s",
							filePath, rs.Start, rs.End, expectedHash, computedHash)
					}
				} else {
					logger.Errorf("Hash mismatch: file=%s, expected=%s, got=%s", filePath, expectedHash, computedHash)
				}
				os.Exit(1)
			}
		}
	}

	fmt.Println("Hash verification successful")
}

func generateFileHashes(hasher common.Hasher, inputFiles, hashFiles []string, cfg *config, progressFunc func(string, int64, int64, int64) common.FileLifecycle) {
	if len(inputFiles) == 0 {
		logger.Errorf("No input files provided")
		os.Exit(1)
	}

	if cfg.increment != "" {
		percent, err := parsePercent(cfg.increment)
		if err != nil {
			logger.Errorf("Invalid increment percentage: error=%v", err)
			os.Exit(1)
		}
		for i, inputFile := range inputFiles {
			hashFile := hashFiles[i]
			if err := computeIncrementalHashes(hasher, inputFile, percent, cfg.key, hashFile, progressFunc); err != nil {
				logger.Errorf("Error computing incremental hashes: file=%s, error=%v", inputFile, err)
				os.Exit(1)
			}
		}
		return
	}

	for i := range inputFiles {
		filePath, rs, err := gfile.ParseFilePath(cfg.args[i])
		if err != nil {
			logger.Errorf("Error parsing file path: file=%s, error=%v", cfg.args[i], err)
			os.Exit(1)
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			logger.Errorf("Error accessing file: file=%s, error=%v", filePath, err)
			os.Exit(1)
		}
		size := fileInfo.Size()
		origRs := rs // Store original RangeSpec for output formatting
		if rs.IsPercent && rs.End != -1 {
			// Convert basis points to bytes
			start := int64(float64(size) * float64(rs.Start) / 10000)
			end := int64(float64(size) * float64(rs.End) / 10000)
			size = end - start
			rs.Start = start
			rs.End = end
			rs.IsPercent = false // Normalize to byte-based range
		} else if rs.End != -1 && !rs.IsPercent {
			size = rs.End - rs.Start
		}
		lc := progressFunc(filePath, size, rs.Start, rs.End)

		hashValue, err := computeHash(filePath, hasher, rs, cfg.key, lc)
		if err != nil {
			logger.Errorf("Error computing hash: file=%s, error=%v", filePath, err)
			os.Exit(1)
		}

		// Determine output file path with range specification
		var outputFilePath string
		isFullFile := (origRs.Start == 0 && origRs.End == -1 && !origRs.IsPercent) ||
			(origRs.Start == 0 && origRs.End == 10000 && origRs.IsPercent)
		if isFullFile {
			outputFilePath = filepath.Base(filePath)
			logger.Debugf("Omitting range spec for full file: file=%s", filePath)
		} else if origRs.IsPercent {
			startPercent := formatPercent(origRs.Start)
			endPercent := formatPercent(origRs.End)
			outputFilePath = fmt.Sprintf("%s#%s%%-%s%%", filepath.Base(filePath), startPercent, endPercent)
			logger.Debugf("Including percent range spec: file=%s, range=%s%%-%s%%", filePath, startPercent, endPercent)
		} else {
			outputFilePath = fmt.Sprintf("%s#%d-%d", filepath.Base(filePath), origRs.Start, origRs.End)
			logger.Debugf("Including byte range spec: file=%s, range=%d-%d", filePath, origRs.Start, origRs.End)
		}

		fmt.Printf("%s %d %s\n", hashValue, size, outputFilePath)

		if len(hashFiles) > i {
			hashFile := hashFiles[i]
			f, err := os.Create(hashFile)
			if err != nil {
				logger.Errorf("Error creating hash file: file=%s, error=%v", hashFile, err)
				os.Exit(1)
			}
			fmt.Fprintf(f, "%s %d %s\n", hashValue, size, outputFilePath)
			f.Close()
		}
	}
}

func parsePercent(s string) (float64, error) {
	percent, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	if err != nil || percent < 0 || percent >= 100 {
		return 0, fmt.Errorf("invalid increment percentage: %s", s)
	}
	return percent, nil
}

func computeHash(filePath string, hasher common.Hasher, rs common.RangeSpec, key string, lc common.FileLifecycle) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot stat file: %v", err)
	}
	logger.Debugf("computeHash: file=%s, size=%d, range=%d-%d, isPercent=%v", filePath, fileInfo.Size(), rs.Start, rs.End, rs.IsPercent)

	lc.OnStart(rs.Start, rs.End)
	reader := &common.LifecycleReader{Reader: file, Lifecycle: lc}
	defer lc.OnEnd()

	return hasher.Compute(reader, rs, key)
}

// computeIncrementalHashes computes hashes for incremental chunks of a file based on the given percentage.
func computeIncrementalHashes(hasher common.Hasher, filePath string, percent float64, key, outputFile string, progressFunc func(string, int64, int64, int64) common.FileLifecycle) error {
	if percent == 0 {
		return fmt.Errorf("increment percentage cannot be 0%%")
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	fileSize := fileInfo.Size()
	// Use Ceil to ensure we cover 100% (e.g., 3% gives 34 increments: 0%-3%, ..., 99%-100%).
	// For perfect multiples (e.g., 10%), Ceil gives exact increments (100/10 = 10), avoiding duplicates.
	numIncrements := int(math.Ceil(100 / percent))
	results := make([]string, numIncrements)

	jobs := make(chan hashJob, numIncrements)
	resultsChan := make(chan hashResult, numIncrements)
	var wg sync.WaitGroup

	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				hashValue, err := computeHash(job.filePath, job.hasher, job.rs, job.key, job.lifecycle)
				resultsChan <- hashResult{
					index:     job.index,
					hashValue: hashValue,
					size:      job.rs.End - job.rs.Start,
					err:       err,
				}
			}
		}()
	}

	for i := 0; i < numIncrements; i++ {
		startPercent := float64(i) * percent
		endPercent := float64(i+1) * percent
		if endPercent > 100 {
			endPercent = 100
		}
		start := int64(float64(fileSize) * startPercent / 100)
		end := int64(float64(fileSize) * endPercent / 100)
		if i == numIncrements-1 {
			end = fileSize // Ensure last chunk reaches file end
		}
		rs := common.RangeSpec{Start: start, End: end}
		rangeSize := end - start
		lc := progressFunc(filePath, rangeSize, start, end)
		jobs <- hashJob{
			filePath:  filePath,
			rs:        rs,
			hasher:    hasher,
			key:       key,
			lifecycle: lc,
			index:     i,
		}
	}

	close(jobs)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		if result.err != nil {
			return fmt.Errorf("failed to compute hash for range %d%%-%d%%: %w", result.index*int(percent), (result.index+1)*int(percent), result.err)
		}
		startPercent := result.index * int(percent)
		endPercent := (result.index + 1) * int(percent)
		if endPercent > 100 {
			endPercent = 100
		}
		results[result.index] = fmt.Sprintf("%s %d %s#%d%%-%d%%", result.hashValue, result.size, filePath, startPercent, endPercent)
	}

	output := outputFile
	if output == "" {
		output = filePath + hasher.Extension
	}
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()
	for _, result := range results {
		if _, err := fmt.Fprintln(f, result); err != nil {
			return fmt.Errorf("failed to write to output file: %w", err)
		}
		fmt.Println(result)
	}

	return nil
}
