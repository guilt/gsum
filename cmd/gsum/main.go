package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/guilt/gsum/pkg/common"
	"github.com/guilt/gsum/pkg/file"
	"github.com/guilt/gsum/pkg/gpg"
	"github.com/guilt/gsum/pkg/hashers"
	"github.com/guilt/gsum/pkg/lifecycle"
	"github.com/guilt/gsum/pkg/log"
)

var logger = log.NewLogger()

// config holds all command-line options and runtime configuration for gsum.
type config struct {
	algorithm    string
	verifyFile   string
	gpgFile      string
	key          string
	increment    string
	outputFile   string
	showProgress bool
	addComment   bool
	inputArgs    []string
}

// main is the entry point. Parses arguments, sets up hashing or verification, and dispatches work.
func main() {
	config, hasher := parseArgs()

	progressFunc := selectProgressFunc(config.showProgress)
	fileBatch := getFileBatch(config, hasher, config.verifyFile != "")

	if config.verifyFile != "" {
		verifyFileHashes(hasher, fileBatch.inputSpecs, progressFunc, config)
		return
	}

	generateFileHashes(hasher, fileBatch.inputSpecs, fileBatch.outputFiles, config, progressFunc)
}

// selectProgressFunc chooses the appropriate progress reporting function.
func selectProgressFunc(showProgress bool) lifecycle.ProgressFunc {
	if showProgress {
		return lifecycle.MakeProgressBars
	}
	return lifecycle.MakeDefaultLifecycle
}

// parseArgs parses all command-line flags and arguments into a config struct. Exits on error or missing required args.
func parseArgs() (*config, hashers.Hasher) {
	defaultAlgorithm := hashers.GetDefaultHashAlgorithm()
	algorithm := flag.String("algo", defaultAlgorithm, "Hash algorithm ("+strings.Join(hashers.GetAllHasherNames(), ", ")+")")
	verifyFile := flag.String("verify", "", "Verify hash or checksum file")
	gpgFile := flag.String("gpg", "", "GPG signature file")
	key := flag.String("key", "", "Key for keyed hashing")
	increment := flag.String("increment", "", "Incremental hashes (e.g., 10%)")
	outputFile := flag.String("output", "", "Output file for hashes")
	showProgress := flag.Bool("progress", false, "Show progress bar")
	addComment := flag.Bool("comment", false, "Include checksum file comments")
	flag.Parse()

	config := &config{
		algorithm:    strings.TrimSpace(*algorithm),
		verifyFile:   *verifyFile,
		gpgFile:      *gpgFile,
		key:          *key,
		increment:    *increment,
		outputFile:   *outputFile,
		showProgress: *showProgress,
		addComment:   *addComment,
		inputArgs:    flag.Args(),
	}

	// Validate algorithm
	hasher, err := hashers.GetHasher(config.algorithm)
	if err != nil {
		logger.Fatalf("Invalid algorithm: %s", config.algorithm)
	}

	// Auto-detect checksum file for common cases
	if config.verifyFile != "" && len(config.inputArgs) == 0 {
		var spec common.FileAndRangeSpec
		if err := spec.Parse(config.verifyFile); err != nil {
			logger.Fatalf("Invalid file path: %s", config.verifyFile)
		}
		config.inputArgs = []string{spec.FilePath}
		config.verifyFile = spec.FilePath + hasher.Extension
	}

	if err := hasher.Validate(config.key); err != nil {
		logger.Fatalf("Key Validation error: %s", err)
	}

	if len(config.inputArgs) == 0 {
		logger.Fatalf("No input files provided")
	}

	return config, hasher
}

// FileBatch holds parsed input file specs and output file names for batch operations.
type fileBatch struct {
	inputSpecs  []common.FileAndRangeSpec
	outputFiles []string
}

// getFileBatch parses input arguments into file.FileAndRangeSpec structs and determines output file names.
// If isVerify is true, only the last arg is used. If cfg.outputFile is set, it is used as the only output file.
// Otherwise, output files are input file base + hasher.Extension.
// uniqArgs returns a new slice with duplicates removed, preserving order.
func uniqArgs(args []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if !seen[arg] {
			seen[arg] = true
			result = append(result, arg)
		}
	}
	return result
}

func getFileBatch(config *config, hasher hashers.Hasher, isVerify bool) fileBatch {
	// Deduplicate config.inputArgs before parsing
	config.inputArgs = uniqArgs(config.inputArgs)

	var inputSpecs []common.FileAndRangeSpec
	if isVerify {
		// First arg is hash file, rest are files to verify
		if len(config.inputArgs) < 1 {
			logger.Fatalf("Need at least one file to verify")
		}
		inputSpecs = make([]common.FileAndRangeSpec, len(config.inputArgs))
		for i, arg := range config.inputArgs[:] {
			var fileAndRangeSpec common.FileAndRangeSpec
			if err := fileAndRangeSpec.Parse(arg); err != nil {
				logger.Fatalf("Invalid file path: %s", arg)
			}
			inputSpecs[i] = fileAndRangeSpec
		}
	} else {
		inputSpecs = make([]common.FileAndRangeSpec, len(config.inputArgs))
		for i, arg := range config.inputArgs {
			var fileAndRangeSpec common.FileAndRangeSpec
			if err := fileAndRangeSpec.Parse(arg); err != nil {
				logger.Fatalf("Invalid file path: %s", arg)
			}
			inputSpecs[i] = fileAndRangeSpec
		}
	}

	var outputFiles []string
	if config.outputFile != "" {
		outputFiles = []string{config.outputFile}
	} else {
		outputFiles = make([]string, len(inputSpecs))
		for i, spec := range inputSpecs {
			outputFiles[i] = filepath.Base(spec.FilePath) + hasher.Extension
		}
	}

	return fileBatch{
		inputSpecs:  inputSpecs,
		outputFiles: outputFiles,
	}
}

// computeHash computes the hash of a file (or range within a file), using the provided hasher and lifecycle/progress tracker.
// This is a utility for DRY hash computation with progress tracking.
func computeHashForFileAndRange(filePath string, hasher hashers.Hasher, rs common.FileAndRangeSpec, key string, lifeCycle common.FileLifecycle) (string, error) {
	fh, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer fh.Close()

	fileInfo, err := fh.Stat()
	if err != nil {
		return "", err
	}

	start, end, err := rs.ToBytes(fileInfo.Size())
	if err != nil {
		return "", err
	}
	if _, err := fh.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	lifeCycle.OnStart(rs.Start, rs.End)
	limitedReader := io.LimitReader(fh, end-start)
	reader := &common.LifecycleReader{Reader: limitedReader, Lifecycle: lifeCycle}
	defer lifeCycle.OnEnd()
	return hasher.Compute(reader, key, rs)
}

// Loads and parses checksums, computes hashes, and compares results. Exits on mismatch.
func verifyFileHashes(hasher hashers.Hasher, inputSpecs []common.FileAndRangeSpec, progressFunc func(common.FileAndRangeSpec, int64) common.FileLifecycle, cfg *config) {
	hashMap, isHashMap := loadHashMap(hasher, cfg.verifyFile)

	// Collect all hash files actually used for verification
	hashFilesSet := make(map[string]bool)

	for _, fileSpec := range inputSpecs {
		fileInfo, err := os.Stat(fileSpec.FilePath)
		if err != nil {
			logger.Fatalf("Error accessing file: file=%s", fileSpec.FilePath)
		}
		size := fileInfo.Size()

		hashes := selectHashesForFile(fileSpec, cfg, hasher, isHashMap, hashMap)

		for _, c := range hashes {
			verifyHash(fileSpec, c, hasher, size, cfg, progressFunc)
		}

		// Track the hash file used for this verification
		if isHashMap {
			hashFilesSet[cfg.verifyFile] = true
		}
	}
	fmt.Println("Hash verification successful")

	// GPG verification (now that we know the real hash files)
	if cfg.gpgFile != "" {
		hashFiles := make([]string, 0, len(hashFilesSet))
		for f := range hashFilesSet {
			hashFiles = append(hashFiles, f)
		}
		err := gpg.VerifyGPG(hashFiles, cfg.gpgFile)
		if err != nil {
			logger.Fatalf("GPG verification failed: %v", err)
		}
		fmt.Printf("GPG signature verified: %s for %s\n", cfg.gpgFile, strings.Trim(fmt.Sprint(hashFiles), "[]"))
	}
}

// loadHashMap loads and organizes hashes from a file if it exists.
func loadHashMap(hasher hashers.Hasher, verifyFile string) (map[string][]file.CheckSumSpec, bool) {
	if _, err := os.Stat(verifyFile); err == nil {
		allChecks, err := file.ParseChecksums(hasher.ParseChecksumLine, []string{verifyFile})
		if err != nil {
			logger.Fatalf("Error loading hash file: %s", err)
		}
		checksumMap := make(map[string][]file.CheckSumSpec)
		for _, cs := range allChecks {
			base := filepath.Base(cs.FileAndRange.FilePath)
			checksumMap[base] = append(checksumMap[base], cs)
		}
		return checksumMap, true
	}
	return nil, false
}

// selectHashesForFile determines which hashes to use for a given file.
func selectHashesForFile(fileSpec common.FileAndRangeSpec, cfg *config, hasher hashers.Hasher, isHashMap bool, hashMap map[string][]file.CheckSumSpec) []file.CheckSumSpec {
	if isHashMap {
		hashes := hashMap[filepath.Base(fileSpec.FilePath)]
		if len(hashes) == 0 {
			logger.Fatalf("No matching hashes: file=%s, verify=%s", fileSpec.FilePath, cfg.verifyFile)
		}
		return hashes
	} else if len(cfg.verifyFile) == hasher.OutputLen {
		f := common.FileAndRangeSpec{FilePath: fileSpec.FilePath}
		return []file.CheckSumSpec{{
			HashValue:         cfg.verifyFile,
			FileAndRange:      f,
			ExpectedByteCount: 0,
		}}
	}
	logger.Fatalf("Verification file not found or invalid hash: %s", cfg.verifyFile)
	return nil
}

// verifyHash checks a single hash for a file and range.
func verifyHash(fileSpec common.FileAndRangeSpec, c file.CheckSumSpec, hasher hashers.Hasher, size int64, cfg *config, progressFunc func(common.FileAndRangeSpec, int64) common.FileLifecycle) {
	rs := c.FileAndRange
	rangeSize := rs.GetRangeSize(size)
	if c.ExpectedByteCount != 0 && c.ExpectedByteCount != rangeSize {
		logger.Fatalf("Byte count mismatch: %s, expected=%d, got=%d", rs.String(), c.ExpectedByteCount, rangeSize)
	}

	lifeCycle := progressFunc(rs, rangeSize)
	hash, err := computeHashForFileAndRange(fileSpec.FilePath, hasher, rs, cfg.key, lifeCycle)
	if err != nil {
		logger.Fatalf("Error computing hash: %s, error=%s", rs.String(), err)
	}

	if !strings.EqualFold(c.HashValue, hash) {
		logger.Fatalf("Hash mismatch: %s, expected=%s, got=%s", rs.String(), c.HashValue, hash)
	}
}

// generateFileHashes computes and writes hashes for each input file.
// Handles both normal and incremental (percentage-based) hashing. Writes results to output files.
func generateFileHashes(hasher hashers.Hasher, inputSpecs []common.FileAndRangeSpec, hashFiles []string, cfg *config, progressFunc lifecycle.ProgressFunc) {
	if cfg.increment != "" {
		generateIncrementalHashes(hasher, inputSpecs, hashFiles, cfg, progressFunc)
	} else {
		generateHashes(hasher, inputSpecs, hashFiles, cfg, progressFunc)
	}
	// GPG signing: always after all hash writing is complete
	if cfg.gpgFile != "" {
		err := gpg.GenerateGPG(hashFiles, cfg.gpgFile)
		if err != nil {
			logger.Fatalf("GPG signing failed: %v", err)
		}
		fmt.Printf("GPG signature created: %s\n", cfg.gpgFile)
	}
}

// generateHashes computes and writes hashes for each input file.
func generateHashes(hasher hashers.Hasher, inputSpecs []common.FileAndRangeSpec, hashFiles []string, cfg *config, progressFunc lifecycle.ProgressFunc) {
	// Map from output file path to all CheckSumSpecs to write there
	outputMap := make(map[string][]file.CheckSumSpec)
	for i, fileSpec := range inputSpecs {
		outputPath := ""
		if len(hashFiles) == 1 {
			outputPath = hashFiles[0]
		} else if i < len(hashFiles) {
			outputPath = hashFiles[i]
		}
		fileInfo, err := os.Stat(fileSpec.FilePath)
		if err != nil {
			logger.Fatalf("Error accessing file: file=%s", fileSpec.FilePath)
		}
		// Instead of writing here, just collect the specs
		rs := fileSpec
		rangeSize := rs.GetRangeSize(fileInfo.Size())
		lifeCycle := progressFunc(rs, rangeSize)
		hash, err := computeHashForFileAndRange(fileSpec.FilePath, hasher, rs, cfg.key, lifeCycle)
		if err != nil {
			logger.Fatalf("Error computing hash: file=%s, error=%s", rs.String(), err)
		}
		pair := file.CheckSumSpec{HashValue: hash, FileAndRange: rs, ExpectedByteCount: rangeSize}
		if outputPath != "" {
			outputMap[outputPath] = append(outputMap[outputPath], pair)
		}
		// Print immediately (or could defer until after writing, your call)
		fmt.Printf("%s %d %s\n", pair.HashValue, pair.ExpectedByteCount, pair.FileAndRange.String())
	}
	// Now write each output file once
	for outputPath, pairs := range outputMap {
		err := file.WriteChecksums(outputPath, pairs, cfg.addComment)
		if err != nil {
			logger.Fatalf("failed to write hashes: %s", err)
		}
	}
}

// generateIncrementalHashes manages incremental hash generation for all input files.
func generateIncrementalHashes(hasher hashers.Hasher, inputSpecs []common.FileAndRangeSpec, hashFiles []string, cfg *config, progressFunc lifecycle.ProgressFunc) {
	percent, err := common.ParsePercent(cfg.increment)
	if err != nil {
		logger.Fatalf("Invalid increment: %s", cfg.increment)
	}
	// Map from output file path to all CheckSumSpecs to write there
	outputMap := make(map[string][]file.CheckSumSpec)
	for i, fileSpec := range inputSpecs {
		outputPath := ""
		if len(hashFiles) == 1 {
			outputPath = hashFiles[0]
		} else if i < len(hashFiles) {
			outputPath = hashFiles[i]
		}
		fileInfo, err := os.Stat(fileSpec.FilePath)
		if err != nil {
			logger.Fatalf("Error accessing file: file=%s", fileSpec.FilePath)
		}
		ranges := common.IncrementalRanges(fileSpec.FilePath, fileInfo.Size(), percent)
		for _, rs := range ranges {
			rangeSize := rs.GetRangeSize(fileInfo.Size())
			lifeCycle := progressFunc(rs, rangeSize)
			hash, err := computeHashForFileAndRange(fileSpec.FilePath, hasher, rs, cfg.key, lifeCycle)
			if err != nil {
				logger.Fatalf("Error computing hash: file=%s, error=%s", rs.String(), err)
			}
			pair := file.CheckSumSpec{HashValue: hash, FileAndRange: rs, ExpectedByteCount: rangeSize}
			if outputPath != "" {
				outputMap[outputPath] = append(outputMap[outputPath], pair)
			}
			fmt.Printf("%s %d %s\n", pair.HashValue, pair.ExpectedByteCount, pair.FileAndRange.String())
		}
	}
	// Now write each output file once
	for outputPath, pairs := range outputMap {
		err := file.WriteChecksums(outputPath, pairs, cfg.addComment)
		if err != nil {
			logger.Fatalf("failed to write hashes: %s", err)
		}
	}
}

// generateHashForFile computes the hash for a single file and writes it to output if needed.
// generateHashesForSpecs computes hashes for a set of (file, range) specs, writes them to output if needed, and prints them.
func generateHashesForSpecs(filePath string, specs []common.FileAndRangeSpec, outputPath string, hasher hashers.Hasher, key string, fileSize int64, addComment bool, progressFunc lifecycle.ProgressFunc) error {
	pairs := make([]file.CheckSumSpec, 0, len(specs))
	for _, rs := range specs {
		rangeSize := rs.GetRangeSize(fileSize)
		lifeCycle := progressFunc(rs, rangeSize)
		hash, err := computeHashForFileAndRange(filePath, hasher, rs, key, lifeCycle)
		if err != nil {
			return fmt.Errorf("failed to compute hash for: %s: %s", rs.String(), err)
		}
		pairs = append(pairs, file.CheckSumSpec{HashValue: hash, FileAndRange: rs, ExpectedByteCount: rangeSize})
	}
	if outputPath != "" {
		err := file.WriteChecksums(outputPath, pairs, addComment)
		if err != nil {
			return fmt.Errorf("failed to write hashes: %s", err)
		}
	}
	for _, p := range pairs {
		fmt.Printf("%s %d %s\n", p.HashValue, p.ExpectedByteCount, p.FileAndRange.String())
	}
	return nil
}
