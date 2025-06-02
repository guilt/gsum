package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type config struct {
	algo      string
	verify    string
	check     string
	gpg       string
	key       string
	increment string
	output    string
	progress  bool
	args      []string
}

type hashJob struct {
	filePath  string
	rs        RangeSpec
	hasher    Hasher
	key       string
	lifecycle FileLifecycle
	hashValue chan string
	err       chan error
}

func main() {
	config := createAndParseArgs()
	hasher := createAndValidateHasher(config)

	progressFunc := MakeDefaultLifecycle
	if config.progress {
		progressFunc = MakeProgressBars()
	}

	if config.verify != "" || config.check != "" {
		inputFiles := getInputFiles(config)
		hashFiles := getHashFiles(inputFiles, hasher)
		hashes := hasher.getHashes(hashFiles)
		verifyFileHashes(progressFunc, hasher, inputFiles, hashFiles, hashes)
		if config.gpg != "" {
			verifyGPG(config.check, config.gpg)
		}
	} else {
		inputFiles := getInputFiles(config)
		hashFiles := getOutputHashFiles(hasher, config)
		generateFileHashes(progressFunc, hasher, inputFiles, hashFiles, config)
		if config.gpg != "" {
			generateGPG(hashFiles, config)
		}
	}
}

func createAndParseArgs() config {
	defaultAlgo := hashers[GetDefaultHashAlgorithm()].name
	algo := flag.String("algo", defaultAlgo, "Hash algorithm ("+strings.Join(GetAllHasherNames(), ", ")+")")
	verify := flag.String("verify", "", "Verify hash against provided value")
	check := flag.String("check", "", "Verify checksums from a file (e.g., SHA256SUM)")
	gpg := flag.String("gpg", "", "GPG signature file for verification or signing")
	key := flag.String("key", "", "Key for keyed hashing algorithms (e.g., hmac, chacha20-poly1305, siphash)")
	increment := flag.String("increment", "", "Compute incremental hashes (e.g., 10% for 0-10%, 10-20%, etc.)")
	output := flag.String("output", "", "Output file for hashes (default: <file>.<algo>)")
	progress := flag.Bool("progress", false, "Show progress bar during hashing")
	flag.Parse()

	return config{
		algo:      *algo,
		verify:    *verify,
		check:     *check,
		gpg:       *gpg,
		key:       *key,
		increment: *increment,
		output:    *output,
		progress:  *progress,
		args:      flag.Args(),
	}
}

func createAndValidateHasher(config config) Hasher {
	hasher, err := GetHasher(config.algo)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if err := hasher.validate(config.key); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	return hasher
}

func getInputFiles(config config) []string {
	if config.check != "" {
		file, err := os.Open(config.check)
		if err != nil {
			fmt.Printf("Error opening checksum file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		var files []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			filePath := strings.Join(parts[1:], " ")
			if strings.Contains(filePath, "#") {
				filePath, _, _ = ParseFilePath(filePath)
			}
			files = append(files, filePath)
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading checksum file: %v\n", err)
			os.Exit(1)
		}
		return files
	}

	if len(config.args) == 0 {
		fmt.Println("Error: No input files provided")
		os.Exit(1)
	}

	filePath, _, err := ParseFilePath(config.args[0])
	if err != nil {
		fmt.Printf("Error parsing file path: %v\n", config.args[0], err)
		os.Exit(1)
	}
	return []string{filePath}
}

func getHashFiles(inputFiles []string, hasher Hasher) []string {
	if hasher.extension != "" {
		var hashFiles []string
		for _, file := range inputFiles {
			hashFile := file + hasher.extension
			if _, err := os.Stat(hashFile); err == nil {
				hashFiles = append(hashFiles, hashFile)
			}
		}
		return hashFiles
	}
	return inputFiles
}

func getOutputHashFiles(hasher Hasher, config config) []string {
	if config.output != "" {
		return []string{config.output}
	}
	inputFiles := getInputFiles(config)
	var hashFiles []string
	for _, file := range inputFiles {
		hashFiles = append(hashFiles, file+hasher.extension)
	}
	return hashFiles
}

func verifyFileHashes(progressFunc func(filePath string, size, start, end int64) FileLifecycle, hasher Hasher, inputFiles, hashFiles []string, hashes map[string]string) {
	if len(hashFiles) == 0 {
		fmt.Println("Error: No hash files found for verification")
		os.Exit(1)
	}

	for _, hashFile := range hashFiles {
		file, err := os.Open(hashFile)
		if err != nil {
			fmt.Printf("Error opening hash file %s: %v\n", hashFile, err)
			os.Exit(1)
		}
		defer file.Close()

		var selectedHasher Hasher
		for _, h := range hashers {
			if h.acceptsFile(hashFile) {
				selectedHasher = h
				break
			}
		}
		if selectedHasher.algo == 0 {
			selectedHasher = hashers[GetDefaultHashAlgorithm()]
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			hashValue, filePath, rs, err := selectedHasher.parseChecksumLine(line)
			if err != nil {
				for _, h := range hashers {
					if len(hashValue) == h.outputLen {
						hashValue, filePath, rs, err = h.parseChecksumLine(line)
						if err == nil {
							selectedHasher = h
							break
						}
					}
				}
				if err != nil {
					fmt.Printf("Invalid checksum line in %s: %s: %v\n", hashFile, line, err)
					os.Exit(1)
				}
			}

			if err := selectedHasher.validate(hasher.key); err != nil {
				fmt.Printf("Validation error for %s: %v\n", filePath, err)
				os.Exit(1)
			}

			fileInfo, err := os.Stat(filePath)
			if err != nil {
				fmt.Printf("Error accessing file %s: %v\n", filePath, err)
				os.Exit(1)
			}
			size := fileInfo.Size()
			if rs.end != -1 && !rs.isPercent {
				size = rs.end - rs.start
			} else if rs.isPercent && rs.end != -1 {
				size = int64(float64(size) * float64(rs.end-rs.start) / 10000)
			}
			lifecycle := progressFunc(filePath, size, rs.start, rs.end)

			computedHash, err := computeHash(filePath, selectedHasher, rs, hasher.key, lifecycle)
			if err != nil {
				fmt.Printf("Error computing hash for %s: %v\n", filePath, err)
				os.Exit(1)
			}

			if !strings.EqualFold(hashValue, computedHash) {
				fmt.Printf("Hash mismatch for %s: expected %s, got %s\n", filePath, hashValue, computedHash)
				os.Exit(1)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading hash file %s: %v\n", hashFile, err)
			os.Exit(1)
		}
	}

	fmt.Println("All checksums verified successfully")
}

func generateFileHashes(progressFunc func(filePath string, size, start, end int64) FileLifecycle, hasher Hasher, inputFiles, hashFiles []string, config config) {
	if len(inputFiles) == 0 {
		fmt.Println("Error: No input files provided")
		os.Exit(1)
	}

	if config.increment != "" {
		percent, err := parsePercent(config.increment)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		for i, filePath := range inputFiles {
			hashFile := hashFiles[i]
			if err := computeIncrementalHashes(filePath, hasher, percent, config.key, hashFile, progressFunc); err != nil {
				fmt.Printf("Error computing incremental hashes for %s: %v\n", filePath, err)
				os.Exit(1)
			}
		}
		return
	}

	for i, filePath := range inputFiles {
		filePath, rs, err := ParseFilePath(config.args[i])
		if err != nil {
			fmt.Printf("Error parsing file path %s: %v\n", config.args[i], err)
			os.Exit(1)
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			fmt.Printf("Error accessing file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		size := fileInfo.Size()
		if rs.end != -1 && !rs.isPercent {
			size = rs.end - rs.start
		} else if rs.isPercent && rs.end != -1 {
			size = int64(float64(size) * float64(rs.end-rs.start) / 10000)
		}
		lifecycle := progressFunc(filePath, size, rs.start, rs.end)

		hashValue, err := computeHash(filePath, hasher, rs, config.key, lifecycle)
		if err != nil {
			fmt.Printf("Error computing hash for %s: %v\n", filePath, err)
			os.Exit(1)
		}

		if config.verify != "" {
			if strings.EqualFold(config.verify, hashValue) {
				fmt.Println("Hash verification successful")
			} else {
				fmt.Printf("Hash verification failed: expected %s, got %s\n", config.verify, hashValue)
				os.Exit(1)
			}
		} else {
			fmt.Printf("%s %d %s\n", hashValue, rs.end-rs.start, config.args[i])
		}

		if len(hashFiles) > i {
			hashFile := hashFiles[i]
			f, err := os.Create(hashFile)
			if err != nil {
				fmt.Printf("Error creating hash file %s: %v\n", hashFile, err)
				os.Exit(1)
			}
			fmt.Fprintf(f, "%s %s\n", hashValue, filepath.Base(filePath))
			f.Close()
		}
	}
}

func parsePercent(s string) (float64, error) {
	percent, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	if err != nil || percent <= 0 || percent >= 100 {
		return 0, fmt.Errorf("invalid increment percentage: %s", s)
	}
	return percent, nil
}

func computeHash(filePath string, hasher Hasher, rs RangeSpec, key string, lifecycle FileLifecycle) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	lifecycle.OnStart(rs.start, rs.end)
	reader := &lifecycleReader{Reader: file, lifecycle: lifecycle}
	defer lifecycle.OnEnd()

	return hasher.compute(reader, rs, key)
}

func computeIncrementalHashes(filePath string, hasher Hasher, percent float64, key, outputFile string, progressFunc func(filePath string, size, start, end int64) FileLifecycle) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()
	numIncrements := int(100 / percent)
	results := make([]string, numIncrements)

	// Create job queue
	jobs := make(chan hashJob, numIncrements)
	var wg sync.WaitGroup

	// Start workers
	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				hashValue, err := computeHash(job.filePath, job.hasher, job.rs, job.key, job.lifecycle)
				job.hashValue <- hashValue
				job.err <- err
			}
		}()
	}

	// Submit jobs
	for i := 0; i < numIncrements; i++ {
		start := int64(float64(fileSize) * float64(i) * percent / 100)
		end := int64(float64(fileSize) * float64(i+1) * percent / 100)
		if i == numIncrements-1 {
			end = fileSize // Ensure last increment reaches end
		}
		rs := RangeSpec{start: start, end: end}
		hashValue := make(chan string)
		errChan := make(chan error)
		rangeSize := end - start
		lifecycle := progressFunc(filePath, rangeSize, start, end)
		jobs <- hashJob{
			filePath:  filePath,
			rs:        rs,
			hasher:    hasher,
			key:       key,
			lifecycle: lifecycle,
			hashValue: hashValue,
			err:       errChan,
		}
		go func(i int) {
			if err := <-errChan; err != nil {
				fmt.Printf("Error computing hash for range %d%%-%d%%: %v\n", i*int(percent), (i+1)*int(percent), err)
				os.Exit(1)
			}
			results[i] = fmt.Sprintf("%s %d %s#%d%%-%d%%", <-hashValue, end-start, filePath, i*int(percent), (i+1)*int(percent))
		}(i)
	}

	close(jobs)
	wg.Wait()

	// Write results to output file
	output := outputFile
	if output == "" {
		output = filePath + hasher.extension
	}
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer f.Close()
	for _, result := range results {
		if _, err := fmt.Fprintln(f, result); err != nil {
			return fmt.Errorf("error writing to output file: %v", err)
		}
		fmt.Println(result)
	}

	return nil
}

func verifyGPG(checksumFile, gpgFile string) {
	if err := verifyGPGImpl(checksumFile, gpgFile); err != nil {
		fmt.Printf("GPG verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("GPG signature verified successfully")
}

func verifyGPGImpl(checksumFile, gpgFile string) error {
	cmd := exec.Command("gpg", "--verify", gpgFile, checksumFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GPG verification failed: %v\nOutput: %s", err, output)
	}
	return nil
}

func generateGPG(hashFiles []string, config config) {
	if len(hashFiles) == 0 {
		fmt.Println("Error: No hash files to sign")
		os.Exit(1)
	}
	checksumFile := hashFiles[0] // Use first hash file
	gpgFile := config.gpg
	cmd := exec.Command("gpg", "--sign", checksumFile, "--output", gpgFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("GPG signing failed: %v\nOutput: %s\n", err, output)
		os.Exit(1)
	}
	fmt.Printf("GPG signature created: %s\n", gpgFile)
}

type lifecycleReader struct {
	io.Reader
	lifecycle FileLifecycle
}

func (r *lifecycleReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if n > 0 {
		r.lifecycle.OnChunk(int64(n))
	}
	return n, err
}