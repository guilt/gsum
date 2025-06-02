package gpg

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/guilt/gsum/pkg/log"
)

// logger is the package-level logger for debug and error messages.
var logger = log.NewLogger()

// VerifyGPG verifies a GPG signature for a checksum file.
func VerifyGPG(checksumFile, gpgFile string) {
	cmd := exec.Command("gpg", "--verify", gpgFile, checksumFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Errorf("GPG verification failed: error=%v, output=%s", err, output)
		os.Exit(1)
	}
	fmt.Println("GPG signature verified successfully")
}

// GenerateGPG generates a GPG signature for a hash file.
func GenerateGPG(hashFiles []string, gpgFile string) {
	if len(hashFiles) == 0 {
		logger.Errorf("No hash files to sign")
		os.Exit(1)
	}
	checksumFile := hashFiles[0]
	cmd := exec.Command("gpg", "--sign", checksumFile, "--output", gpgFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Errorf("GPG signing failed: error=%v, output=%s", err, output)
		os.Exit(1)
	}
	fmt.Printf("GPG signature created: %s\n", gpgFile)
}
