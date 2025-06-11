package gpg

import (
	"fmt"
	"os/exec"

	"github.com/guilt/gsum/pkg/log"
)

// logger is the package-level logger for debug and error messages.
var logger = log.NewLogger()

// VerifyGPG verifies a GPG signature for a checksum file.
func VerifyGPG(checksumFile, gpgFile string) error {
	cmd := exec.Command("gpg", "--verify", gpgFile, checksumFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GPG verification failed: %w; output: %s", err, output)
	}
	fmt.Println("GPG signature verified successfully")
	return nil
}

// GenerateGPG generates a GPG signature for a hash file.
func GenerateGPG(hashFiles []string, gpgFile string) error {
	if len(hashFiles) == 0 {
		return fmt.Errorf("no hash files to sign")
	}
	checksumFile := hashFiles[0]
	cmd := exec.Command("gpg", "--sign", checksumFile, "--output", gpgFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GPG signing failed: %w; output: %s", err, output)
	}
	fmt.Printf("GPG signature created: %s\n", gpgFile)
	return nil
}
