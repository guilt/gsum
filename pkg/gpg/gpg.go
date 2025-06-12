package gpg

import (
	"fmt"
	"os"
	"os/exec"
)

// VerifyGPG verifies GPG signatures for multiple checksum files.
func VerifyGPG(hashFiles []string, gpgFile string) error {
	if len(hashFiles) != 1 {
		return fmt.Errorf("GPG verification needs exactly one hash file")
	}

	if _, err := os.Stat(gpgFile); err != nil {
		return fmt.Errorf("GPG signature file does not exist: %s", gpgFile)
	}

	hashFile := hashFiles[0]
	cmd := exec.Command("gpg", "--verify", gpgFile, hashFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GPG verification failed for: %s (input: %s) (gpg: %s)", hashFile, output, gpgFile)
	}

	return nil
}

// GenerateGPG signs a hash file with GPG, producing a signature for each.
func GenerateGPG(hashFiles []string, gpgFile string) error {
	if len(hashFiles) != 1 {
		return fmt.Errorf("GPG signing supports only one hash file")
	}

	if _, err := os.Stat(gpgFile); err == nil {
		return fmt.Errorf("GPG signature file already exists: %s", gpgFile)
	}

	hashFile := hashFiles[0]
	cmd := exec.Command("gpg", "--output", gpgFile, "--armor", "--detach-sign", hashFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GPG signing failed for: %s (output: %s) (gpg: %s)", hashFile, output, gpgFile)
	}

	return nil
}
