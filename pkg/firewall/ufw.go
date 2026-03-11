package firewall

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// IsUFWAvailable checks if the 'ufw' command is available globally.
func IsUFWAvailable() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

// AllowPort opens a port in UFW.
func AllowPort(port, protocol string) error {
	if !IsUFWAvailable() {
		return nil
	}
	
	rule := fmt.Sprintf("%s/%s", port, protocol)
	cmd := exec.Command("sudo", "ufw", "allow", rule)
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		errStr := strings.TrimSpace(stderr.String())
		// Provide a more readable error if permission is denied without sudo rights
		if strings.Contains(errStr, "permission denied") || strings.Contains(err.Error(), "exit status") {
			return fmt.Errorf("UFW permission denied or failed (is Agent running as root?): %s", errStr)
		}
		return fmt.Errorf("UFW allow %s failed: %s", rule, errStr)
	}
	
	log.Printf("[UFW] Allowed port %s", rule)
	return nil
}

// DenyPort removes a port opening rule in UFW.
func DenyPort(port, protocol string) error {
	if !IsUFWAvailable() {
		return nil
	}
	
	rule := fmt.Sprintf("%s/%s", port, protocol)
	cmd := exec.Command("sudo", "ufw", "delete", "allow", rule)
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	
	if err := cmd.Run(); err != nil {
		errStr := strings.TrimSpace(stderr.String())
		return fmt.Errorf("UFW deny %s failed: %s", rule, errStr)
	}
	
	log.Printf("[UFW] Denied port %s", rule)
	return nil
}

// ExtractPort safely extracts the purely numeric port string from a ListenAddr.
func ExtractPort(listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		// Fallback: If no port splitting succeeds, assume the string might just be the port or invalid.
		// net.SplitHostPort handles ":80", "1.1.1.1:80", "[::1]:80".
		return strings.ReplaceAll(listenAddr, ":", "")
	}
	return port
}
