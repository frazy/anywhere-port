package firewall

import (
	"testing"
)

func TestExtractPort(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		want       string
	}{
		{
			name:       "standard complete address",
			listenAddr: "0.0.0.0:8080",
			want:       "8080",
		},
		{
			name:       "port only",
			listenAddr: ":9090",
			want:       "9090",
		},
		{
			name:       "ipv6 address",
			listenAddr: "[::1]:443",
			want:       "443",
		},
		{
			name:       "invalid port format fallback",
			listenAddr: "80", // Missing colon usually parsed as invalid by net.SplitHostPort
			want:       "80", 
		},
		{
			name:       "invalid port format with colon",
			listenAddr: "127.0.0.1:22:33", // Too many colons
			want:       "127.0.0.12233",    // stripped colons fallback
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractPort(tt.listenAddr); got != tt.want {
				t.Errorf("ExtractPort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUFWCommandSimulate(t *testing.T) {
	// These only run without error if the environment is valid. We ensure it doesn't panic.
	// Windows / Mac environments will safely return `nil` because IsUFWAvailable() is false.
	_ = AllowPort("test", "tcp")
	_ = DenyPort("test", "tcp")
}
