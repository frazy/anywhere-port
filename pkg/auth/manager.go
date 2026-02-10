package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mojocn/base64Captcha"
)

type AuthConfig struct {
	Username         string
	Password         string
	MaxLoginAttempts int
	BlockDuration    time.Duration
}

type AuthManager struct {
	config AuthConfig
	mu     sync.Mutex

	// IP Blocking
	failures    map[string]int       // IP -> Failure Count
	blocked     map[string]time.Time // IP -> Block Expiry Time
	lastFailure map[string]time.Time // IP -> Last Failure Time (to reset count)

	// Sessions
	sessions map[string]bool // SessionID -> Valid

	// Captcha
	captchaStore base64Captcha.Store
	captcha      *base64Captcha.Captcha
}

func NewAuthManager(username, password string, maxAttempts int, blockDurationStr string) *AuthManager {
	dur, _ := time.ParseDuration(blockDurationStr)
	if dur == 0 {
		dur = 30 * time.Minute
	}

	store := base64Captcha.DefaultMemStore
	driver := base64Captcha.NewDriverDigit(80, 240, 5, 0.7, 80)
	captcha := base64Captcha.NewCaptcha(driver, store)

	return &AuthManager{
		config: AuthConfig{
			Username:         username,
			Password:         password,
			MaxLoginAttempts: maxAttempts,
			BlockDuration:    dur,
		},
		failures:     make(map[string]int),
		blocked:      make(map[string]time.Time),
		lastFailure:  make(map[string]time.Time),
		sessions:     make(map[string]bool),
		captchaStore: store,
		captcha:      captcha,
	}
}

// GenerateCaptcha returns id, b64s, error
func (m *AuthManager) GenerateCaptcha() (string, string, error) {
	id, b64s, _, err := m.captcha.Generate()
	return id, b64s, err
}

// VerifyCaptcha verifies the captcha
func (m *AuthManager) VerifyCaptcha(id, answer string) bool {
	return m.captchaStore.Verify(id, answer, true)
}

// Login attempts to log in
func (m *AuthManager) Login(username, password, captchaId, captchaAnswer, clientIP string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Check if blocked
	if exp, ok := m.blocked[clientIP]; ok {
		if time.Now().Before(exp) {
			log.Printf("[Auth] Blocked login attempt from IP: %s (Blocked until: %v)", clientIP, exp)
			return "", fmt.Errorf("操作过于频繁，请稍后再试")
		}
		// Block expired
		delete(m.blocked, clientIP)
		delete(m.failures, clientIP)
		log.Printf("[Auth] Block expired for IP: %s", clientIP)
	}

	// 2. Verify Captcha
	if !m.VerifyCaptcha(captchaId, captchaAnswer) {
		log.Printf("[Auth] Invalid captcha from IP: %s", clientIP)
		return "", m.recordFailure(clientIP, "验证码错误")
	}

	// 3. Verify Credentials
	if username != m.config.Username || password != m.config.Password {
		log.Printf("[Auth] Invalid credentials from IP: %s (User: %s)", clientIP, username)
		return "", m.recordFailure(clientIP, "用户名或密码错误")
	}

	// Success: Reset failures and create session
	if count, ok := m.failures[clientIP]; ok && count > 0 {
		delete(m.failures, clientIP)
		delete(m.blocked, clientIP)
	}

	sessionID := generateToken()
	m.sessions[sessionID] = true
	log.Printf("[Auth] Login successful from IP: %s (User: %s)", clientIP, username)
	return sessionID, nil
}

func (m *AuthManager) recordFailure(clientIP, msg string) error {
	m.failures[clientIP]++
	m.lastFailure[clientIP] = time.Now()

	count := m.failures[clientIP]
	log.Printf("[Auth] Login failed for IP: %s (Count: %d/%d)", clientIP, count, m.config.MaxLoginAttempts)

	if count >= m.config.MaxLoginAttempts {
		expiry := time.Now().Add(m.config.BlockDuration)
		m.blocked[clientIP] = expiry
		log.Printf("[Auth] IP %s blocked for %v (Until: %v)", clientIP, m.config.BlockDuration, expiry)
		return fmt.Errorf("操作过于频繁，请稍后再试")
	}

	return fmt.Errorf(msg)
}

func (m *AuthManager) Logout(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

func (m *AuthManager) IsAuthenticated(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[token]
}

// Middleware verifies session cookie
func (m *AuthManager) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip for static login page, login API and Agent WebSocket endpoint
		if r.URL.Path == "/login" || r.URL.Path == "/api/login" || r.URL.Path == "/api/captcha" ||
			r.URL.Path == "/api/cluster/ws" || strings.HasPrefix(r.URL.Path, "/api/cluster/connect/script") ||
			strings.HasPrefix(r.URL.Path, "/download/") || r.URL.Path == "/favicon.ico" {
			next(w, r)
			return
		}

		cookie, err := r.Cookie("session_token")
		if err != nil || !m.IsAuthenticated(cookie.Value) {
			if r.URL.Path == "/" || r.URL.Path == "/index.html" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Helper to get IP
func GetClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}
