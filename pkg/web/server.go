package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	texttpl "text/template"
	"time"

	"anywhere-port/pkg/auth"
	"anywhere-port/pkg/cluster"

	"github.com/gorilla/websocket"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	auth       *auth.AuthManager
	hub        *cluster.Hub
	publicAddr string
	upgrader   websocket.Upgrader
	templates  *template.Template
}

const (
	defaultLinuxTpl = `#!/bin/bash
# Anywhere-Port Installer for Linux (Internal Fallback)
MASTER="{{.MasterAddr}}"
ID="{{.AgentID}}"
TOKEN="{{.Token}}"
DOWNLOAD_URL="{{.DownloadUrl}}/awport-agent_linux_amd64"

echo -e "\033[36mAnywhere-Port Agent Installer\033[0m"
echo "-----------------------------"
echo "Master: $MASTER"
echo "ID:     $ID"

WORK_DIR="$HOME/anywhere-port"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# 1. 下载 Agent
echo "Downloading agent from $DOWNLOAD_URL..."
if command -v curl &> /dev/null; then
    curl -sL "$DOWNLOAD_URL" -o awport-agent
elif command -v wget &> /dev/null; then
    wget -q "$DOWNLOAD_URL" -O awport-agent
else
    echo -e "\033[31m[!] Neither curl nor wget found.\033[0m"
    exit 1
fi
chmod +x awport-agent
echo "Starting agent..."
nohup ./awport-agent -master "$MASTER" -id "$ID" -token "$TOKEN" > agent.log 2>&1 &
PID=$!
echo -e "\033[32m[+] Agent started with PID $PID\033[0m"
`

	defaultWindowsTpl = `# Anywhere-Port Installer for Windows (Internal Fallback)
$ErrorActionPreference = "Stop"
$Master = "{{.MasterAddr}}"
$ID = "{{.AgentID}}"
$Token = "{{.Token}}"
$DownloadUrl = "{{.DownloadUrl}}/awport-agent.exe"

Write-Host "Anywhere-Port Agent Installer" -ForegroundColor Cyan
Write-Host "-----------------------------"
Write-Host "Master: $Master"
Write-Host "ID:     $ID"

$InstallDir = "anywhere-port"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}
Set-Location $InstallDir

Write-Host "Downloading agent from $DownloadUrl..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile "awport-agent.exe" -UseBasicParsing
} catch {
    Write-Error "Failed to download agent: $_"
    exit 1
}

$BatFile = "start_agent_$ID.bat"
$CmdContent = "@echo off
cd /d ""%%~dp0""
start /b awport-agent.exe -master $Master -id $ID -token $Token"
Set-Content -Path $BatFile -Value $CmdContent

Write-Host "Setup complete. Run '$BatFile' to start." -ForegroundColor Green
`
)

func NewServer(authMgr *auth.AuthManager, hub *cluster.Hub, publicAddr string) *Server {
	tmpl := template.New("base")
	// 从嵌入的 staticFS 中递归解析所有模版
	tmpl, err := tmpl.ParseFS(staticFS, "static/*.html", "static/partials/*.tmpl")
	if err != nil {
		log.Printf("Template parsing failed: %v", err)
	}

	return &Server{
		auth:       authMgr,
		hub:        hub,
		publicAddr: publicAddr,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		templates: tmpl,
	}
}

func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()

	// API
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/", s.handleRuleAction) // DELETE, PUT

	// Auth API
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/captcha", s.handleCaptcha)
	mux.HandleFunc("/api/logout", s.handleLogout)

	// Cluster API
	mux.HandleFunc("/api/cluster/nodes", s.handleNodes)
	mux.HandleFunc("/api/cluster/nodes/reset", s.handleResetNodeToken)
	mux.HandleFunc("/api/cluster/nodes/update", s.handleUpdateNode)      // New: Update node comment
	mux.HandleFunc("/api/cluster/backup", s.handleBackup)                // New: Manual backup trigger
	mux.HandleFunc("/api/cluster/connect/script", s.handleConnectScript) // New: Generate install script
	mux.HandleFunc("/api/cluster/ws", s.handleWS)

	// Download API
	// 映射 /download/ 到本地 ./dist/ 目录
	distDir := "./dist"
	distFS := http.FileServer(http.Dir(distDir))
	mux.Handle("/download/", http.StripPrefix("/download/", distFS))

	// Static Files with Middleware
	// We need to serve /login without auth, but protect others if we want (actually middleware handles it)
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))

	// Custom File Handler to support SPA-like or specific mappings if needed,
	// but here we just need to route /login to login.html if not found (or just let fileServer handle it)
	// Actually, we should map "/" to index.html explicitly to ensure middleware catches it during redirect check.

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			if err := s.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if r.URL.Path == "/login" || r.URL.Path == "/login.html" {
			if err := s.templates.ExecuteTemplate(w, "login.html", nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	// Wrap Global Middleware
	return http.ListenAndServe(addr, s.auth.Middleware(mux.ServeHTTP))
}

func (s *Server) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	id, b64s, err := s.auth.GenerateCaptcha()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"id":    id,
		"image": b64s,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		CaptchaId  string `json:"captcha_id"`
		CaptchaVal string `json:"captcha_val"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ip := auth.GetClientIP(r)
	// Clean IP (remove port if present)
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	token, err := s.auth.Login(creds.Username, creds.Password, creds.CaptchaId, creds.CaptchaVal, ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		s.auth.Logout(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rules := s.hub.GetAllRules()
		json.NewEncoder(w).Encode(rules)
		return
	}

	if r.Method == http.MethodPost {
		var config cluster.ForwardRule
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if config.ID == "" {
			config.ID = fmt.Sprintf("%d", time.Now().UnixNano())
		}

		if config.NodeID == "" {
			http.Error(w, "NodeID is required", http.StatusBadRequest)
			return
		}

		s.hub.AddRule(config)
		w.WriteHeader(http.StatusCreated)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleRuleAction(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if id == "" {
		http.Error(w, "Missing ID", http.StatusBadRequest)
		return
	}

	// 流量重置功能在 Master 层面需要转发指令给 Agent，此处暂留空或仅支持状态重置
	if r.Method == http.MethodPost && strings.HasSuffix(id, "/reset") {
		// realID := strings.TrimSuffix(id, "/reset")
		// TODO: 向对应 Agent 发送重置指令
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodDelete {
		s.hub.RemoveRule(id)
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodPut {
		var config struct {
			SpeedLimit int64  `json:"speed_limit"`
			TotalQuota int64  `json:"total_quota"`
			Comment    string `json:"comment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := s.hub.UpdateRule(id, config.SpeedLimit, config.TotalQuota, config.Comment); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
}

// syncToAgents 已停用，规则同步由 Hub 内部自动处理

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Register a new pre-approved node
		var req struct {
			ID       string `json:"id"`
			Comment  string `json:"comment"`
			OS       string `json:"os"`
			IsBackup bool   `json:"is_backup"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.ID == "" {
			req.ID = fmt.Sprintf("node_%d", time.Now().Unix())
		}
		if req.OS == "" {
			req.OS = "linux"
		}

		token, err := s.hub.CreateNode(req.ID, req.Comment, req.OS, req.IsBackup)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict) // Assume conflict
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"id":    req.ID,
			"token": token,
		})
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodes := s.hub.ListAgents()
	json.NewEncoder(w).Encode(nodes)
}

func (s *Server) handleResetNodeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := s.hub.ResetNodeToken(req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"id":    req.ID,
		"token": token,
	})
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID       string `json:"id"`
		Comment  string `json:"comment"`
		OS       string `json:"os"`
		IsBackup bool   `json:"is_backup"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := s.hub.UpdateNode(req.ID, req.Comment, req.OS, req.IsBackup); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	go s.hub.PushBackupsToNodes()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Backup triggered"))
}

// handleConnectScript 生成一键安装/启动脚本
func (s *Server) handleConnectScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	osType := r.URL.Query().Get("os") // "linux" or "windows"
	agentID := r.URL.Query().Get("id")
	token := r.URL.Query().Get("token")

	if agentID == "" || token == "" {
		http.Error(w, "Missing id or token", http.StatusBadRequest)
		return
	}

	// 动态组装数据
	data := struct {
		MasterAddr  string
		AgentID     string
		Token       string
		DownloadUrl string
	}{
		MasterAddr:  s.publicAddr,
		AgentID:     agentID,
		Token:       token,
		DownloadUrl: "",
	}

	// 智能构建 DownloadUrl
	if strings.HasPrefix(s.publicAddr, "http://") || strings.HasPrefix(s.publicAddr, "https://") {
		data.DownloadUrl = fmt.Sprintf("%s/download", s.publicAddr)
	} else {
		data.DownloadUrl = fmt.Sprintf("http://%s/download", s.publicAddr)
	}

	var scriptName, defaultTpl string
	if osType == "windows" {
		w.Header().Set("Content-Type", "text/plain")
		scriptName = "install.ps1.tpl"
		defaultTpl = defaultWindowsTpl
	} else {
		w.Header().Set("Content-Type", "text/x-shellscript")
		scriptName = "install.sh.tpl"
		defaultTpl = defaultLinuxTpl
	}

	// 尝试加载外部模板: 优先 dist/scripts/ -> 然后 scripts/
	tplContent := defaultTpl
	paths := []string{
		filepath.Join("dist", "scripts", scriptName),
		filepath.Join("scripts", scriptName),
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			tplContent = string(b)
			break
		}
	}

	// 强制统一换行符: Windows CRLF -> Unix LF
	// 防止 Windows 下编辑的模板在 Linux 客户端执行时报 $'\r': command not found
	tplContent = strings.ReplaceAll(tplContent, "\r\n", "\n")

	t, err := texttpl.New("script").Parse(tplContent)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		http.Error(w, "Render error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(buf.Bytes())
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade failed: %v", err)
		return
	}

	// 1. 等待 Auth 消息
	var msg cluster.Message
	if err := conn.ReadJSON(&msg); err != nil {
		conn.Close()
		return
	}

	if msg.Type != cluster.MsgAuth {
		conn.Close()
		return
	}

	// 简单解析 Auth Payload (实际生产应有更强的 Token 校验)
	payloadBytes, _ := json.Marshal(msg.Payload)
	var authPayload cluster.AuthPayload
	json.Unmarshal(payloadBytes, &authPayload)

	if authPayload.ID == "" {
		conn.Close()
		return
	}

	// 2. 注册并开始消息循环
	// 获取真实 IP (通过 Header 或 RemoteAddr)
	clientIP := auth.GetClientIP(r)
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx] // Remove port if present
	}

	_ = s.hub.Register(conn, clientIP, authPayload)
	defer s.hub.Unregister(authPayload.ID)

	// 注册后立即推送该节点的生存规则
	s.hub.SyncRulesToAgent(authPayload.ID)

	for {
		var incoming cluster.Message
		if err := conn.ReadJSON(&incoming); err != nil {
			log.Printf("Agent %s disconnected: %v", authPayload.ID, err)
			break
		}

		switch incoming.Type {
		case cluster.MsgHeartbeat:
			var hb cluster.HeartbeatPayload
			pBytes, _ := json.Marshal(incoming.Payload)
			json.Unmarshal(pBytes, &hb)
			s.hub.UpdateHeartbeat(authPayload.ID, hb)
		case cluster.MsgStatsReport:
			var report cluster.StatsReportPayload
			pBytes, _ := json.Marshal(incoming.Payload)
			json.Unmarshal(pBytes, &report)
			s.hub.UpdateRulesStats(authPayload.ID, report)
		}
	}
}
