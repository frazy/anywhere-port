package cluster

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Agent 代理节点在 Master 端的表现
type Agent struct {
	Info NodeInfo
	Conn *websocket.Conn
	mu   sync.Mutex
}

func (a *Agent) Send(msg Message) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Conn.WriteJSON(msg)
}

// Hub 管理所有在线 Agent 并持久化节点和规则
type Hub struct {
	mu     sync.RWMutex
	agents map[string]*Agent

	// 持久化数据
	DataDir     string
	NodesPath   string // 仅存 Config
	InfosPath   string // 仅存 Stats (实时动态数据)
	TrafficPath string // 仅存 UsedTraffic 列表 (Agnet 上报汇总)
	RulesPath   string

	configs  map[string]NodeConfig  // 节点静态配置 (ID -> Config)
	stats    map[string]NodeStats   // 节点动态状态 (ID -> Stats)
	allRules map[string]ForwardRule // 所有节点的规则 (ID -> Rule)
}

func NewHub(dataDir string) *Hub {
	h := &Hub{
		agents:      make(map[string]*Agent),
		configs:     make(map[string]NodeConfig),
		stats:       make(map[string]NodeStats),
		allRules:    make(map[string]ForwardRule),
		DataDir:     dataDir,
		NodesPath:   filepath.Join(dataDir, "nodes.json"),
		InfosPath:   filepath.Join(dataDir, "nodes_infos.json"),
		TrafficPath: filepath.Join(dataDir, "stats.json"),
		RulesPath:   filepath.Join(dataDir, "rules.json"),
	}
	h.loadData()

	// 启动周期性自动备份协程 (每小时一次)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			h.PushBackupsToNodes()
		}
	}()

	return h
}

// Register 注册新 Agent (需验证 Token)
func (h *Hub) Register(conn *websocket.Conn, clientIP string, auth AuthPayload) *Agent {
	h.mu.Lock()
	defer h.mu.Unlock()

	// [Pre-registration Check] 必须预先注册且 Token 匹配
	config, exists := h.configs[auth.ID]
	if !exists {
		log.Printf("[Security] Rejecting unknown agent: %s", auth.ID)
		_ = conn.WriteJSON(Message{Type: MsgAuthFailed, Payload: "Node not registered"})
		return nil
	}
	if config.Token != "" && config.Token != auth.Token {
		log.Printf("[Security] Invalid token for agent: %s", auth.ID)
		_ = conn.WriteJSON(Message{Type: MsgAuthFailed, Payload: "Invalid token"})
		return nil
	}

	// [Conflict Detection]
	if oldAgent, exists := h.agents[auth.ID]; exists {
		// clientIP 优先使用外部传入的 (即 header 中的)，如果没有则从 conn 获取
		finalIP := clientIP
		if finalIP == "" {
			finalIP = getIPFromAddr(conn.RemoteAddr().String())
		}
		oldIP := oldAgent.Info.IP // Use stored IP

		if finalIP != oldIP {
			log.Printf("[Security] ID Conflict blocked: %s (New: %s, Old: %s)", auth.ID, finalIP, oldIP)
			_ = conn.WriteJSON(Message{Type: MsgAuthFailed, Payload: "ID already in use by another IP"})
			return nil
		}
		log.Printf("Agent reconnected from same IP: %s", auth.ID)
	}

	// 更新或初始化状态
	stats := h.stats[auth.ID]
	stats.Status = "online"
	stats.LastSeen = time.Now()

	// 优先使用传入的 clientIP (Real IP)
	if clientIP != "" {
		stats.IP = clientIP
	} else {
		stats.IP = getIPFromAddr(conn.RemoteAddr().String())
	}

	stats.Version = auth.Version

	// 存储静态指纹
	stats.OSVersion = auth.OS
	stats.CPUModel = auth.CPUModel
	stats.MemTotal = auth.MemTotal
	stats.DiskTotal = auth.DiskTotal

	h.stats[auth.ID] = stats

	agent := &Agent{
		Info: NodeInfo{
			NodeConfig: config,
			NodeStats:  stats,
		},
		Conn: conn,
	}
	h.agents[auth.ID] = agent
	log.Printf("Agent registered: %s (IP: %s)", auth.ID, stats.IP)

	h.saveDataLocked()

	return agent
}

// CreateNode 预注册节点并生成 Token
func (h *Hub) CreateNode(id, comment, osType string, isBackup bool) (string, error) {
	h.mu.Lock()
	if _, exists := h.configs[id]; exists {
		h.mu.Unlock()
		return "", fmt.Errorf("node ID already exists")
	}

	token := generateRandomToken(32)
	h.configs[id] = NodeConfig{
		ID:       id,
		Token:    token,
		Hostname: comment,
		OS:       osType,
		IsBackup: isBackup,
	}
	// 同时初始化一个默认状态
	h.stats[id] = NodeStats{
		Status:   "offline",
		LastSeen: time.Now(),
	}
	h.mu.Unlock()

	h.SaveData()
	go h.PushBackupsToNodes()
	return token, nil
}

// UpdateNode 更新节点信息
func (h *Hub) UpdateNode(id, comment, osType string, isBackup bool) error {
	h.mu.Lock()
	config, ok := h.configs[id]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("node %s not found", id)
	}

	config.Hostname = comment
	config.OS = osType
	config.IsBackup = isBackup
	h.configs[id] = config

	// 同时更新在线 agent 的 Info
	if agent, ok := h.agents[id]; ok {
		agent.Info.Hostname = comment
		agent.Info.OS = osType
		agent.Info.IsBackup = isBackup
	}
	h.mu.Unlock()

	h.SaveData()
	go h.PushBackupsToNodes()
	return nil
}

// ResetNodeToken 重置指定节点的 Token 并返回新 Token
func (h *Hub) ResetNodeToken(id string) (string, error) {
	h.mu.Lock()
	cfg, exists := h.configs[id]
	if !exists {
		h.mu.Unlock()
		return "", fmt.Errorf("node not found")
	}

	newToken := generateRandomToken(32)
	cfg.Token = newToken
	h.configs[id] = cfg
	h.mu.Unlock()

	h.SaveData()
	go h.PushBackupsToNodes()
	return newToken, nil
}

func generateRandomToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			// Fallback or panic, but better to just use time fallback if critical failure
			return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
		}
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

// 辅助函数：从 host:port 中提取 IP
func getIPFromAddr(addr string) string {
	// 简单实现，实际生产可能需要更复杂的解析
	// 对于 IPv6 [::1]:port 可能需要注意
	// 这里假设是标准 net/http RemoteAddr 格式
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// Unregister 注销 Agent
func (h *Hub) Unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if agent, ok := h.agents[id]; ok {
		agent.Conn.Close()
		delete(h.agents, id)

		// 更新状态为离线
		if s, ok := h.stats[id]; ok {
			s.Status = "offline"
			h.stats[id] = s
		}

		log.Printf("Agent unregistered: %s", id)
		h.saveDataLocked() // 掉线立即保存状态
	}
}

// GetAgent 获取指定 Agent
func (h *Hub) GetAgent(id string) *Agent {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.agents[id]
}

// ListAgents 列出所有已注册节点
func (h *Hub) ListAgents() []NodeInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()

	list := make([]NodeInfo, 0, len(h.configs))
	for id, cfg := range h.configs {
		stats, ok := h.stats[id]
		if !ok {
			stats = NodeStats{Status: "offline", LastSeen: time.Now()}
		}

		// 实时更新在线状态（内存中判断）
		if _, online := h.agents[id]; online {
			stats.Status = "online"
		} else {
			stats.Status = "offline"
		}

		list = append(list, NodeInfo{
			NodeConfig: cfg,
			NodeStats:  stats,
		})
	}
	return list
}

// Broadcast 向所有 Agent 广播消息 (这里通常用于全局配置或指令)
func (h *Hub) Broadcast(msg Message) {
	h.mu.RLock()
	agents := make([]*Agent, 0, len(h.agents))
	for _, a := range h.agents {
		agents = append(agents, a)
	}
	h.mu.RUnlock()

	for _, a := range agents {
		go func(agent *Agent) {
			if err := agent.Send(msg); err != nil {
				log.Printf("Broadcast to %s failed: %v", agent.Info.ID, err)
			}
		}(a)
	}
}

// SyncRulesToAgent 推送规则给特定 Agent
func (h *Hub) SyncRulesToAgent(nodeID string) {
	h.mu.RLock()
	agent, ok := h.agents[nodeID]
	if !ok {
		h.mu.RUnlock()
		return
	}

	rules := make([]ForwardRule, 0)
	for _, r := range h.allRules {
		if r.NodeID == nodeID {
			rules = append(rules, r)
		}
	}
	h.mu.RUnlock()

	msg := Message{
		Type: MsgSyncRules,
		Payload: SyncRulesPayload{
			Rules: rules,
		},
	}
	agent.Send(msg)
}

// UpdateHeartbeat 更新心跳状态
func (h *Hub) UpdateHeartbeat(id string, payload HeartbeatPayload) {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats, exists := h.stats[id]
	if !exists {
		return
	}
	stats.LastSeen = time.Now()
	stats.CPUUsage = payload.CPUUsage
	stats.LoadAvg = payload.LoadAvg
	stats.MemUsed = payload.MemUsed
	stats.DiskUsed = payload.DiskUsed
	stats.Uptime = payload.Uptime
	stats.RulesCount = payload.RulesCount
	stats.Status = "online"

	h.stats[id] = stats

	// 同时也更新一下在线 agent 的 Info，方便实时渲染
	if agent, ok := h.agents[id]; ok {
		agent.Info.NodeStats = stats
	}
}

// UpdateRulesStats 处理来自 Agent 的流量统计上报
func (h *Hub) UpdateRulesStats(nodeID string, report StatsReportPayload) {
	h.mu.Lock()
	defer h.mu.Unlock()

	updated := false
	for ruleID, stats := range report.Stats {
		if rule, ok := h.allRules[ruleID]; ok {
			// Agent 上报的是该规则的总已用流量
			totalUsed := stats.UpBytes + stats.DownBytes
			if rule.UsedTraffic != totalUsed {
				rule.UsedTraffic = totalUsed
				h.allRules[ruleID] = rule
				updated = true
			}
		}
	}

	if updated {
		h.saveDataLocked()
	}
}

// --- 数据管理方法 ---

func (h *Hub) loadData() {
	// 加载节点配置
	if data, err := os.ReadFile(h.NodesPath); err == nil {
		var list []NodeConfig
		json.Unmarshal(data, &list)
		for _, cfg := range list {
			h.configs[cfg.ID] = cfg
		}
	}

	// 加载节点实时统计 (选填，不强制)
	if data, err := os.ReadFile(h.InfosPath); err == nil {
		var list []NodeStatsMap
		json.Unmarshal(data, &list)
		for _, item := range list {
			h.stats[item.ID] = item.Stats
		}
	}

	// [补全] 确保每个 Config 都有对应的 Stats
	for id := range h.configs {
		if _, ok := h.stats[id]; !ok {
			h.stats[id] = NodeStats{
				Status:   "offline",
				LastSeen: time.Now(),
			}
		}
	}

	// 加载规则
	if data, err := os.ReadFile(h.RulesPath); err == nil {
		var list []ForwardRule
		json.Unmarshal(data, &list)
		migrated := false
		for _, r := range list {
			if r.NodeID == "" {
				r.NodeID = "local"
				migrated = true
			}
			h.allRules[r.ID] = r
		}

		if migrated {
			log.Println("[Migration] Migrated rules to node 'local'")
			if _, ok := h.configs["local"]; !ok {
				h.configs["local"] = NodeConfig{
					ID:       "local",
					Hostname: "Legacy Migration",
				}
				h.stats["local"] = NodeStats{
					Status:   "offline",
					LastSeen: time.Now(),
				}
			}
			h.SaveData()
		}
	}
}

type NodeStatsMap struct {
	ID    string    `json:"id"`
	Stats NodeStats `json:"stats"`
}

func (h *Hub) SaveData() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	h.saveDataLocked()
}

// saveDataLocked 内部保存逻辑 (需锁)
func (h *Hub) saveDataLocked() {
	// 保存节点配置
	configList := make([]NodeConfig, 0, len(h.configs))
	for _, cfg := range h.configs {
		configList = append(configList, cfg)
	}
	nb, _ := json.MarshalIndent(configList, "", "  ")
	os.WriteFile(h.NodesPath, nb, 0644)

	// 保存节点状态 (实时数据)
	statsList := make([]NodeStatsMap, 0, len(h.stats))
	for id, s := range h.stats {
		statsList = append(statsList, NodeStatsMap{ID: id, Stats: s})
	}
	sb, _ := json.MarshalIndent(statsList, "", "  ")
	os.WriteFile(h.InfosPath, sb, 0644)

	// 保存规则
	ruleList := make([]ForwardRule, 0, len(h.allRules))
	// 同时生成独立的流量统计 stats.json
	trafficList := make([]TrafficSnapshot, 0, len(h.allRules))

	for _, r := range h.allRules {
		ruleList = append(ruleList, r)
		trafficList = append(trafficList, TrafficSnapshot{
			ID:          r.ID,
			NodeID:      r.NodeID,
			UsedTraffic: r.UsedTraffic,
		})
	}
	rb, _ := json.MarshalIndent(ruleList, "", "  ")
	os.WriteFile(h.RulesPath, rb, 0644)

	tb, _ := json.MarshalIndent(trafficList, "", "  ")
	os.WriteFile(h.TrafficPath, tb, 0644)
}

func (h *Hub) AddRule(r ForwardRule) {
	h.mu.Lock()
	h.allRules[r.ID] = r
	h.mu.Unlock()
	h.SaveData()
	h.SyncRulesToAgent(r.NodeID)
	go h.PushBackupsToNodes()
}

func (h *Hub) UpdateRule(id string, speedLimit, totalQuota int64, comment string) error {
	h.mu.Lock()
	r, ok := h.allRules[id]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("rule not found")
	}
	r.SpeedLimit = speedLimit
	r.TotalQuota = totalQuota
	r.Comment = comment
	h.allRules[id] = r
	h.mu.Unlock()
	h.SaveData()
	h.SyncRulesToAgent(r.NodeID)
	go h.PushBackupsToNodes()
	return nil
}

func (h *Hub) RemoveRule(id string) {
	h.mu.Lock()
	r, ok := h.allRules[id]
	if ok {
		delete(h.allRules, id)
	}
	h.mu.Unlock()

	if ok {
		h.SaveData()
		h.SyncRulesToAgent(r.NodeID)
		go h.PushBackupsToNodes()
	}
}

func (h *Hub) GetRulesByNode(nodeID string) []ForwardRule {
	h.mu.RLock()
	defer h.mu.RUnlock()
	list := make([]ForwardRule, 0)
	for _, r := range h.allRules {
		if r.NodeID == nodeID {
			list = append(list, r)
		}
	}
	return list
}

func (h *Hub) GetAllRules() []ForwardRule {
	h.mu.RLock()
	defer h.mu.RUnlock()
	list := make([]ForwardRule, 0, len(h.allRules))
	for _, r := range h.allRules {
		list = append(list, r)
	}
	return list
}

// TrafficSnapshot defines the structure for stats.json export
type TrafficSnapshot struct {
	ID          string `json:"id"`
	NodeID      string `json:"node_id"`
	UsedTraffic int64  `json:"used_traffic"`
}

// CreateBackup 打包并压缩核心数据文件
func (h *Hub) CreateBackup() ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	files := map[string]string{
		"nodes.json":       h.NodesPath,
		"rules.json":       h.RulesPath,
		"nodes_infos.json": h.InfosPath,
		"stats.json":       h.TrafficPath,
	}

	for name, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// PushBackupsToNodes 将备份推送给所有在线备份节点
func (h *Hub) PushBackupsToNodes() {
	content, err := h.CreateBackup()
	if err != nil {
		log.Printf("Failed to create backup: %v", err)
		return
	}

	h.mu.RLock()
	backupNodes := make([]*Agent, 0)
	for id, agent := range h.agents {
		if config, ok := h.configs[id]; ok && config.IsBackup {
			backupNodes = append(backupNodes, agent)
		}
	}
	h.mu.RUnlock()

	if len(backupNodes) == 0 {
		return
	}

	payload := BackupPayload{
		Timestamp: time.Now().Unix(),
		Filename:  fmt.Sprintf("backup_%s.tar.gz", time.Now().Format("20060102_150405")),
		Content:   content,
	}
	msg := Message{
		Type:    MsgBackup,
		Payload: payload,
	}

	for _, agent := range backupNodes {
		go func(a *Agent) {
			if err := a.Send(msg); err != nil {
				log.Printf("Failed to push backup to node %s: %v", a.Info.ID, err)
			} else {
				log.Printf("Backup pushed successfully to node %s", a.Info.ID)
			}
		}(agent)
	}
}
