package forward

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"anywhere-port/pkg/limit"
)

// RuleConfig defines the configuration for a forwarding rule
type RuleConfig struct {
	ID         string `json:"id"`
	ListenAddr string `json:"listen_addr"`
	RemoteAddr string `json:"remote_addr"`
	Protocol   string `json:"protocol"` // "tcp", "udp"
	// Limits
	SpeedLimit  int64  `json:"speed_limit"`  // Bytes/s
	TotalQuota  int64  `json:"total_quota"`  // Total Bytes
	UsedTraffic int64  `json:"used_traffic"` // Initial used traffic (synced from Master)
	DialTimeout int    `json:"dial_timeout"` // TCP 连接超时（秒），0 使用默认值
	Comment     string `json:"comment"`      // Remark
}

// RuleStat defines the runtime statistics to persist
type RuleStat struct {
	ID          string `json:"id"`
	UsedTraffic int64  `json:"used_traffic"`
}

// Rule represents a running forwarding rule
type Rule struct {
	Config RuleConfig

	// Runtime
	Limiter  *limit.Limiter
	Listener net.Listener       // For TCP
	UDPConn  *net.UDPConn       // For UDP
	Cancel   context.CancelFunc // To stop the rule
}

// Engine manages all forwarding rules
type Engine struct {
	mu        sync.RWMutex
	rules     map[string]*Rule
	DataDir   string
	RulesPath string
	StatsPath string
	autoSave  bool // 是否自动保存到本地文件
}

func NewEngine(rulesPath, statsPath string) *Engine {
	// 自动创建文件夹，防止路径不存在报错
	if dir := filepath.Dir(rulesPath); dir != "." {
		os.MkdirAll(dir, 0755)
	}
	if dir := filepath.Dir(statsPath); dir != "." {
		os.MkdirAll(dir, 0755)
	}

	return &Engine{
		rules:     make(map[string]*Rule),
		RulesPath: rulesPath,
		StatsPath: statsPath,
		autoSave:  true,
	}
}

func (e *Engine) SetAutoSave(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.autoSave = enabled
}

// AddRule starts a new forwarding rule
func (e *Engine) AddRule(config RuleConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.rules[config.ID]; exists {
		return fmt.Errorf("rule with ID %s already exists", config.ID)
	}

	if err := e.startRule(config, config.UsedTraffic); err != nil { // Start with synced traffic
		return err
	}

	// Persist Config
	if e.autoSave {
		go e.SaveRules()
	}
	return nil
}

func (e *Engine) startRule(config RuleConfig, initialUsed int64) error {
	ctx, cancel := context.WithCancel(context.Background())

	limiter := limit.NewLimiter(config.SpeedLimit, config.TotalQuota)
	limiter.SetUsed(initialUsed)

	rule := &Rule{
		Config:  config,
		Limiter: limiter,
		Cancel:  cancel,
	}

	var err error
	switch config.Protocol {
	case "tcp":
		err = e.startTCP(ctx, rule)
	case "udp":
		err = e.startUDP(ctx, rule)
	default:
		cancel()
		return fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	if err != nil {
		cancel()
		return err
	}
	e.rules[config.ID] = rule
	return nil
}

// UpdateRule updates the configuration of an existing rule (Limits and Comment)
func (e *Engine) UpdateRule(id string, speedLimit int64, totalQuota int64, comment string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule, exists := e.rules[id]
	if !exists {
		return fmt.Errorf("rule not found")
	}

	rule.Limiter.UpdateConfig(speedLimit, totalQuota)
	rule.Config.Comment = comment

	if e.autoSave {
		go e.SaveRules()
	}
	return nil
}

// RemoveRule stops and removes a rule
func (e *Engine) RemoveRule(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule, exists := e.rules[id]
	if !exists {
		return fmt.Errorf("rule not found")
	}

	rule.Cancel()
	if rule.Listener != nil {
		rule.Listener.Close()
	}
	if rule.UDPConn != nil {
		rule.UDPConn.Close()
	}

	delete(e.rules, id)
	if e.autoSave {
		go e.SaveRules()
	}
	return nil
}

// SyncRules 同步规则列表，增量调整运行中的规则
func (e *Engine) SyncRules(configs []RuleConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	newRulesMap := make(map[string]RuleConfig)
	for _, cfg := range configs {
		newRulesMap[cfg.ID] = cfg
	}

	// 1. 停止并删除不再需要的规则
	for id, rule := range e.rules {
		if _, exists := newRulesMap[id]; !exists {
			rule.Cancel()
			if rule.Listener != nil {
				rule.Listener.Close()
			}
			if rule.UDPConn != nil {
				rule.UDPConn.Close()
			}
			delete(e.rules, id)
			log.Printf("Sync: Stopped rule %s", id)
		}
	}

	// 2. 添加或更新规则
	for id, cfg := range newRulesMap {
		if existing, exists := e.rules[id]; exists {
			// 更新现有规则（目前仅心跳/限速/备注，地址变化建议删掉重建，此处简单处理配置更新）
			existing.Config = cfg
			existing.Limiter.UpdateConfig(cfg.SpeedLimit, cfg.TotalQuota)
		} else {
			// 开启新规则
			if err := e.startRule(cfg, cfg.UsedTraffic); err != nil {
				log.Printf("Sync: Failed to start rule %s: %v", id, err)
			} else {
				log.Printf("Sync: Started rule %s", id)
			}
		}
	}

	if e.autoSave {
		go e.SaveRules()
	}
}

// GetRules returns a snapshot
func (e *Engine) GetRules() []RuleSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	snapshots := make([]RuleSnapshot, 0, len(e.rules))
	for _, r := range e.rules {
		used, quota := r.Limiter.Stats()
		snapshots = append(snapshots, RuleSnapshot{
			ID:          r.Config.ID,
			ListenAddr:  r.Config.ListenAddr,
			RemoteAddr:  r.Config.RemoteAddr,
			Protocol:    r.Config.Protocol,
			SpeedLimit:  r.Config.SpeedLimit,
			TotalQuota:  quota,
			UsedTraffic: used,
			Status:      "running",
			Comment:     r.Config.Comment,
		})
	}
	return snapshots
}

type RuleSnapshot struct {
	ID          string `json:"id"`
	ListenAddr  string `json:"listen_addr"`
	RemoteAddr  string `json:"remote_addr"`
	Protocol    string `json:"protocol"`
	SpeedLimit  int64  `json:"speed_limit"`
	TotalQuota  int64  `json:"total_quota"`
	UsedTraffic int64  `json:"used_traffic"`
	Status      string `json:"status"`
	Comment     string `json:"comment"`
}

// Persistence

func (e *Engine) LoadData() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Load Stats Map first
	statsMap := make(map[string]int64)
	if sFile, err := os.Open(e.StatsPath); err == nil {
		var stats []RuleStat
		if err := json.NewDecoder(sFile).Decode(&stats); err == nil {
			for _, s := range stats {
				statsMap[s.ID] = s.UsedTraffic
			}
		}
		sFile.Close()
	}

	// 2. Load Rules
	rFile, err := os.Open(e.RulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer rFile.Close()

	var configs []RuleConfig
	if err := json.NewDecoder(rFile).Decode(&configs); err != nil {
		return err
	}

	// 3. Start Rules with Stats
	for _, cfg := range configs {
		used := statsMap[cfg.ID]
		if err := e.startRule(cfg, used); err != nil {
			log.Printf("Failed to restore rule %s: %v", cfg.ID, err)
		} else {
			e.rules[cfg.ID].Config = cfg
		}
	}
	log.Printf("Loaded %d rules from %s", len(configs), e.RulesPath)
	return nil
}

func (e *Engine) SaveRules() error {
	e.mu.RLock()
	configs := make([]RuleConfig, 0, len(e.rules))
	for _, r := range e.rules {
		configs = append(configs, r.Config)
	}
	e.mu.RUnlock()

	return atomicWriteJSON(e.RulesPath, configs)
}

func (e *Engine) SaveStats() error {
	e.mu.RLock()
	stats := make([]RuleStat, 0, len(e.rules))
	for _, r := range e.rules {
		used, _ := r.Limiter.Stats()
		stats = append(stats, RuleStat{
			ID:          r.Config.ID,
			UsedTraffic: used,
		})
	}
	e.mu.RUnlock()

	return atomicWriteJSON(e.StatsPath, stats)
}

// atomicWriteJSON 先写临时文件再 rename，防止崩溃时损坏数据
func atomicWriteJSON(path string, v interface{}) error {
	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		log.Printf("Failed to create temp file %s: %v", tmpPath, err)
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		file.Close()
		os.Remove(tmpPath)
		return err
	}
	file.Close()

	if err := os.Rename(tmpPath, path); err != nil {
		log.Printf("Failed to rename %s -> %s: %v", tmpPath, path, err)
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// ResetTraffic resets the used traffic for a rule
func (e *Engine) ResetTraffic(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule, exists := e.rules[id]
	if !exists {
		return fmt.Errorf("rule not found")
	}

	rule.Limiter.SetUsed(0)
	go e.SaveStats() // Immediately save stats
	return nil
}

func (e *Engine) StartAutoSave(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				e.SaveStats() // Save stats on exit
				return
			case <-ticker.C:
				e.SaveStats() // Only save stats periodically
			}
		}
	}()
}
