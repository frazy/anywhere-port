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

	"anywhere-port/pkg/firewall"
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
	mu          sync.RWMutex
	rules       map[string]*Rule
	failedRules map[string]string // [NEW] id -> error message
	DataDir     string
	RulesPath   string
	StatsPath   string
	autoSave    bool // 是否自动保存到本地文件
	ufwEnabled  bool // [NEW] 是否由 Master 授权允许操作 UFW
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
		rules:       make(map[string]*Rule),
		failedRules: make(map[string]string),
		RulesPath:   rulesPath,
		StatsPath:   statsPath,
		autoSave:    true,
	}
}

// SetUFWEnabled changes the behavior of UFW automatic integrations
func (e *Engine) SetUFWEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ufwEnabled = enabled
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
		err = fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	if err != nil {
		cancel()
		// Revert UFW if listen failed (Best effort)
		if firewall.IsUFWAvailable() && e.ufwEnabled {
			port := firewall.ExtractPort(config.ListenAddr)
			firewall.DenyPort(port, config.Protocol)
		}
		e.mu.Lock()
		e.failedRules[config.ID] = err.Error()
		e.mu.Unlock()
		return err
	}

	// [FIX] 成功监听后，在此处执行 UFW 的端口放行 (之前遗漏了这步)
	if firewall.IsUFWAvailable() && e.ufwEnabled {
		port := firewall.ExtractPort(config.ListenAddr)
		if ufwErr := firewall.AllowPort(port, config.Protocol); ufwErr != nil {
			// 如果 UFW 放行失败，为了安全起见拒绝让这条规则跑在真空里，应当直接销毁刚刚建立的监听。
			log.Printf("UFW AllowPort failed: %v", ufwErr)
			cancel()
			if rule.Listener != nil {
				rule.Listener.Close()
			}
			if rule.UDPConn != nil {
				rule.UDPConn.Close()
			}
			e.mu.Lock()
			e.failedRules[config.ID] = fmt.Sprintf("UFW Error: %v", ufwErr)
			e.mu.Unlock()
			return ufwErr
		}
	}
	
	e.mu.Lock()
	e.rules[config.ID] = rule
	delete(e.failedRules, config.ID) // clear previous error if any
	e.mu.Unlock()
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

	delete(e.failedRules, id)

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

	if firewall.IsUFWAvailable() && e.ufwEnabled {
		port := firewall.ExtractPort(rule.Config.ListenAddr)
		if err := firewall.DenyPort(port, rule.Config.Protocol); err != nil {
			log.Printf("WARNING: failed to deny port via UFW, manual cleanup required: %v", err)
		}
	}

	delete(e.rules, id)
	if e.autoSave {
		go e.SaveRules()
	}
	return nil
}

// SyncRules 同步规则列表，增量调整运行中的规则
func (e *Engine) SyncRules(configs []RuleConfig) {
	newRulesMap := make(map[string]RuleConfig)
	for _, cfg := range configs {
		newRulesMap[cfg.ID] = cfg
	}

	e.mu.Lock()
	var toStop []*Rule
	var toStopIDs []string
	
	// 1. 找出需要停止的规则
	for id, rule := range e.rules {
		if _, exists := newRulesMap[id]; !exists {
			toStop = append(toStop, rule)
			toStopIDs = append(toStopIDs, id)
			delete(e.rules, id)
		}
	}
	
	// Clean up unused failed rules as well
	for id := range e.failedRules {
		if _, exists := newRulesMap[id]; !exists {
			delete(e.failedRules, id)
		}
	}

	// 2. 找出需要更新和启动的规则
	var toStart []RuleConfig
	for id, cfg := range newRulesMap {
		if existing, exists := e.rules[id]; exists {
			// 更新现有规则配置
			existing.Config = cfg
			existing.Limiter.UpdateConfig(cfg.SpeedLimit, cfg.TotalQuota)
		} else {
			// 收集待开启新规则
			toStart = append(toStart, cfg)
		}
	}
	e.mu.Unlock()

	// 3. 执行停止逻辑 (无锁执行)
	for i, rule := range toStop {
		id := toStopIDs[i]
		rule.Cancel()
		if rule.Listener != nil {
			rule.Listener.Close()
		}
		if rule.UDPConn != nil {
			rule.UDPConn.Close()
		}
		if firewall.IsUFWAvailable() && e.ufwEnabled {
			port := firewall.ExtractPort(rule.Config.ListenAddr)
			if err := firewall.DenyPort(port, rule.Config.Protocol); err != nil {
				log.Printf("WARNING: failed to deny port via UFW: %v", err)
			}
		}
		log.Printf("Sync: Stopped rule %s", id)
	}

	// 4. 执行启动逻辑 (无外层锁，startRule 内部会自行竞争小锁)
	for _, cfg := range toStart {
		if err := e.startRule(cfg, cfg.UsedTraffic); err != nil {
			log.Printf("Sync: Failed to start rule %s: %v", cfg.ID, err)
		} else {
			log.Printf("Sync: Started rule %s", cfg.ID)
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

	snapshots := make([]RuleSnapshot, 0, len(e.rules)+len(e.failedRules))
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
	for id, errMsg := range e.failedRules {
		snapshots = append(snapshots, RuleSnapshot{
			ID:     id,
			Status: "error",
			Error:  errMsg,
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
	Error       string `json:"error,omitempty"`
}

// Persistence

func (e *Engine) LoadData() error {
	// 1. Load Stats Map first (No lock needed for file IO)
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
	// e.startRule internally acquires locks when modifying dictionaries
	for _, cfg := range configs {
		used := statsMap[cfg.ID]
		if err := e.startRule(cfg, used); err != nil {
			log.Printf("Failed to restore rule %s: %v", cfg.ID, err)
		} else {
			// Update the config within a fine-grained lock
			e.mu.Lock()
			if rule, exists := e.rules[cfg.ID]; exists {
				rule.Config = cfg
			}
			e.mu.Unlock()
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
