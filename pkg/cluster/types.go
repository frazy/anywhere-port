package cluster

import "time"

// MessageType 定义通信消息类型
type MessageType string

const (
	MsgHeartbeat   MessageType = "heartbeat"
	MsgSyncRules   MessageType = "sync_rules"
	MsgStatsReport MessageType = "stats_report"
	MsgAuth        MessageType = "auth"
	MsgAuthFailed  MessageType = "auth_failed"
	MsgBackup      MessageType = "backup" // New: Backup data push
)

// Message 统一的消息包装格式
type Message struct {
	Type    MessageType `json:"type"`
	Payload interface{} `json:"payload"`
}

// NodeConfig 节点持久化配置
type NodeConfig struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	Hostname string `json:"hostname"`  // 备注名
	OS       string `json:"os"`        // 操作系统 (linux, windows)
	IsBackup bool   `json:"is_backup"` // 是否作为备份节点
}

// NodeStats 节点实时运行数据
type NodeStats struct {
	Status   string    `json:"status"` // online, offline
	IP       string    `json:"ip"`
	Version  string    `json:"version"`
	LastSeen time.Time `json:"last_seen"`

	// 静态指标 (连接时确定)
	OSVersion string `json:"os_version"`
	CPUModel  string `json:"cpu_model"`
	MemTotal  uint64 `json:"mem_total"`  // MB
	DiskTotal uint64 `json:"disk_total"` // MB

	// 瞬态指标 (定期更新)
	CPUUsage   float64    `json:"cpu_usage"`
	LoadAvg    [3]float64 `json:"load_avg"`
	MemUsed    uint64     `json:"mem_used"`  // MB
	DiskUsed   uint64     `json:"disk_used"` // MB
	Uptime     uint64     `json:"uptime"`    // Seconds
	RulesCount int        `json:"rules_count"`
}

// NodeInfo 汇总信息（用于 API 返回）
type NodeInfo struct {
	NodeConfig
	NodeStats
}

// HeartbeatPayload 心跳载荷 (瞬态数据)
type HeartbeatPayload struct {
	CPUUsage   float64    `json:"cpu_usage"`
	LoadAvg    [3]float64 `json:"load_avg"`
	MemUsed    uint64     `json:"mem_used"`
	DiskUsed   uint64     `json:"disk_used"`
	Uptime     uint64     `json:"uptime"`
	RulesCount int        `json:"rules_count"`
}

// ForwardRule 转发规则（与 Agent 保持一致）
type ForwardRule struct {
	ID          string `json:"id"`
	NodeID      string `json:"node_id"` // 所属节点 ID
	ListenAddr  string `json:"listen_addr"`
	RemoteAddr  string `json:"remote_addr"`
	Protocol    string `json:"protocol"`     // tcp, udp
	SpeedLimit  int64  `json:"speed_limit"`  // Bytes/s
	TotalQuota  int64  `json:"total_quota"`  // Bytes
	UsedTraffic int64  `json:"used_traffic"` // 已使用流量 (bytes)
	Comment     string `json:"comment"`
}

// SyncRulesPayload 规则下发载荷
type SyncRulesPayload struct {
	Rules []ForwardRule `json:"rules"`
}

// StatsReportPayload 流量统计上报载荷
type StatsReportPayload struct {
	Stats map[string]RuleStats `json:"stats"` // key is RuleID
}

type RuleStats struct {
	UpBytes   int64 `json:"up"`
	DownBytes int64 `json:"down"`
}

// AuthPayload 认证载荷 (Agent -> Master, 包含静态数据)
type AuthPayload struct {
	ID    string `json:"id"`
	Token string `json:"token"`

	// 静态指纹
	Version   string `json:"version"`
	OS        string `json:"os"`
	CPUModel  string `json:"cpu_model"`
	MemTotal  uint64 `json:"mem_total"`
	DiskTotal uint64 `json:"disk_total"`
}

// BackupPayload 备份数据载荷
type BackupPayload struct {
	Timestamp int64  `json:"timestamp"`
	Filename  string `json:"filename"` // e.g., backup_20240101.tar.gz
	Content   []byte `json:"content"`  // Compressed bytes
}
