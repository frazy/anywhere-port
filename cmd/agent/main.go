package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"anywhere-port/pkg/cluster"
	"anywhere-port/pkg/forward"
	"strings"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

const Version = "v2.0"

func getOSPrettyName() string {
	// 尝试读取 /etc/os-release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name := strings.TrimPrefix(line, "PRETTY_NAME=")
				return strings.Trim(name, "\"")
			}
		}
	}

	// Fallback to gopsutil
	if hi, err := host.Info(); err == nil {
		return fmt.Sprintf("%s %s", hi.OS, hi.PlatformVersion)
	}
	return "unknown"
}

func main() {
	masterAddr := flag.String("master", "localhost:9090", "Master address")
	agentID := flag.String("id", "", "Agent Unique ID")
	token := flag.String("token", "default_token", "Auth token")
	flag.Parse()

	if *agentID == "" || *token == "" {
		log.Fatal("Error: -id and -token are required.\nPlease register the node on Master Web UI first, then copy the full start command.")
	}

	log.Printf("Starting Anywhere-Port Agent %s (ID: %s)...", Version, *agentID)

	// 1. 初始化引擎
	// 统一存储规范：agent_rules_{id}.json, agent_stats_{id}.json
	rulesPath := filepath.Join("data", fmt.Sprintf("agent_rules_%s.json", *agentID))
	statsPath := filepath.Join("data", fmt.Sprintf("agent_stats_%s.json", *agentID))

	engine := forward.NewEngine(rulesPath, statsPath)
	if err := engine.LoadData(); err != nil {
		log.Printf("Info: No existing stats found or failed to load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 开启引擎自动保存 (stats.json)
	engine.StartAutoSave(ctx)

	// 2. 初始化集群客户端
	client := cluster.NewClient(*masterAddr, *agentID, *token, Version)

	// 采集静态信息 (Auth 时上报)
	staticOS := getOSPrettyName()
	staticCPU := "unknown"
	var staticMem uint64
	var staticDisk uint64

	if ci, err := cpu.Info(); err == nil && len(ci) > 0 {
		staticCPU = ci[0].ModelName
	}
	if v, err := mem.VirtualMemory(); err == nil {
		staticMem = v.Total / 1024 / 1024
	}
	if d, err := disk.Usage("/"); err == nil {
		staticDisk = d.Total / 1024 / 1024
	}
	client.SetStaticInfo(staticOS, staticCPU, staticMem, staticDisk)

	// 设置回调：规则同步
	client.OnRulesSync = func(rules []cluster.ForwardRule) {
		log.Printf("Received %d rules from Master, syncing...", len(rules))
		engineConfigs := make([]forward.RuleConfig, 0, len(rules))
		for _, r := range rules {
			engineConfigs = append(engineConfigs, forward.RuleConfig{
				ID:          r.ID,
				ListenAddr:  r.ListenAddr,
				RemoteAddr:  r.RemoteAddr,
				Protocol:    r.Protocol,
				SpeedLimit:  r.SpeedLimit,
				TotalQuota:  r.TotalQuota,
				UsedTraffic: r.UsedTraffic,
				Comment:     r.Comment,
			})
		}
		engine.SyncRules(engineConfigs)
	}

	// 设置回调：心跳载荷 (动态上报)
	client.OnHeartbeat = func() cluster.HeartbeatPayload {
		hb := cluster.HeartbeatPayload{
			RulesCount: len(engine.GetRules()),
		}

		if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
			hb.CPUUsage = percents[0]
		}
		if l, err := load.Avg(); err == nil {
			hb.LoadAvg = [3]float64{l.Load1, l.Load5, l.Load15}
		}
		if v, err := mem.VirtualMemory(); err == nil {
			hb.MemUsed = v.Used / 1024 / 1024
		}
		if d, err := disk.Usage("/"); err == nil {
			hb.DiskUsed = d.Used / 1024 / 1024
		}
		if hi, err := host.Info(); err == nil {
			hb.Uptime = hi.Uptime
		}

		return hb
	}

	// 3. 运行客户端
	go client.Start(ctx)

	// 4. 定期上报流量统计 (stats.json 的内容也会通过 websocket 上传给 Master)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rules := engine.GetRules()
				report := cluster.StatsReportPayload{
					Stats: make(map[string]cluster.RuleStats),
				}
				for _, r := range rules {
					// 将 engine 的单变量 UsedTraffic 拆分为 Up/Down (此处由于存储限制暂时合在一起，后续可扩展)
					report.Stats[r.ID] = cluster.RuleStats{
						UpBytes:   r.UsedTraffic,
						DownBytes: 0,
					}
				}
				client.Send(cluster.Message{
					Type:    cluster.MsgStatsReport,
					Payload: report,
				})
			}
		}
	}()

	// 优雅退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Agent shutting down...")
}
