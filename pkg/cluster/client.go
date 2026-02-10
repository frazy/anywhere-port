package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client Agent 端的通信客户端
type Client struct {
	MasterAddr string
	AgentID    string
	Token      string
	Version    string

	// 静态指标存储
	OS        string
	CPUModel  string
	MemTotal  uint64
	DiskTotal uint64

	conn *websocket.Conn
	mu   sync.Mutex

	OnRulesSync func([]ForwardRule)
	OnHeartbeat func() HeartbeatPayload
}

func NewClient(masterAddr, agentID, token, version string) *Client {
	return &Client{
		MasterAddr: masterAddr,
		AgentID:    agentID,
		Token:      token,
		Version:    version,
	}
}

// SetStaticInfo 设置握手上报的静态信息
func (c *Client) SetStaticInfo(os, cpu string, mem, disk uint64) {
	c.OS = os
	c.CPUModel = cpu
	c.MemTotal = mem
	c.DiskTotal = disk
}

func (c *Client) Send(msg Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	return c.conn.WriteJSON(msg)
}

// Start 开始连接并运行消息循环
func (c *Client) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := c.connect(ctx); err != nil {
				log.Printf("Connect failed, retrying in 5s: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}
			c.run(ctx)
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	// 智能解析 MasterAddr 协议
	targetUrl := c.MasterAddr
	// 如果没有协议头，默认为 ws://
	if !strings.Contains(targetUrl, "://") {
		targetUrl = "ws://" + targetUrl
	}

	u, err := url.Parse(targetUrl)
	if err != nil {
		return fmt.Errorf("invalid master address: %v", err)
	}

	// 协议转换: http->ws, https->wss
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}

	u.Path = "/api/cluster/ws"
	log.Printf("Connecting to Master: %s", u.String())

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return err
	}
	c.conn = conn

	// 1. 发送 Auth
	authMsg := Message{
		Type: MsgAuth,
		Payload: AuthPayload{
			ID:        c.AgentID,
			Token:     c.Token,
			Version:   c.Version,
			OS:        c.OS,
			CPUModel:  c.CPUModel,
			MemTotal:  c.MemTotal,
			DiskTotal: c.DiskTotal,
		},
	}
	return c.conn.WriteJSON(authMsg)
}

func (c *Client) run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Recovered in client run loop: %v", r)
		}
	}()
	defer c.conn.Close()

	// 心跳定时器
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	errCh := make(chan error, 1)

	// 读循环
	go func() {
		for {
			var msg Message
			if err := c.conn.ReadJSON(&msg); err != nil {
				errCh <- err
				return
			}

			c.handleMessage(msg)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			log.Printf("Read error: %v", err)
			return
		case <-ticker.C:
			// 发送心跳 (使用 Send 方法确保线程安全)
			var hb HeartbeatPayload
			if c.OnHeartbeat != nil {
				hb = c.OnHeartbeat()
			}
			msg := Message{
				Type:    MsgHeartbeat,
				Payload: hb,
			}
			if err := c.Send(msg); err != nil {
				log.Printf("Heartbeat failed: %v", err)
				return
			}
		}
	}
}

func (c *Client) handleMessage(msg Message) {
	switch msg.Type {
	case MsgSyncRules:
		var payload SyncRulesPayload
		pBytes, _ := json.Marshal(msg.Payload)
		if err := json.Unmarshal(pBytes, &payload); err == nil {
			if c.OnRulesSync != nil {
				c.OnRulesSync(payload.Rules)
			}
		}
	case MsgAuthFailed:
		log.Printf("[FATAL] Authentication failed: %v", msg.Payload)
		os.Exit(1)
	case MsgBackup:
		var payload BackupPayload
		pBytes, _ := json.Marshal(msg.Payload)
		if err := json.Unmarshal(pBytes, &payload); err == nil {
			backupDir := "backups"
			os.MkdirAll(backupDir, 0755)
			path := filepath.Join(backupDir, payload.Filename)
			if err := os.WriteFile(path, payload.Content, 0644); err == nil {
				log.Printf("[Backup] Received and saved backup: %s", payload.Filename)
				// 清理旧备份，只保留最新的 48 个
				cleanOldBackups(backupDir, 48)
			} else {
				log.Printf("[Backup] Failed to save backup %s: %v", payload.Filename, err)
			}
		}
	}
}

func cleanOldBackups(dir string, maxKeep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("[Backup] Failed to read backup dir for cleanup: %v", err)
		return
	}

	var backups []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.gz") {
			backups = append(backups, e)
		}
	}

	if len(backups) <= maxKeep {
		return
	}

	// 按修改时间倒序排序 (最新的在前面)
	sort.Slice(backups, func(i, j int) bool {
		iInfo, _ := backups[i].Info()
		jInfo, _ := backups[j].Info()
		return iInfo.ModTime().After(jInfo.ModTime())
	})

	// 删除多余的文件
	for _, e := range backups[maxKeep:] {
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil {
			log.Printf("[Backup] Failed to delete old backup %s: %v", e.Name(), err)
		} else {
			log.Printf("[Backup] Deleted old backup: %s", e.Name())
		}
	}
}
