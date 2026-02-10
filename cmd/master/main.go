package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gopkg.in/yaml.v3"

	"anywhere-port/pkg/auth"
	"anywhere-port/pkg/cluster"
	"anywhere-port/pkg/web"
)

type Config struct {
	WebAddr    string     `yaml:"web_addr"`
	PublicAddr string     `yaml:"public_addr"` // 外部访问地址 (用于生成连接命令)
	DataDir    string     `yaml:"data_dir"`
	Auth       AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Username         string `yaml:"username"`
	Password         string `yaml:"password"`
	MaxLoginAttempts int    `yaml:"max_login_attempts"`
	BlockDuration    string `yaml:"block_duration"`
}

func main() {
	configFile := flag.String("config", "config.yml", "Path to config file")
	flag.Parse()

	// Default Config
	config := Config{
		WebAddr:    ":9090",
		PublicAddr: "localhost:9090",
		DataDir:    "./data",
	}

	// Load Config File
	if data, err := os.ReadFile(*configFile); err == nil {
		if err := yaml.Unmarshal(data, &config); err != nil {
			log.Fatalf("Failed to parse config file: %v", err)
		}
		log.Printf("Loaded config from %s", *configFile)
	} else {
		log.Printf("Config file %s not found, using defaults", *configFile)
	}

	// Ensure Data Directory
	cwd, _ := os.Getwd()
	// Resolve DataDir absolute path if needed, or keep relative to CWD
	var absDataDir string
	if filepath.IsAbs(config.DataDir) {
		absDataDir = config.DataDir
	} else {
		absDataDir = filepath.Join(cwd, config.DataDir)
	}

	// Initialize Auth
	authMgr := auth.NewAuthManager(
		config.Auth.Username,
		config.Auth.Password,
		config.Auth.MaxLoginAttempts,
		config.Auth.BlockDuration,
	)

	// Initialize Cluster Hub
	hub := cluster.NewHub(absDataDir)

	// Initialize Web Server
	server := web.NewServer(authMgr, hub, config.PublicAddr) // Engine is nil because Master doesn't forward

	// Start Web Server
	go func() {
		if err := server.ListenAndServe(config.WebAddr); err != nil {
			log.Fatalf("Web Server failed: %v", err)
		}
	}()

	log.Printf("Anywhere-Port Master started. Web UI at http://localhost%s", config.WebAddr)
	log.Printf("Data directory: %s", absDataDir)

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	hub.SaveData() // Save all node and rule info
}
