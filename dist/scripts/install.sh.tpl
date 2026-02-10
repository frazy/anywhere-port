#!/bin/bash
# Anywhere-Port Installer for Linux

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

# 2. 启动
echo "Starting agent..."
nohup ./awport-agent -master "$MASTER" -id "$ID" -token "$TOKEN" > agent.log 2>&1 &
PID=$!
echo -e "\033[32m[+] Agent started with PID $PID\033[0m"
echo "Log: $WORK_DIR/agent.log"
