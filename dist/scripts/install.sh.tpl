#!/bin/bash
set -e

# Anywhere-Port Agent Installer for Linux

MASTER="{{.MasterAddr}}"
ID="{{.AgentID}}"
TOKEN="{{.Token}}"
DOWNLOAD_URL="{{.DownloadUrl}}/awport-agent_linux_amd64"

echo -e "\033[36mAnywhere-Port Agent Installer\033[0m"
echo "-----------------------------"
echo "Master: $MASTER"
echo "ID:     $ID"

WORK_DIR="$HOME/anywhere-port"
PID_FILE="$WORK_DIR/agent.pid"
BINARY="$WORK_DIR/awport-agent"
TMP_BINARY="$WORK_DIR/awport-agent.new"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR" || exit 1

# 1. Download to temp file first (avoids "Text file busy")
echo "Downloading agent from $DOWNLOAD_URL..."
if command -v curl &> /dev/null; then
    curl -fSL "$DOWNLOAD_URL" -o "$TMP_BINARY"
elif command -v wget &> /dev/null; then
    wget -q "$DOWNLOAD_URL" -O "$TMP_BINARY"
else
    echo -e "\033[31m[!] Neither curl nor wget found.\033[0m"
    exit 1
fi

# Verify download
if [ ! -s "$TMP_BINARY" ]; then
    echo -e "\033[31m[!] Download failed or file is empty.\033[0m"
    rm -f "$TMP_BINARY"
    exit 1
fi
chmod +x "$TMP_BINARY"

# 2. Stop old agent AFTER download succeeds
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[*] Stopping old agent (PID: $OLD_PID)..."
        kill "$OLD_PID"
        for i in $(seq 1 5); do
            kill -0 "$OLD_PID" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$OLD_PID" 2>/dev/null && kill -9 "$OLD_PID"
        sleep 1
    fi
    rm -f "$PID_FILE"
fi

# 3. Replace binary (mv is atomic, no "Text file busy")
mv -f "$TMP_BINARY" "$BINARY"

# 4. Start
echo "Starting agent..."
echo "=== $(date '+%Y-%m-%d %H:%M:%S') ===" >> agent.log
nohup "$BINARY" -master "$MASTER" -id "$ID" -token "$TOKEN" >> agent.log 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"

sleep 1
if kill -0 "$PID" 2>/dev/null; then
    echo -e "\033[32m[+] Agent started with PID $PID\033[0m"
    echo "Log: $WORK_DIR/agent.log"
else
    echo -e "\033[31m[-] Agent failed to start! Check agent.log\033[0m"
    rm -f "$PID_FILE"
    exit 1
fi
