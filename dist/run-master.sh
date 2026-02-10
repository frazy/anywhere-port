#!/bin/bash

APP_NAME="awport-master"
NEW_BINARY="awport-master_linux_amd64"
LOG_FILE="master.log"

echo "=== Anywhere-Port Deploy Script ==="

# 1. Stop existing process
# Filter by name, exclude current script (if name matches), exclude grep
PID=$(ps -ef | grep "$APP_NAME" | grep -v "$NEW_BINARY" | grep -v "grep" | grep -v "run.sh" | awk '{print $2}')

if [ -n "$PID" ]; then
    echo "[*] Stopping existing $APP_NAME (PID: $PID)..."
    kill $PID
    
    # Wait loop
    for i in {1..10}; do
        if ! ps -p $PID > /dev/null; then
            break
        fi
        echo "    Waiting for shutdown..."
        sleep 1
    done

    # Force kill if necessary
    if ps -p $PID > /dev/null; then
        echo "[!] Process hung, force killing..."
        kill -9 $PID
    fi
    echo "[+] Process stopped."
else
    echo "[*] $APP_NAME is not running."
fi

# 2. Update binary
if [ -f "$NEW_BINARY" ]; then
    echo "[*] Found new binary: $NEW_BINARY"
    
    # Backup old if exists
    if [ -f "$APP_NAME" ]; then
        mv "$APP_NAME" "${APP_NAME}.bak"
    fi
    
    mv "$NEW_BINARY" "$APP_NAME"
    chmod +x "$APP_NAME"
    echo "[+] Binary updated."
elif [ -f "$APP_NAME" ]; then
    echo "[*] No new binary found, using existing $APP_NAME."
else
    echo "[-] Error: Binary $APP_NAME not found!"
    exit 1
fi

# 3. Start
echo "[*] Starting $APP_NAME..."
nohup ./$APP_NAME > "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "[+] Started with PID: $NEW_PID"
echo "    Log file: $LOG_FILE"
