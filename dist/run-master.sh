#!/bin/bash
set -e

APP_NAME="awport-master"
NEW_BINARY="awport-master_linux_amd64"
LOG_FILE="master.log"
PID_FILE="${APP_NAME}.pid"

echo "=== Anywhere-Port Deploy Script ==="

# 1. Stop existing process (via PID file)
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[*] Stopping existing $APP_NAME (PID: $OLD_PID)..."
        kill "$OLD_PID"

        # Wait loop
        for i in $(seq 1 10); do
            if ! kill -0 "$OLD_PID" 2>/dev/null; then
                break
            fi
            echo "    Waiting for shutdown... ($i/10)"
            sleep 1
        done

        # Force kill if necessary
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "[!] Process hung, force killing..."
            kill -9 "$OLD_PID"
        fi
        echo "[+] Process stopped."
    else
        echo "[*] Stale PID file found, cleaning up."
    fi
    rm -f "$PID_FILE"
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
echo "=== $(date '+%Y-%m-%d %H:%M:%S') ===" >> "$LOG_FILE"
nohup ./$APP_NAME >> "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"

# 4. Verify startup
sleep 1
if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "[+] Started successfully (PID: $NEW_PID)"
    echo "    Log file: $LOG_FILE"
else
    echo "[-] Error: Process exited immediately! Check $LOG_FILE for details."
    rm -f "$PID_FILE"
    exit 1
fi
