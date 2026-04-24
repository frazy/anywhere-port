#!/bin/bash
set -e

# ==============================================================================
# Anywhere-Port Agent Installer (Advanced Version)
# ==============================================================================
# Injected Template Parameters (DO NOT REMOVE)
MASTER="{{.MasterAddr}}"
ID="{{.AgentID}}"
TOKEN="{{.Token}}"
DOWNLOAD_URL="{{.DownloadUrl}}/awport-agent_linux_amd64"

# --- System Configuration ---
APP_NAME="awport-agent"
SERVICE_NAME="awport-agent.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
WORK_DIR="/root/anywhere-port"
BINARY="${WORK_DIR}/${APP_NAME}"
LOG_FILE="info.log"

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "\033[31m[-] 此操作需要管理员权限，请使用 sudo 或以 root 用户身份运行。\033[0m"
        exit 1
    fi
}

# 辅助函数：显示横幅
show_banner() {
    echo -e "\033[36m"
    echo "    ___                            __                         ____                __ "
    echo "   /   |  ____  __  ___      _____/ /_  ___  ________        / __ \____  ________/ /_"
    echo "  / /| | / __ \/ / / / | /| / / ___/ __ \/ _ \/ ___/ _ \      / /_/ / __ \/ ___/ __/ __/"
    echo " / ___ |/ / / / /_/ /| |/ |/ /__  / / / /  __/ /  /  __/     / ____/ /_/ / /  / /_/ /_  "
    echo "/_/  |_/_/ /_/\__, / |__/|__/\___/_/ /_/\___/_/   \___/     /_/    \____/_/   \__/\__/  "
    echo "             /____/                                                                  "
    echo -e "\033[0m"
    echo "--------------------------------------------------------------------------------"
    echo " Master: $MASTER"
    echo " Agent ID: $ID"
    echo "--------------------------------------------------------------------------------"
}

# 辅助函数：等待用户按键
pause() {
    read -n 1 -s -r -p $'\n按任意键返回菜单...'
}

# 检查服务是否已安装
check_service_installed() {
    if [ ! -f "$SERVICE_FILE" ]; then
        echo -e "\033[33m[-] 错误: 服务尚未安装，请先选择选项 1。\033[0m"
        return 1
    fi
    return 0
}

# 核心功能：下载二进制文件（增强版：原子替换 + 超时保护）
download_binary() {
    local target="$1"
    local tmp_target="${target}.tmp"
    echo "[*] 正在从 $DOWNLOAD_URL 下载 Agent..."
    mkdir -p "$WORK_DIR"
    
    # 增加超时保护，防止弱网死锁
    if command -v curl &> /dev/null; then
        curl -fSL --connect-timeout 10 --max-time 120 "$DOWNLOAD_URL" -o "$tmp_target"
    elif command -v wget &> /dev/null; then
        wget -q -T 60 "$DOWNLOAD_URL" -O "$tmp_target"
    else
        echo -e "\033[31m[!] 未找到 curl 或 wget，无法下载。\033[0m"
        return 1
    fi

    if [ ! -s "$tmp_target" ]; then
        echo -e "\033[31m[!] 下载失败或文件为空。\033[0m"
        rm -f "$tmp_target"
        return 1
    fi
    
    chmod +x "$tmp_target"
    mv -f "$tmp_target" "$target"
    return 0
}

# 核心功能：安装并注册服务（增强版：清理旧版 + 安全权限控制）
install_service() {
    check_root
    echo "[*] 正在配置系统服务..."

    # 1. 清理旧版残留 (兼容性处理)
    if [ -f "${WORK_DIR}/agent.pid" ]; then
        echo "[*] 检测到旧版 PID 文件，正在清理..."
        local old_pid=$(cat "${WORK_DIR}/agent.pid" 2>/dev/null || true)
        [ -n "$old_pid" ] && kill "$old_pid" 2>/dev/null || true
        rm -f "${WORK_DIR}/agent.pid"
    fi

    # 2. 下载二进制
    download_binary "$BINARY" || return 1

    # 3. 写入服务文件
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Anywhere-Port Agent Service ($ID)
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=${WORK_DIR}
ExecStart=/bin/bash -c "exec '${BINARY}' -master '${MASTER}' -id '${ID}' -token '${TOKEN}' >> '${WORK_DIR}/${LOG_FILE}' 2>&1"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    chmod 600 "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    echo -e "\033[32m[+] 服务安装/更新成功并已启动！\033[0m"

    # 4. 核心黑科技：生成/更新管理脚本 (支持管道模式运行时的自复制)
    save_management_script
}

# 核心黑科技：将内存中的函数和变量导出为独立的管理脚本
save_management_script() {
    local self_path="${WORK_DIR}/run-agent.sh"
    echo "[*] 正在生成本地管理工具..."
    
    # 写入基础配置变量
    cat > "$self_path" <<EOF
#!/bin/bash
set -e

# --- 自动生成的静态配置 ---
MASTER='${MASTER}'
ID='${ID}'
TOKEN='${TOKEN}'
DOWNLOAD_URL='${DOWNLOAD_URL}'
APP_NAME='${APP_NAME}'
SERVICE_NAME='${SERVICE_NAME}'
SERVICE_FILE='${SERVICE_FILE}'
WORK_DIR='${WORK_DIR}'
BINARY='${BINARY}'
LOG_FILE='${LOG_FILE}'

EOF

    # 关键：导出当前脚本定义的所有函数
    declare -f >> "$self_path"

    # 写入执行入口
    cat >> "$self_path" <<'EOF'

# --- 脚本执行入口 ---
if [ $# -gt 0 ]; then
    case "$1" in
        install) install_service ;;
        uninstall) uninstall_service ;;
        update) update_agent ;;
        status) check_service_installed && (systemctl status "$SERVICE_NAME" || true) ;;
        log) if [ -f "${WORK_DIR}/${LOG_FILE}" ]; then tail -f "${WORK_DIR}/${LOG_FILE}" || true; fi ;;
        *) echo "Usage: $0 {install|uninstall|update|status|log}"; exit 1 ;;
    esac
else
    if [ -t 0 ]; then
        while true; do show_menu; done
    else
        install_service
    fi
fi
EOF

    chmod +x "$self_path"
    echo -e "\033[32m[+] 管理脚本已就位: $self_path\033[0m"
}

# 核心功能：卸载服务
uninstall_service() {
    check_root
    echo "[*] 正在卸载服务..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo -e "\033[32m[+] 服务已完全卸载。\033[0m"
}

# 核心功能：仅更新 Agent 二进制（增强版：带时间戳备份）
update_agent() {
    echo "[*] 正在检查二进制更新..."
    local tmp_bin="${BINARY}.new"
    if download_binary "$tmp_bin"; then
        echo "[*] 停止当前运行的实例..."
        systemctl stop "$SERVICE_NAME" || true
        
        if [ -f "$BINARY" ]; then
            local bak="${BINARY}.$(date +%Y%m%d_%H%M%S).bak"
            mv "$BINARY" "$bak"
            echo "    已备份旧版本为: $bak"
        fi
        
        mv "$tmp_bin" "$BINARY"
        echo "[*] 重启服务..."
        systemctl start "$SERVICE_NAME"
        echo -e "\033[32m[+] Agent 二进制已成功更新。\033[0m"
    else
        echo -e "\033[31m[-] 更新失败。\033[0m"
    fi
}

show_menu() {
    show_banner
    echo " 1) 安装 / 修复 Systemd 服务 (Full Deploy)"
    echo " 2) 卸载 Systemd 服务"
    echo " 3) 仅更新 Agent 二进制文件"
    echo " 4) 启动服务"
    echo " 5) 停止服务"
    echo " 6) 重启服务"
    echo " 7) 查看运行状态"
    echo " 8) 实时查看日志 (info.log)"
    echo " 0) 退出"
    echo "--------------------------------------------------------------------------------"
    read -p "请输入操作序号: " choice
    echo ""
    case $choice in
        1) install_service; pause ;;
        2) uninstall_service; pause ;;
        3) update_agent; pause ;;
        4) check_service_installed && (systemctl start "$SERVICE_NAME" && echo "[+] 已启动") || true; pause ;;
        5) check_service_installed && (systemctl stop "$SERVICE_NAME" && echo "[+] 已停止") || true; pause ;;
        6) check_service_installed && (systemctl restart "$SERVICE_NAME" && echo "[+] 已重启") || true; pause ;;
        7) check_service_installed && (systemctl status "$SERVICE_NAME" || true); pause ;;
        8) if [ -f "${WORK_DIR}/${LOG_FILE}" ]; then tail -f "${WORK_DIR}/${LOG_FILE}" || true; else echo "[-] 日志尚未产生"; pause; fi ;;
        0) exit 0 ;;
        *) echo "[-] 无效选择"; sleep 1 ;;
    esac
}

# --- 执行入口 ---
if [ $# -gt 0 ]; then
    case "$1" in
        install) install_service ;;
        uninstall) uninstall_service ;;
        update) update_agent ;;
        *) echo "Usage: $0 {install|uninstall|update}"; exit 1 ;;
    esac
else
    # 交互式终端检查
    if [ -t 0 ]; then
        # 首次运行检查
        if [ ! -f "$BINARY" ]; then
            echo -e "\033[36m[*] 检测到初次运行，正在自动安装...\033[0m"
            install_service || true
        fi
        # 进入交互菜单
        while true; do
            show_menu
        done
    else
        # 非交互模式（Pipe 模式）：直接执行安装/覆盖逻辑，确保自动化脚本有效
        echo -e "\033[36m[*] 检测到非交互运行模式，开始自动部署/更新...\033[0m"
        install_service
        echo "[*] 自动化部署任务完成。"
    fi
fi
