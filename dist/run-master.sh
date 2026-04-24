#!/bin/bash
set -e

# 自动获取脚本所在的绝对路径（支持软链接解析）
DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" || echo "${BASH_SOURCE[0]}")")" && pwd)"
cd "$DIR"

APP_NAME="awport-master"
NEW_BINARY="awport-master_linux_amd64"
LOG_FILE="info.log"
SERVICE_NAME="awport-master.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "[-] 此操作需要管理员权限，请使用 sudo 或以 root 用户身份运行。"
        exit 1
    fi
}

# 辅助函数：检查服务是否已安装
check_service_installed() {
    if [ ! -f "$SERVICE_FILE" ]; then
        echo "[-] 错误: 服务尚未安装，请先选择选项 1。"
        return 1
    fi
    return 0
}

# 辅助函数：等待用户按键
pause() {
    read -n 1 -s -r -p $'\n按任意键返回菜单...'
}

install_service() {
    check_root
    echo "[*] 正在安装 Systemd 服务..."
    
    # 确保二进制文件具有执行权限
    chmod +x "${DIR}/${APP_NAME}" 2>/dev/null || true

    # 为路径增加引号保护，防止路径包含空格导致失败
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Anywhere-Port Master Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=${DIR}
# 将服务的标准输出和错误输出重定向到 info.log
ExecStart=/bin/bash -c "exec '${DIR}/${APP_NAME}' >> '${DIR}/${LOG_FILE}' 2>&1"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    # 安装后尝试启动服务
    systemctl start "$SERVICE_NAME"
    echo "[+] 服务安装成功并已尝试启动！(已设置为开机自启)"
    echo "[提示] 日志文件 ${LOG_FILE} 会随运行持续增长，建议后续手动配置 logrotate 进行管理。"
    pause
}

uninstall_service() {
    check_root
    echo "[*] 正在卸载 Systemd 服务..."
    
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        echo "    已停止服务。"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
        echo "    已取消开机自启。"
    fi
    
    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        echo "    已删除服务配置文件。"
    fi
    
    systemctl daemon-reload
    echo "[+] 服务已彻底卸载。"
    pause
}

update_and_restart() {
    # 增加服务安装检查
    if ! check_service_installed; then
        pause
        return
    fi

    if [ -f "$NEW_BINARY" ]; then
        echo "[*] 发现新的二进制文件: $NEW_BINARY"
        
        echo "[*] 停止服务..."
        systemctl stop "$SERVICE_NAME" || true

        if [ -f "$APP_NAME" ]; then
            # 使用时间戳备份，防止覆盖旧备份
            BACKUP_NAME="${APP_NAME}.$(date +%Y%m%d_%H%M%S).bak"
            mv "$APP_NAME" "$BACKUP_NAME"
            echo "    已将旧版本备份为: $BACKUP_NAME"
        fi

        mv "$NEW_BINARY" "$APP_NAME"
        chmod +x "$APP_NAME"
        echo "[+] 二进制文件已更新。"
        
        echo "[*] 启动服务..."
        systemctl start "$SERVICE_NAME"
        echo "[+] 部署并重启完成。"
    elif [ -f "$APP_NAME" ]; then
        echo "[*] 未发现新包文件，重新启动现有服务..."
        systemctl restart "$SERVICE_NAME"
        echo "[+] 服务已重启。"
    else
        echo "[-] 错误: 找不到可执行文件 $APP_NAME 并且没有新的包 $NEW_BINARY"
    fi
    pause
}

show_menu() {
    echo ""
    echo "=== Anywhere-Port Master 部署管理菜单 ==="
    echo "1) 安装 Systemd 服务 (需 root)"
    echo "2) 卸载 Systemd 服务 (需 root)"
    echo "3) 更新文件并重启服务 (若存在新包)"
    echo "4) 启动服务"
    echo "5) 停止服务"
    echo "6) 重启服务"
    echo "7) 查看服务状态"
    echo "8) 实时查看日志 (info.log)"
    echo "0) 退出"
    echo "========================================="
    read -p "请输入对应数字进行操作: " choice
    echo ""
    case $choice in
        1) install_service ;;
        2) uninstall_service ;;
        3) update_and_restart ;;
        # 增加服务存在性检查和 || true 保护，防止 set -e 导致脚本退出
        4) check_service_installed && (systemctl start "$SERVICE_NAME" && echo "[+] 服务已启动" || echo "[-] 启动失败") && pause || pause ;;
        5) check_service_installed && (systemctl stop "$SERVICE_NAME" && echo "[+] 服务已停止" || echo "[-] 停止失败") && pause || pause ;;
        6) check_service_installed && (systemctl restart "$SERVICE_NAME" && echo "[+] 服务已重启" || echo "[-] 重启失败") && pause || pause ;;
        7) check_service_installed && (systemctl status "$SERVICE_NAME" || true) && pause || pause ;;
        # 增加 || true 防止 tail -f 被 Ctrl+C 终止时导致脚本退出
        8) if [ -f "${DIR}/${LOG_FILE}" ]; then tail -f "${DIR}/${LOG_FILE}" || true; else echo "[-] 日志文件不存在"; pause; fi ;;
        0) echo "退出。"; exit 0 ;;
        *) echo "[-] 无效的选择，请重试。" ;;
    esac
}

# 增加参数调用功能（如果不传参数则显示菜单）
if [ $# -gt 0 ]; then
    case "$1" in
        install) install_service ;;
        uninstall) uninstall_service ;;
        update) update_and_restart ;;
        start) systemctl start "$SERVICE_NAME" || true ;;
        stop) systemctl stop "$SERVICE_NAME" || true ;;
        restart) systemctl restart "$SERVICE_NAME" || true ;;
        status) systemctl status "$SERVICE_NAME" || true ;;
        log) tail -f "${DIR}/${LOG_FILE}" || true ;;
        *) echo "用法: $0 [install|uninstall|update|start|stop|restart|status|log]"; exit 1 ;;
    esac
else
    while true; do
        show_menu
    done
fi
