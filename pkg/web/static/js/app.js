const API_URL = '/api/rules';
let currentState = {
    selectedNodeId: null,
    nodes: [],
    rules: [],
    topRowStartIndex: 0,
    sidebarAutoTriggered: false
};

// HTML 转义，防止 XSS
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Bootstrap Modals
let editModal, deleteModal, registerModal, confirmModal, nodeEditModal;

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Modals
    editModal = new bootstrap.Modal(document.getElementById('editModal'));
    deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
    registerModal = new bootstrap.Modal(document.getElementById('registerModal'));
    confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));
    nodeEditModal = new bootstrap.Modal(document.getElementById('nodeEditModal'));

    // Initial Load
    fetchData();

    // Polling
    setInterval(fetchData, 2000);

    // Event Listeners
    setupEventListeners();

    // Check hash for direct node selection
    if (window.location.hash) {
        selectNode(window.location.hash.substring(1));
    }
});

function setupEventListeners() {
    document.getElementById('addForm').addEventListener('submit', handleAddRule);
    document.getElementById('registerForm').addEventListener('submit', handleRegisterSubmit);
}

async function toggleSidebar(force) {
    const sidebar = document.getElementById('node-sidebar');
    if (!sidebar) return;

    const isActive = typeof force === 'boolean' ? force : !sidebar.classList.contains('active');

    if (isActive) {
        sidebar.classList.add('active');
    } else {
        sidebar.classList.remove('active');
    }
}

async function fetchData() {
    await Promise.all([loadNodes(), loadRules()]);
    renderUI();
}

async function loadNodes() {
    try {
        const res = await fetch('/api/cluster/nodes');
        if (!res.ok) return;
        currentState.nodes = await res.json();
    } catch (err) { }
}

async function loadRules() {
    try {
        const res = await fetch(API_URL);
        if (res.status === 401) {
            window.location.href = '/login';
            return;
        }
        currentState.rules = await res.json();
    } catch (err) { }
}

function renderUI() {
    renderNodes();
    renderRules();
}

function renderNodes() {
    const list = document.getElementById('node-list');
    const sidebarList = document.getElementById('sidebar-list');
    const handle = document.getElementById('sidebar-toggle-handle');

    if (!list || !sidebarList) return;
    list.innerHTML = '';
    sidebarList.innerHTML = '';

    if (currentState.nodes.length === 0) {
        if (handle) handle.style.visibility = 'hidden';
        list.innerHTML = '<div class="py-4 text-center text-muted flex-grow-1">尚未注册任何节点</div>';
        return;
    }

    // 1. 稳态排序
    currentState.nodes.sort((a, b) => a.id.localeCompare(b.id));

    // 2. 规模感知：控制一体化手柄可见性
    if (currentState.nodes.length > 4) {
        if (handle) handle.style.visibility = 'visible';
        if (!currentState.sidebarAutoTriggered) {
            toggleSidebar(true);
            currentState.sidebarAutoTriggered = true;
        }
    } else {
        if (handle) handle.style.visibility = 'hidden';
    }

    // 3. 渲染全部节点到侧边栏
    currentState.nodes.forEach((node, absoluteIndex) => {
        const isActive = node.id === currentState.selectedNodeId ? 'active' : '';
        const statusColor = node.status === 'online' ? 'text-success' : 'text-danger';
        const alias = node.hostname ? `(${escapeHtml(node.hostname)})` : '';
        const backupBadge = node.is_backup ? `<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" fill="currentColor" class="text-info" viewBox="0 0 16 16" title="冗余备份节点" style="transform: translateY(1px);"><path fill-rule="evenodd" d="M7.646 5.146a.5.5 0 0 1 .708 0l2 2a.5.5 0 0 1-.708.708L8.5 6.707V10.5a.5.5 0 0 1-1 0V6.707L6.354 7.854a.5.5 0 1 1-.708-.708z"/><path d="M4.406 3.342A5.53 5.53 0 0 1 8 2c2.69 0 4.923 2 5.166 4.579.066.646-.083 1.258-.405 1.763l-.01.015a.5.5 0 0 1-.849-.526L11.9 7.82c.204-.32.302-.712.261-1.125C11.967 4.53 10.19 3 8 3c-2.015 0-3.693 1.258-4.28 3h.526a.5.5 0 0 1 0 1H2.5a.5.5 0 0 1-.5-.5V4.5a.5.5 0 0 1 1 0v.581c.642-1.74 2.37-3.239 4.406-3.739z"/></svg> ` : '';

        sidebarList.innerHTML += `
            <div class="sidebar-item ${isActive}" onclick="handleNodeSelection('${node.id}', ${absoluteIndex})">
                <div class="d-flex justify-content-between align-items-center">
                    <div class="text-truncate" style="max-width: 220px;">
                        <strong>${escapeHtml(node.id)}</strong> <small class="text-muted">${alias}</small>
                    </div>
                    <div class="d-flex align-items-center gap-1">
                        ${backupBadge}
                        <span class="${statusColor}" style="font-size: 0.6rem;">●</span>
                    </div>
                </div>
            </div>
        `;
    });

    // 4. 计算顶部行的展示范围 (智能窗口)
    // 确保 startIndex 合法
    let startIndex = currentState.topRowStartIndex;
    if (startIndex + 4 > currentState.nodes.length) {
        startIndex = Math.max(0, currentState.nodes.length - 4);
    }

    const displayNodes = currentState.nodes.slice(startIndex, startIndex + 4);

    displayNodes.forEach(node => {
        const isActive = node.id === currentState.selectedNodeId ? 'active' : '';
        const statusColor = node.status === 'online' ? 'text-success' : 'text-danger';
        const alias = node.hostname ? `(${escapeHtml(node.hostname)})` : '';

        const memInfo = node.mem_total ? `${(node.mem_used / 1024).toFixed(1)} / ${(node.mem_total / 1024).toFixed(1)} GB` : '---';
        const diskUsagePercent = node.disk_total ? Math.round((node.disk_used / node.disk_total) * 100) : 0;
        const uptimeStr = node.uptime ? formatUptime(node.uptime) : '---';

        const statsHtml = node.status === 'online' ? `
            <div class="row g-2 mt-2">
                <div class="col-6">
                    <div class="d-flex justify-content-between small text-muted mb-1" style="font-size: 0.75rem;">
                        <span>CPU</span>
                        <span>${node.cpu_usage.toFixed(1)}%</span>
                    </div>
                    <div class="progress" style="height: 4px; background-color: rgba(0,0,0,0.05);">
                        <div class="progress-bar bg-primary" style="width: ${node.cpu_usage}%"></div>
                    </div>
                </div>
                <div class="col-6">
                    <div class="d-flex justify-content-between small text-muted mb-1" style="font-size: 0.75rem;">
                         <span>MEM</span>
                         <span>${((node.mem_used || 0) / 1024).toFixed(1)}G</span>
                    </div>
                    <div class="progress" style="height: 4px; background-color: rgba(0,0,0,0.05);">
                        <div class="progress-bar bg-info" style="width: ${Math.round((node.mem_used / node.mem_total) * 100)}%"></div>
                    </div>
                </div>
            </div>
                <div class="node-meta-grid mt-2 pt-2 border-top border-light">
                    <div class="meta-item"><span class="meta-label">CPU:</span>${node.cpu_model || 'Unknown'}</div>
                    <div class="meta-item"><span class="meta-label">OS:</span>${node.os_version || 'Unknown'}</div>
                    <div class="meta-item"><span class="meta-label">DISK:</span>${diskUsagePercent}% (${(node.disk_used / 1024).toFixed(0)}G / ${(node.disk_total / 1024).toFixed(0)}G)
                        <div class="disk-progress"><div class="disk-bar" style="width: ${diskUsagePercent}%"></div></div>
                    </div>
                    <div class="meta-item"><span class="meta-label">UP:</span>${uptimeStr}</div>
                </div>
            </div>
        ` : '<div class="mt-2 text-center text-muted small bg-light rounded flex-grow-1 d-flex align-items-center justify-content-center">AGENT OFFLINE</div>';

        list.innerHTML += `
            <div class="card p-3 clickable-node ${isActive}" onclick="selectNode('${node.id}')">
                <div class="node-card-header mb-1">
                    <div class="node-title-group">
                        <div class="fw-bold text-truncate-auto">
                            ${escapeHtml(node.id)} <span class="text-muted fw-normal small">${alias}</span>
                        </div>
                    </div>
                    <div class="d-flex align-items-center gap-1">
                        ${node.is_backup ? `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="text-info" viewBox="0 0 16 16" title="冗余备份节点" style="transform: translateY(1.5px);"><path fill-rule="evenodd" d="M7.646 5.146a.5.5 0 0 1 .708 0l2 2a.5.5 0 0 1-.708.708L8.5 6.707V10.5a.5.5 0 0 1-1 0V6.707L6.354 7.854a.5.5 0 1 1-.708-.708z"/><path d="M4.406 3.342A5.53 5.53 0 0 1 8 2c2.69 0 4.923 2 5.166 4.579.066.646-.083 1.258-.405 1.763l-.01.015a.5.5 0 0 1-.849-.526L11.9 7.82c.204-.32.302-.712.261-1.125C11.967 4.53 10.19 3 8 3c-2.015 0-3.693 1.258-4.28 3h.526a.5.5 0 0 1 0 1H2.5a.5.5 0 0 1-.5-.5V4.5a.5.5 0 0 1 1 0v.581c.642-1.74 2.37-3.239 4.406-3.739z"/></svg>` : ''}
                        <div class="node-status-badge ${statusColor} small" style="font-size: 0.7rem;">● ${node.status.toUpperCase()}</div>
                    </div>
                </div>
                <div class="text-muted small d-flex justify-content-between align-items-center mb-1" style="font-size: 0.75rem; opacity: 0.8;">
                    <span>${node.ip || '0.0.0.0'}</span>
                    <span class="font-monospace">${node.version || 'v?'}</span>
                </div>
                ${statsHtml}
            </div>
        `;
    });

    updateGlobalStats();
}

/**
 * 处理节点选中逻辑 (侧边栏专用)
 * @param {string} id 节点ID
 * @param {number} index 在全局节点列表中的索引
 */
window.handleNodeSelection = function (id, index) {
    // 1. 设置位移焦点：将选中的节点推至顶部行首位，除非余量不足补齐4窗口
    currentState.topRowStartIndex = Math.min(index, Math.max(0, currentState.nodes.length - 4));

    // 2. 执行标准选中逻辑
    selectNode(id);
}

function formatUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

function selectNode(id) {
    currentState.selectedNodeId = id;
    const node = currentState.nodes.find(n => n.id === id);
    renderUI();

    document.getElementById('management-area').style.display = 'flex';
    document.getElementById('input-node-id').value = id;
    document.getElementById('selected-node-display').textContent = '当前管理节点: ' + id;

    // Update Connection Command
    updateCommandDisplay();

    // Update hash for deep linking
    window.location.hash = id;
}

window.updateCommandDisplay = function () {
    const id = currentState.selectedNodeId;
    const node = currentState.nodes.find(n => n.id === id);
    if (!node) return;

    const os = node.os || 'linux'; // 使用节点持久化的 OS
    const host = window.location.host;
    const scriptUrl = `${window.location.protocol}//${host}/api/cluster/connect/script?id=${node.id}&token=${node.token || ''}&os=${os}`;

    let cmd = "";
    if (os === "windows") {
        cmd = `powershell -ExecutionPolicy Bypass -Command "irm '${scriptUrl}' | iex"`;
    } else {
        cmd = `curl -sL "${scriptUrl}" | bash`;
    }
    document.getElementById('node-connect-cmd').value = cmd;
}

window.copySelectCommand = function () {
    const text = document.getElementById('node-connect-cmd').value;
    navigator.clipboard.writeText(text).then(() => {
        showToast('命令已复制到剪贴板', 'success');
    }).catch(() => {
        // Fallback for older browsers
        const el = document.getElementById('node-connect-cmd');
        el.select();
        document.execCommand('copy');
        showToast('命令已复制到剪贴板', 'success');
    });
}

window.openNodeEdit = function () {
    const id = currentState.selectedNodeId;
    const node = currentState.nodes.find(n => n.id === id);
    if (!node) return;

    document.getElementById('node-edit-id').value = id;
    document.getElementById('node-edit-comment').value = node.hostname || '';

    // 设置 OS 单选按钮
    const os = node.os || 'linux';
    const osRadio = document.getElementById(`node-edit-os-${os}`);
    if (osRadio) osRadio.checked = true;

    // 设置备份节点勾选框
    document.getElementById('node-edit-is-backup').checked = !!node.is_backup;

    nodeEditModal.show();
}

window.saveNodeEdit = async function () {
    const id = document.getElementById('node-edit-id').value;
    const comment = document.getElementById('node-edit-comment').value;
    const os = document.querySelector('input[name="node-edit-os"]:checked').value;
    const is_backup = document.getElementById('node-edit-is-backup').checked;

    try {
        const res = await fetch('/api/cluster/nodes/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, comment, os, is_backup })
        });

        if (res.ok) {
            nodeEditModal.hide();
            showToast('节点信息已更新', 'success');
            fetchData();
        } else {
            showToast('更新失败: ' + await res.text(), 'danger');
        }
    } catch (err) {
        showToast('更新失败: 网络错误', 'danger');
    }
}

window.resetNodeToken = async function () {
    const id = currentState.selectedNodeId;
    if (!id) return;

    const ok = await showConfirm(
        `确认重置节点 ${id} 的 Token？重置后现有的 Agent 将无法连接，直到您更新命令重启。`,
        '重置安全凭证'
    );
    if (!ok) return;

    try {
        const resp = await fetch('/api/cluster/nodes/reset', {
            method: 'POST',
            body: JSON.stringify({ id })
        });
        if (!resp.ok) throw new Error(await resp.text());

        const data = await resp.json();
        const node = currentState.nodes.find(n => n.id === id);
        if (node) {
            node.token = data.token;
            selectNode(id); // 刷新显示
            showToast('Token 已重置，请更新 Agent 启动命令', 'success');
        }
    } catch (err) {
        showError(err.message);
    }
}

function renderRules() {
    if (!currentState.selectedNodeId) {
        document.getElementById('management-area').style.display = 'none';
        document.getElementById('empty-management-state').style.display = 'flex';
        return;
    }

    document.getElementById('empty-management-state').style.display = 'none';
    const tbody = document.getElementById('ruleTable');
    const filteredRules = currentState.rules.filter(r => r.node_id === currentState.selectedNodeId);

    document.getElementById('rule-count').textContent = `(${filteredRules.length})`;

    filteredRules.sort((a, b) => a.id.localeCompare(b.id));

    let html = '';
    if (filteredRules.length === 0) {
        html = `<tr><td colspan="7" class="text-center text-muted py-4">该节点暂无转发规则</td></tr>`;
    } else {
        html = filteredRules.map(r => {
            const speedDisplay = r.speed_limit > 0 ? formatBytes(r.speed_limit) + '/s' : '∞';
            const quotaDisplay = r.total_quota > 0 ? formatBytes(r.total_quota) : '∞';
            const used = formatBytes(r.used_traffic || 0);
            const badgeClass = r.protocol === 'tcp' ? 'badge-tcp' : 'badge-udp';
            const commentSafe = escapeHtml(r.comment || '').replace(/'/g, "\\'");

            return `
                <tr>
                    <td class="table-mono">${r.listen_addr}</td>
                    <td class="table-mono text-truncate" style="max-width: 0;" title="${r.remote_addr}">${r.remote_addr}</td>
                    <td><span class="badge ${badgeClass}">${r.protocol.toUpperCase()}</span></td>
                    <td class="text-end table-mono">
                         <span class="clickable-edit" onclick="openEdit('${r.id}', ${r.speed_limit || 0}, ${r.total_quota || 0}, '${commentSafe}')">
                            ${speedDisplay}
                        </span>
                    </td>
                    <td class="text-end table-mono">
                         <span class="clickable-edit" onclick="openEdit('${r.id}', ${r.speed_limit || 0}, ${r.total_quota || 0}, '${commentSafe}')">
                            ${used} / ${quotaDisplay}
                        </span>
                    </td>
                    <td>${escapeHtml(r.comment || '')}</td>
                    <td class="text-center">
                        <button class="btn btn-sm btn-outline-danger" onclick="openDelete('${r.id}')">删除</button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    tbody.innerHTML = html;
}

async function handleAddRule(e) {
    e.preventDefault();
    if (!currentState.selectedNodeId) return;

    const formData = new FormData(e.target);
    let listenAddr = formData.get('listen_addr').trim();
    const remoteAddr = formData.get('remote_addr').trim();
    const protocol = formData.get('protocol');
    const speedKB = parseInt(formData.get('speed_limit')) || 0;
    const quotaMB = parseInt(formData.get('total_quota')) || 0;

    // 1. 端口自动补齐逻辑: 如果只输入数字，自动补齐开头的冒号
    if (/^\d+$/.test(listenAddr)) {
        listenAddr = ':' + listenAddr;
    }

    // 2. 合法性检查
    // 监听地址: 支持 :port, ip:port, [ipv6]:port
    const listenRegex = /^(\[([0-9a-fA-F:]+)\]|([0-9.]+)|):(\d+)$/;
    if (!listenRegex.test(listenAddr)) {
        showError('监听地址格式错误（正确示例：:8080 或 0.0.0.0:8080）');
        return;
    }

    // 远程目标: 支持 host:port (host 可以是 IP 或 域名)
    const remoteRegex = /^(\[([0-9a-fA-F:]+)\]|([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}|[0-9.]+|localhost):(\d+)$/;
    if (!remoteRegex.test(remoteAddr)) {
        showError('远程目标格式错误（正确示例：1.2.3.4:80 或 example.com:443）');
        return;
    }

    const data = {
        node_id: currentState.selectedNodeId,
        listen_addr: listenAddr,
        remote_addr: remoteAddr,
        protocol: protocol,
        speed_limit: speedKB * 1024,
        total_quota: quotaMB * 1024 * 1024,
        comment: formData.get('comment')
    };

    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (res.ok) {
            e.target.reset();
            document.getElementById('input-node-id').value = currentState.selectedNodeId;
            fetchData();
        } else {
            showError('Error: ' + await res.text());
        }
    } catch (err) {
        showError('Request failed');
    }
}

// Register Node Logic
window.openRegister = function () {
    document.getElementById('reg-id').value = '';
    document.getElementById('reg-comment').value = '';
    document.getElementById('reg-result').style.display = 'none';
    document.getElementById('reg-form-area').style.display = 'block';
    registerModal.show();
}

async function handleRegisterSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('reg-id').value;
    const comment = document.getElementById('reg-comment').value;

    try {
        const os = document.querySelector('input[name="reg-os"]:checked').value;
        const is_backup = document.getElementById('reg-is-backup').checked;
        const res = await fetch('/api/cluster/nodes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, comment, os, is_backup })
        });

        if (!res.ok) {
            showToast('注册失败: ' + await res.text(), 'danger');
            return;
        }

        const data = await res.json();

        // Show result
        document.getElementById('reg-form-area').style.display = 'none';
        document.getElementById('reg-result').style.display = 'block';

        const host = window.location.host;
        const scriptUrl = `${window.location.protocol}//${host}/api/cluster/connect/script?id=${data.id}&token=${data.token}&os=${os}`;

        let cmd = "";
        if (os === "windows") {
            cmd = `powershell -ExecutionPolicy Bypass -Command "irm '${scriptUrl}' | iex"`;
        } else {
            cmd = `curl -sL "${scriptUrl}" | bash`;
        }

        document.getElementById('reg-command').value = cmd;

        // Refresh list to show offline node
        fetchData();

    } catch (err) {
        showToast('注册失败: 网络错误', 'danger');
    }
}

window.copyCommand = function () {
    const text = document.getElementById('reg-command').value;
    navigator.clipboard.writeText(text).then(() => {
        showToast('命令已复制到剪贴板', 'success');
    }).catch(() => {
        const el = document.getElementById('reg-command');
        el.select();
        document.execCommand('copy');
        showToast('命令已复制到剪贴板', 'success');
    });
}

// Utilities
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showToast(msg, type = 'success') {
    const isError = type === 'danger';
    const elId = isError ? 'error-toast' : 'success-toast';
    const msgId = isError ? 'error-msg' : 'success-msg';

    const el = document.getElementById(elId);
    document.getElementById(msgId).textContent = msg;

    el.style.display = 'block';
    requestAnimationFrame(() => {
        el.classList.add('show');
    });
    setTimeout(() => {
        el.classList.remove('show');
        setTimeout(() => { el.style.display = 'none'; }, 300);
    }, 3000);
}

// Alias for old code
function showError(msg) {
    showToast(msg, 'danger');
}

function showConfirm(msg, title = '确认操作') {
    return new Promise((resolve) => {
        document.getElementById('confirm-title').textContent = title;
        document.getElementById('confirm-msg').textContent = msg;
        const okBtn = document.getElementById('confirm-ok-btn');

        const onConfirm = () => {
            confirmModal.hide();
            resolve(true);
            cleanup();
        };

        const onCancel = () => {
            resolve(false);
            cleanup();
        };

        const cleanup = () => {
            okBtn.removeEventListener('click', onConfirm);
            document.getElementById('confirmModal').removeEventListener('hidden.bs.modal', onCancel);
        };

        okBtn.addEventListener('click', onConfirm);
        document.getElementById('confirmModal').addEventListener('hidden.bs.modal', onCancel, { once: true });

        confirmModal.show();
    });
}

function logout() {
    fetch('/api/logout').then(() => window.location.reload());
}

// Action Bindings
window.openEdit = function (id, speed, quota, comment) {
    document.getElementById('edit-id').value = id;
    document.getElementById('edit-speed').value = (speed / 1024).toFixed(0);
    document.getElementById('edit-quota').value = (quota / 1024 / 1024).toFixed(0);
    document.getElementById('edit-comment').value = comment;
    editModal.show();
}

window.saveEdit = async function () {
    const id = document.getElementById('edit-id').value;
    const speedKB = parseInt(document.getElementById('edit-speed').value) || 0;
    const quotaMB = parseInt(document.getElementById('edit-quota').value) || 0;
    const comment = document.getElementById('edit-comment').value;

    const data = {
        speed_limit: speedKB * 1024,
        total_quota: quotaMB * 1024 * 1024,
        comment: comment
    };

    try {
        const res = await fetch(`${API_URL}/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        if (res.ok) {
            editModal.hide();
            fetchData();
        } else {
            showError('Update failed: ' + await res.text());
        }
    } catch (e) {
        showError('Update failed: Network error');
    }
}

window.openDelete = function (id) {
    document.getElementById('delete-id').value = id;
    deleteModal.show();
}

window.confirmDelete = async function () {
    const id = document.getElementById('delete-id').value;
    try {
        const res = await fetch(`${API_URL}/${id}`, { method: 'DELETE' });
        if (res.ok) {
            deleteModal.hide();
            fetchData();
        } else {
            showError('Delete failed: ' + await res.text());
        }
    } catch (err) {
        showError('Network error');
    }
}

function updateGlobalStats() {
    const total = currentState.nodes.length;
    const online = currentState.nodes.filter(n => n.status === 'online').length;
    const el = document.getElementById('node-count');
    if (el) el.textContent = `${online} 在线 / ${total} 总数`;
}
window.triggerBackup = async function () {
    try {
        const res = await fetch('/api/cluster/backup', { method: 'POST' });
        if (res.ok) {
            showToast('备份已触发，数据正在推送到冗余节点', 'success');
        } else {
            showToast('备份触发失败: ' + await res.text(), 'danger');
        }
    } catch (err) {
        showToast('备份触发失败: 网络错误', 'danger');
    }
}
