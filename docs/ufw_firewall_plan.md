# UFW 防火墙联动与异常反馈机制设计

基于用户的深度思考，我们需要在原计划的基础上，强化 Agent 对 Master 的**状态反馈**和**重试/同步机制**能力。这不仅对 UFW 适用，也顺带解决了原本端口被占用时 Agent 启动失败而在 Master 端“假装运行”的问题。

## 1. 反馈机制 (Feedback)

目前 Agent 仅向 Master 上报使用流量（`StatsReportPayload`）。为实现完整的反馈链，需扩展此通讯：

### 1.1 数据结构的扩展 (pkg/cluster/types.go)
```go
type RuleStats struct {
	UpBytes   int64  `json:"up"`
	DownBytes int64  `json:"down"`
	Error     string `json:"error,omitempty"` // [NEW] 记录规则执行的异常（如 UFW 失败、端口占用）
}

type ForwardRule struct {
	// ... existing fields ...
	Error string `json:"error,omitempty"` // [NEW] Master 持有的实时故障原因
}
```

### 1.2 Agent 侧报错感知 (pkg/forward/engine.go)
1. Engine 内部引入一个新的 map：`failedRules map[string]string`，专门记录 `id -> errorMsg`。
2. 当 `startRule` 失败（不论是因为无法 Listen 还是 UFW 失败）：
   - 该 Rule 不会进入 `e.rules` 成功列表。
   - 改为记录到 `e.failedRules[config.ID] = "UFW Allow Failed: " + err.Error()`。
3. Agent 周期性（默认15s）上报的 `StatsReportPayload` 时：
   - 遍历 `e.rules` 上报正常流量，`Error` 为空字符串。
   - 遍历 `e.failedRules`，上报流量 0，`Error` 为具体的报错信息。

### 1.3 Master 侧与前端 (Web UI)
- `Hub.UpdateRulesStats` 解析上报的 `Error` 字段更新给 `h.allRules`。
- 前端 `app.js` 渲染时：
   - 检查 `r.error`，若非空，将规则状态标识为红色的 `ERROR`，并在 tooltip 或旁边展示错误原因。
   - 提供一个『重试 (Retry)』按钮。

## 2. 操作重试 (Retry)

当用户在界面上看到 `ERROR` 状态，并且他们通过其他手段（例如在服务器侧 kill 掉占用进程）恢复了环境，需要能够重试。

### 2.1 重试核心链路
- **前端动作**：调用 API `/api/rules/{id}/retry`。
- **Master 动作 (pkg/web/server.go)**：新增 `handleRuleRetry` 处理器。通过 `Hub` 直接强制调用 `h.SyncRulesToAgent(nodeID)`。
- **Agent 动作 (pkg/forward/engine.go)**：由于 `failedRules` 只是临时记录在内存，`SyncRules` 到达时，会读取待同步列表中的此条规则。由于他目前不在运行态 (`e.rules`) 中，Engine 将其视为一个**新增规则**再次调用 `startRule`，并重新触发一次完整的 UFW 注入与 Listen 绑定流程。
- 如果重试成功，`startRule` 将清理掉对应的 `failedRules` 并加入运行态，下一个 15s 后 UI 将绿灯恢复。

## 3. 删除操作时的同步一致性

如果用户点击“删除”：
1. Master 直接从内存中删除此条目，`UFW Status` 将从 UI 消失。
2. Master 推送最新的规则清单到 Agent (`SyncRules`)。
3. Agent 发现该规则已不在期望列表中，执行 `RemoveRule` 及 `firewall.DenyPort`。

**若 `firewall.DenyPort` 删除失败怎么办？**
- 删除操作失败，往往意味着 OS 层面 `ufw` 命令卡死、环境变量缺失甚至遭到篡改。
- 此时规则流量已经被阻断（Listener 被 Close），即使防火墙漏洞还在，程序也无法响应请求。
- **策略：尽力而为 (Best Effort) 且仅本地输出 Warn 日志。** 
- 在分布式架构里，Agent 是纯无状态受控端。由于该规则的定义已不复存在于 Master 记录中（UI 也是如此认为），因此我们不做无止境的回调重试。Agent 的 `RemoveRule` 日志记录 `WARNING: failed to deny port via UFW, manual cleanup required` 是最佳且最安全的实践，不阻塞后续系统的运行。

---
请您审查该升级版的设计方案：不仅解决了 UFW 的状态透出和重启，一并解决底层转发的一切失败上报。是否可以依据本文件，更新执行计划并投入代码开发？
