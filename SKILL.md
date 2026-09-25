---
name: ssh-persistent
description: 通过 SSH 长连接排查远程服务器，适合需要多次执行命令或传输文件的任务。统一经 `ssh-mux.sh` 管理直连、标准跳板机和仅允许交互式登录的堡垒机（内部调用 `ssh-mux.py`）。支持 Linux 和 `macOS`；`Windows` 需在 `WSL` 中运行。
---

# SSH 长连接管理

通过本目录的 `ssh-mux.sh` 连接服务器、执行命令和传输文件，内部调用 `ssh-mux.py`。执行时使用配置中的主机别名，后续操作继续使用已建立的连接。

适用于需要多次操作的远程排查、巡检和日志收集。只执行一次命令时无需使用本工具，目标主机必须能通过 SSH 访问。

## 运行环境与连接方式

Linux 和 `macOS` 需要 Python 3.7 或更新版本，以及 `ssh`；默认文件传输需要 `scp`，使用 `--transport auto` 等新方式时可省略。脚本只使用 Python 标准库。`jump` 模式使用密码认证时，本机还需要 `sshpass`；使用密钥时省略密码配置。

`Windows` 经 `WSL` 运行：有 `bash` 时使用 `ssh-mux.sh`，否则使用 `ssh-mux.bat`。在 `Windows` 上操作前，先读 [Windows 运行说明](references/windows.md)。

| 模式 | 使用场景 |
| --- | --- |
| `jump` | 直连，或支持 `ssh -J` 的标准跳板机；通过 SSH 的连接复用功能保持连接。 |
| `shell` | 只允许交互式登录的堡垒机；后台进程保持终端，并逐层登录目标主机。 |

没有 `via` 时使用 `jump`；配置 `via` 后由 `via_mode` 指定，默认仍为 `jump`。

## 按需读取引用文档

仅在任务涉及对应场景时读取，不必预先加载全部文档。

| 何时读取 | 文档 |
| --- | --- |
| 使用 `Windows`、准备 `WSL` 或处理路径转换 | [Windows 运行说明](references/windows.md) |
| 新增或删除主机、配置跳板机和堡垒机 | [主机与连接配置](references/connections.md) |
| 上传、下载文件或配置暂存主机 | [文件传输](references/transfers.md) |
| 连接失败、会话无响应，或调整环境变量 | [连接排查与运行机制](references/troubleshooting.md) |
| 手动编辑配置、查询字段含义 | [hosts.conf.example](hosts.conf.example) |

配置默认位于 `~/.config/ssh-mux/hosts.conf`，可用 `SSH_MUX_CONFIG` 更改。密码以明文保存，请勿把真实配置提交到公开仓库。

## 执行命令

将 `S` 设为本技能目录中启动脚本的实际路径。下面的 `A`、`B` 是已配置的主机别名：

```bash
S=/path/to/ssh-persistent/ssh-mux.sh
"$S" list
"$S" connect A                         # 提前连接，已有连接时跳过
"$S" exec A 'uptime'                   # 未连接时自动登录
"$S" exec A --timeout 300 'some-command'
"$S" status
"$S" push A ./app.tar.gz /tmp/         # 先读文件传输说明
"$S" pull B /var/log/app.log ./
```

`exec` 返回远程命令的输出和退出码。`shell` 模式会去除终端回显和颜色控制码。

`--session`、`--timeout`、`--file` 放在别名前后均可，但必须位于命令文本之前。命令一旦开始，后续参数全部按远程命令处理。

将完整命令文本作为一个参数传入。直接写 `exec A awk '{print $1}' 文件` 会在本地丢失程序外层引号；复杂命令优先使用下面的 `--file`。需要直接传入 `awk` 命令时，见[命令引号](references/troubleshooting.md#命令引号)。

`shell` 模式执行命令默认超时为 120 秒，上限为 7200 秒，超过上限会被截断。`jump` 模式执行命令时忽略 `--session` 和 `--timeout`；传输超时的含义见[文件传输](references/transfers.md)。

### 从本地文件执行复杂命令

将以下内容保存为本地 `check.sh`，`$1`、`$2` 和引号按正常脚本语法书写：

```bash
printf 'alice 10\nbob 20\n' | awk '
    { total += $2 }
    END { printf "total=%d\n", total }
'
```

```bash
"$S" exec A --file ./check.sh
"$S" exec A --session case-1234 --timeout 300 -f ./check.sh
"$S" exec A --file - < ./check.sh       # 从标准输入读取
```

`-f` 与 `--file` 同义，也支持 `--file=路径`；不能同时提供文件和命令文本。相对文件路径按本地当前目录解析。文件需为 `UTF-8`，支持文件开头的字节顺序标记和 `Windows` 换行。空文件、读取失败或编码错误会在连接前报错。

文件内容不会经过本地 shell 展开，按远端登录 shell 的语法在独立子 shell 内执行。`#!` 不会自动选择解释器；目录和变量修改只影响本次执行，`exit` 返回退出码并保留持久连接。`shell` 模式分段传输与执行共用 `--timeout`，文件较大或网络较慢时可增加该值。

### 多个任务使用独立会话

`shell` 模式的命令文本会保留当前目录和环境变量。同一任务可共用会话；多个助手并行工作时，必须使用不同的 `--session`。同一任务的 `exec`、`push`、`pull` 使用同一会话名即可共用连接。

```bash
"$S" exec A --session case-1234 'uptime'
"$S" exec A --session case-5678 'df -h'
"$S" exit A --session case-1234        # 只关闭该任务的会话
```

未指定时使用 `default`。每个独立会话都要重新登录，堡垒机可能限制同一账号的并发会话数。

## 使用限制与断线处理

- `shell` 模式不要运行需要手动交互的命令，如 `vi`、前台 `top` 或 `read`。长任务可增加超时，或用 `nohup ... &` 在后台运行。
- **`shell` 模式断线后会尝试重建一次并重试命令，原命令可能已经执行。** 使用前确认重复执行不会产生额外影响。
- `shell` 模式命令执行超时会发送 `Ctrl-C` 尝试恢复会话，不会自动重试命令。
- 排查结束后关闭本任务的连接；默认空闲 600 秒也会自动断开。调整空闲时间或排查失败时读[连接排查说明](references/troubleshooting.md)。

```bash
"$S" exit A                           # shell 模式关闭 A 的所有会话
"$S" exit --all                       # 关闭所有主机的连接
```
