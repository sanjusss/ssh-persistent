---
name: ssh-persistent
description: 通过 SSH 长连接排查远程服务器，适合需要多次执行命令或传输文件的任务。使用 `ssh-mux.py` 管理直连、标准跳板机和仅允许交互式登录的堡垒机。支持 Linux 和 `macOS`；`Windows` 需在 `WSL` 中运行。
---

# SSH 长连接管理

使用本目录中的 `ssh-mux.py` 连接服务器、执行命令和传输文件。主机地址、端口及登录信息保存在配置文件中，执行命令时引用主机别名。首次登录后，后续操作继续使用已有连接。

适用于远程排查、巡检、日志收集，以及通过跳板机或堡垒机访问内网主机。只执行一次命令时，无需使用本工具。目标主机必须能通过 SSH 访问。

## 运行环境与连接方式

本工具支持 Linux 和 `macOS`。原生 `Windows` 请在 `WSL`（`Windows` 的 Linux 子系统）中运行。脚本依赖 Unix 终端接口，`Windows` 版 `OpenSSH` 也不支持这里使用的连接复用功能。

本机需要 Python 3、`ssh` 和 `scp`。脚本只使用 Python 标准库；`scp` 负责传输文件。`jump` 模式使用密码登录时，本机还需要 `sshpass`，用于自动填写密码。

### Windows：准备 `WSL` 环境

以下命令在 `Windows` 终端（如 `PowerShell`）中执行。安装 `WSL` 属于系统级变更：会启用系统组件、下载发行版镜像并占用约 2 GB 磁盘空间。**必须先向用户说明这些影响并取得显式同意，才能安装**。执行前先用 `wsl -l -v` 检查，已有可用发行版时直接使用，不要重复安装。

```bash
# 安装 Ubuntu；--no-launch 跳过首次启动的交互式初始化，之后直接以 root 使用
wsl --install -d Ubuntu --no-launch

# 在 WSL 内安装依赖；python3 已随 Ubuntu 自带
wsl -u root -- bash -c 'apt-get update && apt-get install -y openssh-client sshpass'
```

### Windows：调用脚本

配置文件保存在 `WSL` 内的默认路径（`~/.config/ssh-mux/hosts.conf`），无需设置环境变量。所有子命令都通过 `wsl bash -c` 调用，技能目录在 `Windows` 侧时按 `/mnt/c/...` 规则映射：

```bash
wsl bash -c 'python3 /mnt/c/<技能目录>/ssh-persistent/ssh-mux.py exec db "hostname && uptime"'
```

`host add`、`push`、`status`、`exit` 等子命令替换引号内的命令即可。命令包在 `bash -c` 的引号里，是为了避免 `Git Bash` 自动改写 `/mnt/...` 开头的参数。长连接和守护进程运行在 `WSL` 内，空闲超时和断开行为与 Linux 一致。

脚本根据目标主机的配置选择连接方式：

| 模式 | 适用情况 | 连接方式 |
| --- | --- | --- |
| `jump` | 直连，或经过支持 `ssh -J` 的标准跳板机 | 使用 `ControlMaster`，即 SSH 提供的连接复用功能。后续命令共用已建立的连接。 |
| `shell` | 堡垒机只允许交互式登录，不支持 `ssh -J` 或直接执行远程命令 | 后台进程保持登录终端，依次登录中转主机和目标主机，再向终端发送命令。 |

没有配置 `via` 时使用 `jump` 模式。配置 `via` 后，由 `via_mode` 指定模式，默认也是 `jump`。

## 添加主机

配置文件默认位于 `~/.config/ssh-mux/hosts.conf`，可通过环境变量 `SSH_MUX_CONFIG` 更改。优先使用 `host add` 和 `host remove` 管理主机，也可以手动编辑文件。

下面的地址和登录信息都是示例。将 `S` 设为本技能目录中脚本的实际路径：

```bash
S=/path/to/ssh-persistent/ssh-mux.py

# 直接连接，db 是主机别名
python3 $S host add db --host 7.7.7.7 --user root --password 'xxx'

# 标准跳板机：先添加 jump，再添加通过 jump 访问的 web
python3 $S host add jump --host 5.5.5.5 --port 2222 --user jump --password 'xxx'
python3 $S host add web --host 6.6.6.6 --user root --password 'xxx' \
        --via jump --via-mode jump

# 堡垒机：通过登录名指定目标 IP
python3 $S host add bastion --host 2.2.2.2 --user T123456 \
        --password 'xxx' --routing username
python3 $S host add A --host 3.3.3.3 --user root --password 'xxx' \
        --via bastion --via-mode shell

# 从 A 继续登录 B
python3 $S host add B --host 4.4.4.4 --user root --password 'xxx' \
        --via A --via-mode shell

python3 $S list
python3 $S host remove B
```

`host add` 只保存配置，不连接主机。别名已存在时，需要先删除再添加。如果其他主机的 `via` 引用了某个别名，脚本会拒绝删除该别名。删除配置不会断开已经建立的会话。

脚本保存配置时会将权限设为 `600`，即只有文件所有者可以读写。保存时会重写整个配置文件，原有注释会丢失。密码以明文保存，请勿把真实配置提交到公开仓库。

### 手动编辑配置

配置采用 `INI` 格式：每台主机占一个 `[别名]` 段，下面填写 `字段=值`。各字段的含义、默认值和完整示例统一放在 [hosts.conf.example](hosts.conf.example) 中，手动编辑时查阅该文件。

`routing=username` 适用于登录名格式为 `<账号>/<目标IP>/any` 的堡垒机。脚本先填写堡垒机密码，再根据目标机的提示填写用户名和密码。

密码中的 `%` 等特殊字符无需转义。手动编辑配置时，不要在密码后面添加行内注释，以免注释被当作密码的一部分。

## 执行命令

```bash
python3 $S connect A                  # 提前连接；已连接时跳过
python3 $S exec A 'uptime'            # 未连接时自动登录
python3 $S exec A 'ps aux --sort=-%cpu | head -20'
python3 $S status                     # 查看连接状态
python3 $S exit A                     # 断开 A 的连接；shell 模式下断开 A 的所有会话
python3 $S exit --all                 # 断开所有主机的连接
```

`exec` 返回远程命令的退出码和输出。`shell` 模式会去除终端回显（终端重复显示的输入内容）和颜色控制码。

`exec` 的 `--session`、`--timeout` 选项可以放在别名或命令前后。`shell` 模式默认等待命令执行 `120` 秒，超时后发送 `Ctrl-C`，尝试恢复会话。需要等待更长时间时，增加 `--timeout`：

```bash
python3 $S exec A --timeout 300 'some-command'
```

当前 `jump` 模式不使用 `--session` 和 `--timeout`；这两个选项用于 `shell` 模式。

### 多个任务使用独立会话

`shell` 模式会保留当前目录、环境变量等状态。同一个人工智能助手执行同一任务时，可以共用会话。多个助手并行工作时，必须为各自的任务指定不同的 `--session`，避免相互影响。

```bash
python3 $S exec A --session case-1234 'uptime'  # 助手甲
python3 $S exec A --session case-5678 'df -h'   # 助手乙
python3 $S exit A --session case-1234          # 只断开助手甲的会话
```

不指定 `--session` 时使用 `default` 会话。每个独立会话都需要从头完成登录，之后才可继续使用。堡垒机可能限制同一账号的同时在线会话数。

## 传输文件

```bash
python3 $S push A ./app.tar.gz /tmp/   # 上传文件
python3 $S pull B /var/log/app.log ./  # 下载文件
```

`jump` 模式直接使用 `scp`，共用已建立的 SSH 连接。

`shell` 模式通过中转主机运行 `scp`，逐台复制文件。例如访问路径为“本机 → `A` → `B`”时，上传文件先到 `A`，再从 `A` 复制到 `B`。下载顺序相反。这种模式需要配置 `[local]`，下面两种方式选一种。

### 本机可以接受 SSH 登录

本机运行 `sshd`（接收 SSH 登录的服务）时，在 `[local]` 中填写本机地址和登录信息：

```bash
python3 $S host add local --host 1.1.1.1 --user myuser --password 'xxx'
```

地址必须能被中转主机访问，不能填写 `127.0.0.1`。中转主机通过 `scp` 从本机读取文件，或把文件写回本机。这种传输方式需要配置本机的登录密码。

### 本机不能接受 SSH 登录

用 `staging` 指定一台暂存主机。本机和连接路径上的第一台中转主机都必须能通过 SSH 登录这台服务器。

```bash
python3 $S host add relay --host 5.5.5.5 --user root --password 'xxx'
python3 $S host add local --staging relay
```

上传时，本机先上传到暂存主机，中转主机再从那里取文件。下载时，中转主机先上传到暂存主机，本机再下载。

暂存主机必须使用 `jump` 模式，可以经过标准跳板机访问，并且必须配置 `password`。使用 `staging` 后，`[local]` 的 `host`、`user`、`password` 可以省略。如果已有 `[local]`，先删除再按所选方式添加。

每次在中转主机上复制文件时，脚本优先使用那台主机上的 `sshpass` 填写密码。没有 `sshpass` 时，脚本会尝试识别密码提示并应答。如果输出中恰好出现 `password:`，可能被误认为密码提示。

## 使用限制与断线处理

- `shell` 模式向终端发送命令，单行命令不要超过约 4000 字符，以免超过终端的输入缓冲限制。
- `shell` 模式不要运行需要手动交互的命令，例如 `vi`、前台 `top` 或 `read`。长任务可增加 `--timeout`，或使用 `nohup ... &` 在后台运行。
- `shell` 会话断开后，脚本会尝试重建一次并重试命令。原命令可能已经执行，需确认重复执行不会产生额外影响。命令超时不会自动重试。
- 排查结束后运行 `exit`，或运行 `exit --all` 断开全部连接。默认空闲 600 秒也会自动断开。

## 工作原理与排查文件

`jump` 模式用 `ControlMaster` 建立后台 SSH 连接。后续 `ssh` 和 `scp` 通过本机的套接字（进程间通信接口）使用这条连接，无需重新认证。套接字默认位于 `/tmp/ssh_mux_j_<主机>_<端口>_<用户>`。

`shell` 模式为每个“主机别名 + 会话名”启动一个守护进程，即持续在后台运行的进程。守护进程使用 `pty`（伪终端，供程序模拟终端输入输出）保持登录，自动应答各层登录提示。

登录完成后，脚本关闭终端回显并清空命令提示符。执行命令时，在输出前后添加随机标记，以识别命令输出和退出码。

`shell` 模式的文件默认位于 `/tmp/`，名称以 `ssh_mux_s_<别名>_<会话>` 开头：

| 后缀 | 用途 |
| --- | --- |
| `.sock` | 命令行工具与守护进程通信的套接字。 |
| `.log` | 守护进程日志。 |
| `.err` | 建立会话失败时记录的错误。 |
| `.pid` | 守护进程的进程号。 |

连接失败时，先查看命令给出的错误和日志路径。

### 环境变量

| 变量 | 用途 | 默认值 |
| --- | --- | --- |
| `SSH_MUX_CONFIG` | 配置文件路径 | `~/.config/ssh-mux/hosts.conf` |
| `SSH_MUX_SOCKET_DIR` | 套接字及会话文件所在目录 | `/tmp` |
| `SSH_MUX_PERSIST` | 空闲多久后自动断开，单位为秒 | `600` |
