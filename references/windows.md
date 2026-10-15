# Windows 与 `WSL`

在 `Windows` 上使用本技能、安装依赖或处理本地路径时读取。

原生 `Windows` 请在 `WSL`（`Windows` 的 Linux 子系统）中运行。脚本依赖 Unix 终端接口，`Windows` 版 `OpenSSH` 也不支持这里使用的连接复用功能。

## 准备 `WSL` 环境

以下命令在 `Windows` 终端（如 `PowerShell`）中执行。安装 `WSL` 属于系统级变更：会启用系统组件、下载发行版镜像并占用约 2 `GB` 磁盘空间。**必须先向用户说明这些影响并取得显式同意，才能安装**。执行前先用 `wsl -l -v` 检查，已有可用发行版时直接使用，不要重复安装。

```bash
# 安装 Ubuntu；--no-launch 跳过首次启动的交互式初始化，之后直接以 root 使用
wsl --install -d Ubuntu --no-launch

# 在 WSL 内安装依赖；python3 已随 Ubuntu 自带
wsl -u root -- bash -c 'apt-get update && apt-get install -y openssh-client sshpass'
```

启动器要求 `python3` 和 `ssh`，不检查 `scp`。`push`、`pull` 默认使用 `scp`；没有 `scp` 时需显式指定 `--transport auto` 等方式，`--transport` 选项与 Linux 相同。

## 调用方式

`Git Bash`、`MSYS2`、`Cygwin` 等 `bash` 环境下与其他系统一致，使用 `ssh-mux.sh`。它会自动检查 `WSL`、发行版和依赖，把本地文件路径映射为 `WSL` 路径（相对路径、`C:\...`、`/tmp/...` 形式均可），再经 `WSL` 运行：

```bash
./ssh-mux.sh exec db "hostname && uptime"
./ssh-mux.sh push db ./app.tar.gz /tmp/
```

没有 `bash` 时（`PowerShell`/`cmd`），直接运行功能相同的 `ssh-mux.bat`：

```bat
ssh-mux.bat exec db "hostname && uptime"
```

远程路径原样传递；本地相对路径基于当前目录解析，当前目录在网络路径上时请改用绝对路径。配置文件保存在 `WSL` 内的默认路径（`~/.config/ssh-mux/hosts.conf`），无需设置环境变量。在 `Windows` 侧设置的环境变量（如 `SSH_MUX_CONFIG`、`SSH_MUX_PROXY`）不会自动传入 `WSL`，需要经 `WSLENV`（`Windows` 与 `WSL` 之间转发环境变量的机制）转发后才生效；脚本在 `WSL` 内运行，一般无需设置这些变量。脚本所在目录、`exec --file` 及 `push`/`pull` 的本地文件参数不支持 `//` 开头的网络共享路径（即 `Windows` 的 `UNC` 路径，形如 `\\服务器\共享名`，在 `WSL` 中显示为 `//服务器/共享名`）。使用这类路径时脚本会直接报错，请改用本地路径。长连接和守护进程运行在 `WSL` 内，空闲超时和断开行为与 Linux 一致。

## 代理与回环地址

逐段代理的配置字段和优先级见[主机与连接配置](connections.md#逐段代理)。在 `WSL` 内运行时，注意两类执行位置的区别：

- 本机握手程序运行在 `WSL` 内。`SSH_MUX_PROXY` 或首段代理填 `127.0.0.1` 时，指向 `WSL` 虚拟机自身，不是 `Windows` 宿主机的代理。要访问宿主机上的代理，请填写宿主机在 `WSL` 网络中的地址。
- 跳板段和远端段的代理由该段起点访问，地址相对起点解析。这些段上的 `127.0.0.1` 指向起点主机自身。

远端终端段需要在起点主机运行 Python 代理程序（Python 3.4 或更新版本）；本机段和标准跳板段只使用本机的 Python，跳板无需安装。
