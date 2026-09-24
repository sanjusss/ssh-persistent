#!/bin/sh
# ssh-mux 启动器。整个脚本保持 POSIX 兼容,可被 dash 等严格 POSIX shell 执行。
# Linux/macOS:检查 Python 版本后直接运行本目录的 ssh-mux.py。
# Windows(Git Bash/MSYS/Cygwin):直接通过 wsl.exe 在 WSL 中运行,包括
# WSL 与依赖检查;push/pull 的本地路径参数转换为 WSL 路径,远程路径原样保留。
# PowerShell/cmd 用户可直接运行 ssh-mux.bat,功能相同。

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "$(uname -s)" in
MINGW*|MSYS*|CYGWIN*)
    die() { echo "ssh-mux: $*" >&2; exit 1; }

    # 安装 WSL 或补装依赖属于系统级变更,提示时提醒需征得用户同意,步骤见 SKILL.md
    command -v wsl.exe >/dev/null 2>&1 \
        || die "未找到 wsl.exe,需要先安装 WSL(步骤见 SKILL.md;安装前需征得用户同意)"
    wsl.exe -e true >/dev/null 2>&1 \
        || die "WSL 中没有已安装的 Linux 发行版,需要先安装(步骤见 SKILL.md;安装前需征得用户同意)"
    if ! miss=$(wsl.exe -e bash -c \
        'for c in python3 ssh scp; do command -v $c >/dev/null || exit 1; done
         command -v sshpass >/dev/null || echo no-sshpass' 2>/dev/null); then
        die "WSL 内缺少 python3/ssh/scp(或发行版没有 bash),请用 Ubuntu,或执行:wsl -u root -- apt-get install -y python3 openssh-client"
    fi
    [ "$miss" = "no-sshpass" ] && echo "ssh-mux: 提示:WSL 内未安装 sshpass,密码登录会失败,仅密钥登录可忽略" \
        "(安装:wsl -u root -- apt-get install -y sshpass)"
    wsl.exe -e python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null \
        || die "WSL 内 Python 版本低于 3.7,请升级后再使用"

    # C:\x\y 或 C:/x/y -> /mnt/c/x/y(盘符必须小写,实测 /mnt/C 不可用)
    to_wsl() {
        _d=${1%%:*}
        _r=${1#*:}
        _d=$(printf '%s' "$_d" | tr 'A-Z' 'a-z')
        _r=$(printf '%s' "$_r" | tr '\\' '/')
        printf '/mnt/%s%s' "$_d" "$_r"
    }
    WSLPY=$(to_wsl "$(cygpath -w "$DIR/ssh-mux.py")")

    if [ "$1" = "push" ] || [ "$1" = "pull" ]; then
        # push <别名> [选项] <本地路径> <远程路径>;pull 的两个路径顺序相反。
        # 选项可放在任意位置;第一个非选项参数是别名,其后的非选项参数按
        # 位置计数:push 转换第 1 个(本地路径),pull 转换第 2 个。用
        # "追加到尾部 + shift 头部"的队列法重建参数,不依赖 bash 数组。
        if [ "$1" = "push" ]; then loc=1; else loc=2; fi
        nopt=0      # 遇到 -- 之后,其余参数全部按位置参数处理
        gotalias=0
        pathpos=0
        total=$#
        seen=1
        set -- "$@" "$1"
        shift
        while [ "$seen" -lt "$total" ]; do
            arg=$1; shift; seen=$((seen + 1))
            if [ "$nopt" -eq 0 ]; then
                case "$arg" in
                --) nopt=1; set -- "$@" "$arg"; continue ;;
                --session|--timeout)
                    if [ "$seen" -ge "$total" ]; then
                        die "$arg 需要一个参数值"
                    fi
                    val=$1; shift; seen=$((seen + 1))
                    set -- "$@" "$arg" "$val"
                    continue
                    ;;
                -*) set -- "$@" "$arg"; continue ;;
                esac
            fi
            if [ "$gotalias" -eq 0 ]; then
                gotalias=1
                set -- "$@" "$arg"
                continue
            fi
            pathpos=$((pathpos + 1))
            if [ "$pathpos" -eq "$loc" ]; then
                case "$arg" in /*) arg=$(cygpath -w "$arg") ;; esac
                case "$arg" in [a-zA-Z]:*) arg=$(to_wsl "$arg") ;; esac
            fi
            set -- "$@" "$arg"
        done
    fi
    # 禁用 MSYS 对 "/" 开头参数的自动改写(远程路径和 /mnt/... 必须原样传递)
    MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
        exec wsl.exe -e python3 "$WSLPY" "$@"
    ;;
*)
    if command -v python3 >/dev/null 2>&1; then
        PY=python3
    elif command -v python >/dev/null 2>&1; then
        PY=python
    else
        echo "ssh-mux: 未找到 Python,请先安装 Python 3.7 或更新版本" >&2
        exit 1
    fi
    if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)'; then
        echo "ssh-mux: 需要 Python 3.7 或更新版本,当前为 $("$PY" --version 2>&1)" >&2
        exit 1
    fi
    exec "$PY" "$DIR/ssh-mux.py" "$@"
    ;;
esac
