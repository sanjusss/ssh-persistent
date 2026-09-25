#!/bin/sh
# ssh-mux 启动器。整个脚本保持 POSIX 兼容,可被 dash 等严格 POSIX shell 执行。
# Linux/macOS:检查 Python 版本后直接运行本目录的 ssh-mux.py。
# Windows(Git Bash/MSYS/Cygwin):直接通过 wsl.exe 在 WSL 中运行,包括
# WSL 与依赖检查;push/pull 的本地路径参数转换为 WSL 路径,远程路径原样保留。
# PowerShell/cmd 用户可直接运行 ssh-mux.bat,功能相同。

# 经符号链接调用时逐级解析,找到脚本的真实所在目录
SRC=$0
while [ -h "$SRC" ]; do
    DIR=$(CDPATH= cd -- "$(dirname -- "$SRC")" && pwd)
    SRC=$(readlink "$SRC")
    case $SRC in
    /*) ;;
    *) SRC=$DIR/$SRC ;;
    esac
done
DIR=$(CDPATH= cd -- "$(dirname -- "$SRC")" && pwd)

if [ ! -f "$DIR/ssh-mux.py" ]; then
    echo "ssh-mux: 未找到 ssh-mux.py(应与 ssh-mux.sh 同目录:$DIR)" >&2
    exit 1
fi

case "$(uname -s)" in
MINGW*|MSYS*|CYGWIN*)
    die() { echo "ssh-mux: $*" >&2; exit 1; }

    # 安装 WSL 或补装依赖属于系统级变更,提示时提醒需征得用户同意,步骤见 SKILL.md
    command -v wsl.exe >/dev/null 2>&1 \
        || die "未找到 wsl.exe,需要先安装 WSL(步骤见 SKILL.md;安装前需征得用户同意)"
    wsl.exe -e true >/dev/null 2>&1 \
        || die "WSL 中没有已安装的 Linux 发行版,需要先安装(步骤见 SKILL.md;安装前需征得用户同意)"
    if ! miss=$(wsl.exe -e bash -c \
        'for c in python3 ssh; do command -v $c >/dev/null || exit 1; done
         command -v sshpass >/dev/null || echo SSHMUX-NO-SSHPASS' 2>/dev/null); then
        die "WSL 内缺少 python3/ssh(或发行版没有 bash),请用 Ubuntu,或执行:wsl -u root -- apt-get install -y python3 openssh-client"
    fi
    # bash 启动文件可能向 stdout 打印内容,标记带独特前缀并用通配判断,避免误判
    case $miss in
    *SSHMUX-NO-SSHPASS*)
        echo "ssh-mux: 提示:WSL 内未安装 sshpass,密码登录会失败,仅密钥登录可忽略" \
            "(安装:wsl -u root -- apt-get install -y sshpass)"
        ;;
    esac
    wsl.exe -e python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null \
        || die "WSL 内 Python 版本低于 3.7,请升级后再使用"

    # 先按当前 Windows 目录解析相对路径,再让 WSL 按实际挂载位置转换。
    to_wsl() {
        case $1 in
        \\\\*|//*) die "不支持网络路径($1),请先把文件放到本地磁盘再传输" ;;
        esac
        _win=$(cygpath -aw -- "$1") || die "无法解析本地路径($1)"
        case $_win in
        \\\\*|//*) die "不支持网络路径($_win),请先把文件放到本地磁盘再传输" ;;
        esac
        # 用正斜杠避免 Windows 命令行把末尾反斜杠和闭合引号合并。
        _win=$(printf '%s' "$_win" | tr '\\' '/')
        _mapped=$(MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' \
            wsl.exe -e wslpath -a "$_win") || die "无法转换为 WSL 路径($1)"
        [ -n "$_mapped" ] || die "无法转换为 WSL 路径($1)"
        printf '%s' "$_mapped"
    }
    WSLPY=$(to_wsl "$DIR/ssh-mux.py") || exit 1

    if [ "$1" = "exec" ]; then
        # 只转换命令开始前的 --file/-f；远程命令中的同名参数原样传递。
        total=$#
        seen=1
        gotalias=0
        command_started=0
        set -- "$@" "$1"
        shift
        while [ "$seen" -lt "$total" ]; do
            arg=$1; shift; seen=$((seen + 1))
            if [ "$command_started" -eq 0 ]; then
                case "$arg" in
                --) command_started=1 ;;
                --file|-f|--session|--timeout)
                    [ "$seen" -lt "$total" ] || die "$arg 需要一个参数值"
                    val=$1; shift; seen=$((seen + 1))
                    case "$arg" in
                    --file|-f)
                        if [ "$val" != "-" ]; then val=$(to_wsl "$val") || exit 1; fi
                        ;;
                    esac
                    set -- "$@" "$arg" "$val"
                    continue
                    ;;
                --file=*)
                    val=${arg#--file=}
                    if [ "$val" != "-" ]; then val=$(to_wsl "$val") || exit 1; fi
                    arg=--file=$val
                    ;;
                --session=*|--timeout=*) ;;
                -h|--help)
                    if [ "$gotalias" -eq 1 ]; then command_started=1; fi
                    ;;
                *)
                    if [ "$gotalias" -eq 0 ]; then gotalias=1; else command_started=1; fi
                    ;;
                esac
            fi
            set -- "$@" "$arg"
        done
    fi

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
                --session|--timeout|--transport|--leg)
                    # 带值选项清单需与 ssh-mux.py push/pull 的 argparse 带值选项保持同步
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
                arg=$(to_wsl "$arg") || exit 1
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
