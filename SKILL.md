---
name: ssh-persistent
description: 通过 SSH 长连接远程排查服务器。支持直连/标准跳板(`ControlMaster` 多路复用)和堡垒机(仅交互终端)两种场景,用 `ssh-mux.py` 统一管理连接、命令执行和文件传输。当需要对远程服务器执行多次 SSH 命令时使用。仅支持 Linux/`macOS`,`Windows` 请在 `WSL` 中使用。
---

# SSH 持久连接(ssh-persistent)

## 概述

用本目录下的 `ssh-mux.py` 管理所有远程访问。主机信息(IP、端口、用户名、密码)放在配置文件里,命令行只引用别名。一次登录,后续命令复用长连接,避免重复握手和认证。

两种连接模式,按目标主机在配置里的写法自动选择:

- **`jump` 模式**:直连主机或标准 SSH 跳板机(支持 `-J`)。走 `ControlMaster` 多路复用,多次命令只需 1 次认证,后续延迟约 0.1 秒。
- **`shell` 模式**:堡垒机只给交互终端(不支持 `-J`、`exec` 通道被拦截)。由后台守护进程持有一条"本机→堡垒机→…→目标"的终端会话链,命令像手工敲进终端一样发进去执行。

## 何时使用 / 不使用

使用:对同一台服务器执行 2 次以上命令;远程排查、巡检、日志收集;需要经堡垒机或跳板机访问内网主机;需要在主机间传文件。

不使用:只执行单次命令;目标主机完全无法通过 SSH 到达;运行环境是原生 `Windows`(本工具依赖 Unix 的 `pty`、`fcntl` 等接口,只支持 Linux/`macOS`,`Windows` 上请在 `WSL` 里使用)。

## 文件组成

- `ssh-mux.py`:主程序,所有操作都通过它执行。用法:`python3 ssh-mux.py <子命令> ...`
- `hosts.conf.example`:配置文件模板,各字段的写法示例

## 配置文件

路径 `~/.config/ssh-mux/hosts.conf`(可用环境变量 `SSH_MUX_CONFIG` 改)。主机用 `host add` / `host remove` 子命令管理,不用手改文件:

```bash
S=/path/to/ssh-persistent/ssh-mux.py    # 本文件同目录的脚本

python3 $S host add db --host 7.7.7.7 --user root --password 'xxx'          # 直连主机
python3 $S host add bastion --host 2.2.2.2 --user T123456 \
        --password 'xxx' --routing username                                  # 用户名路由型堡垒机
python3 $S host add A --host 3.3.3.3 --user root --password 'xxx' \
        --via bastion --via-mode shell                                       # 经堡垒机
python3 $S host add web --host 6.6.6.6 --user root --password 'xxx' \
        --via jump --via-mode jump                                           # 经标准跳板(-J)
python3 $S host add local --host 1.1.1.1 --user myuser --password 'xxx' # [local] 保留段
python3 $S host add local --staging jump    # 本机没开 `sshd` 时改这样:传输经暂存主机 `jump` 换手
python3 $S host remove A                                                     # 删除(被 `via` 引用时拒绝)
```

`host add` 只写配置不建连;文件保存为 `600` 权限,重写时注释会丢失。也可以直接手改配置文件,格式如下,每台主机一段,段名即别名:

```ini
[local]                    # 保留段:文件传输用,host 填中转主机能访问到本机的地址
host=1.1.1.1
user=myuser
password=mypass
# staging=jump             # 本机没开 `sshd` 时改配这项:传输经暂存主机换手,上面三个字段可省

[bastion]                  # 用户名路由型堡垒机
host=2.2.2.2
user=T123456
password=jump-pass
routing=username           # 登录名自动拼成 T123456/<目标IP>/any

[A]                        # 经堡垒机访问的主机
host=3.3.3.3
user=root
password=a-pass
via=bastion
via_mode=shell             # 堡垒机只给交互终端

[B]                        # 经 A 访问的主机
host=4.4.4.4
user=root
password=b-pass
via=A
via_mode=shell

[web]                      # 经标准跳板(-J)访问的主机
host=6.6.6.6
user=root
password=web-pass
via=jump
via_mode=jump
```

字段:`host`(必填)、`port`(默认 22)、`user`(默认当前用户)、`password`(不配走密钥)、`via`(跳板别名)、`via_mode`(`jump` 标准跳板,默认;`shell` 堡垒机)、`routing=username`(用户名路由型堡垒机,只标在堡垒机自己身上)、`staging`(只用于 `[local]` 段,见下)。密码明文保存,等号后内容原样读取,特殊字符不用转义。

`[local]` 段有两种配法:本机开了 `sshd` 时配 `host`/`user`/`password`,中转机直接 `scp` 回本机;本机没开 `sshd` 时配 `staging=<别名>`,指向一台本机和链路最外层中转机都能 ssh 到的暂存主机,文件经它换手。暂存主机必须是 `jump` 模式可直连的主机(可以有 `jump` 跳板链),且要配 `password`。

## 命令用法

```bash
S=/path/to/ssh-persistent/ssh-mux.py    # 本文件同目录的脚本

python3 $S connect A                    # 建立长连接(已连接则跳过)
python3 $S exec A 'uptime'              # 执行远程命令,未连接时自动建连
python3 $S exec A 'ps aux --sort=-%cpu | head -20'
python3 $S push A ./app.tar.gz /tmp/    # 上传文件
python3 $S pull B /var/log/app.log ./   # 下载文件(B 经 A 中转)
python3 $S status                       # 所有主机的连接状态
python3 $S list                         # 配置里有哪些主机
python3 $S host add db --host 7.7.7.7 --user root --password 'xxx'  # 添加主机
python3 $S host remove db               # 删除主机(详见上文"配置文件"一节)
python3 $S exit A                       # 断开;exit --all 全部断开
```

`exec` 的退出码就是远程命令的退出码,输出是远程命令的输出(已剥掉终端回显和颜色码)。`--session` 和 `--timeout` 可以放在别名前后任意位置(默认 120 秒,超时自动发 `Ctrl-C` 并恢复会话)。

文件传输说明:`shell` 模式下本机与目标之间没有直接通道,`push`/`pull` 在中转主机上用 `scp` 逐棒接力(本机→`A`→`B` 或反向),依赖配置里 `[local]` 段。本机没开 `sshd` 时,按上文的 `staging` 配法走暂存主机换手。`jump` 模式直接走 `scp` 复用长连接。

## 多 `agent` 并发

同一个 `agent` 的多条命令共享一条会话;不同 `agent` 必须用 `--session` 隔开,否则会话状态(当前目录、环境变量)互相污染:

```bash
python3 $S exec A --session case-1234 'uptime'    # agent 甲
python3 $S exec A --session case-5678 'df -h'     # agent 乙,独立会话链
python3 $S exit A --session case-1234             # 只断开自己的会话
```

每条会话独立走完整登录链(建链几秒),之后命令即时执行。不带 `--session` 时用 `default` 会话。注意堡垒机对同一账号的并发会话数可能有上限。

## 工作原理

**`jump` 模式**:`sshpass` + `ControlMaster` 建后台主连接,socket 在 `/tmp/ssh_mux_j_<主机>_<端口>_<用户>`;后续 ssh/`scp` 复用 socket 不再认证;空闲 `SSH_MUX_PERSIST` 秒(默认 600)自动关闭。

**`shell` 模式**:每个 (别名, 会话) 一个守护进程,持有 `pty` 终端会话链。建链时自动应答各层登录提示(堡垒机密码 → 目标机 `login:`/`password:`),落稳后关回显、清提示符。`exec` 用随机标记包住命令来截取输出和退出码;会话断开自动重建一次。socket、日志在 `/tmp/ssh_mux_s_<别名>_<会话>.{sock,log}`,建链失败原因在 `.err` 文件里。

## 注意事项

- `exec` 的命令是"敲进终端"的语义:单行不要超过约 4000 字符(终端行缓冲限制);不要跑需要交互输入的命令(`vi`、`top` 前台、`read`),长任务自己加 `nohup ... &` 或加 `--timeout`
- 文件传输的每一棒优先用中转主机上的 `sshpass` 喂密码;中转机没有 `sshpass` 时,回退到自动应答密码提示。回退路径下,命令输出里若恰好出现 `password:` 字样可能误触发,属于已知小风险
- 排查结束后跑 `exit`(或 `exit --all`)清理;忘记了也会按 `SSH_MUX_PERSIST` 超时自动清理
- 依赖:python3(只用标准库)、ssh、`scp`;`jump` 模式密码认证需要本机有 `sshpass`,文件传输建议中转主机也装上 `sshpass`(不装会自动回退)
- 环境变量:`SSH_MUX_CONFIG`(配置文件路径)、`SSH_MUX_SOCKET_DIR`(socket 目录,默认 /tmp)、`SSH_MUX_PERSIST`(空闲自动断开秒数,默认 600)
