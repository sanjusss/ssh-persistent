# ssh-persistent

SSH 长连接管理工具:一次登录,后续命令和文件传输全部复用同一条连接,不用反复握手认证。单文件 Python 脚本,只用标准库。

两种场景都能用:

- **直连 / 标准跳板机**:走 `ControlMaster` 多路复用,一次认证后命令延迟约 0.1 秒
- **堡垒机**:只给交互终端(不支持 `-J`)也能用。支持"用户名路由"型堡垒机(登录名拼成 `<账号>/<目标IP>/any` 选择目标),由后台守护进程持有终端会话链,命令像手工敲进终端一样执行

人工排查服务器可以用,给 `AI agent` 当 SSH 工具更顺手:命令行只引用主机别名,密码不出现在命令里;不同 `agent` 用 `--session` 隔开会话,互不干扰。

## 特性

- 长连接复用:`exec` / `push` / `pull` 都不再重复认证
- 多级链:本机 → 堡垒机 → 中转 → 目标,文件传输在中转机上用 `scp` 逐棒接力
- 主机管理:`host add` / `host remove` 增删主机,不用手改配置文件
- 多会话隔离:同一台主机可以并行开多条独立会话
- 断线自愈:会话断开自动重建一次

## 运行环境

- 平台:Linux 或 `macOS`。原生 `Windows` 不支持(依赖 Unix 的 `pty`、`fcntl` 等接口,且 `Win32-OpenSSH` 不支持连接多路复用),`Windows` 请使用 `WSL`
- python3(只用标准库)
- 本机有 `ssh`、`scp`;密码认证需要 `sshpass`
- 文件传输建议中转主机也装 `sshpass`(没有会自动回退到交互式应答)

## 快速上手

```bash
git clone https://github.com/sanjusss/ssh-persistent.git
cd ssh-persistent
S=./ssh-mux.py

# 添加主机(配置保存在 ~/.config/ssh-mux/hosts.conf)
python3 $S host add db --host 7.7.7.7 --user root --password 'xxx'

# 经用户名路由型堡垒机的主机
python3 $S host add bastion --host 2.2.2.2 --user T123456 \
        --password 'xxx' --routing username
python3 $S host add A --host 3.3.3.3 --user root --password 'xxx' \
        --via bastion --via-mode shell

# 日常使用
python3 $S exec A 'uptime'              # 执行远程命令(未连接时自动建连)
python3 $S push A ./app.tar.gz /tmp/    # 上传文件
python3 $S pull A /var/log/app.log ./   # 下载文件
python3 $S status                       # 查看所有连接状态
python3 $S exit A                       # 断开;exit --all 全部断开
```

文件传输依赖配置里的 `[local]` 段(中转主机回连本机用的地址和凭据):

```bash
python3 $S host add local --host <本机地址> --user <本机用户> --password 'xxx'
```

## 作为 `Kimi Code` `skill`

本目录同时是一个 `skill`:把整个目录放到 `~/.agents/skills/`(或项目的 `.agents/skills/`)下,`agent` 会自动按 `SKILL.md` 的说明调用脚本。

## 文档

- `SKILL.md`:完整命令用法、多 `agent` 并发、工作原理和注意事项
- `hosts.conf.example`:配置文件各字段的写法

## 安全说明

密码在配置文件里明文保存(`~/.config/ssh-mux/hosts.conf`,权限自动设为 `600`)。这是设计取舍:工具面向受信任的排查环境,换取配置和使用的简单。请勿把真实配置文件提交到公开仓库。

## 许可证

MIT,见 `LICENSE` 文件。
