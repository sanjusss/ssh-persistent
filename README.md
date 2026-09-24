# ssh-persistent

用 `ssh-mux.py` 保持 SSH 连接，方便反复排查同一台服务器。首次登录后，后续命令和文件传输继续使用已有连接。支持直接连接、标准跳板机，以及只允许交互式登录的堡垒机。

脚本可以手动运行，也可以供人工智能助手调用。

## 安装与快速开始

需要 Linux 或 `macOS`、Python 3，以及 `ssh`、`scp` 命令。原生 `Windows` 请在 `WSL`（`Windows` 的 Linux 子系统）中运行。脚本只使用 Python 标准库，无需安装 Python 依赖包。

下面演示直接连接服务器。使用密码登录时，本机还需要 `sshpass`，用于自动填写密码；使用密钥登录时，省略 `--password`。

```bash
git clone https://github.com/sanjusss/ssh-persistent.git
cd ssh-persistent
S=./ssh-mux.py

# 将地址、用户名和密码替换为实际信息，db 是自己起的主机别名
python3 $S host add db --host 7.7.7.7 --user root --password 'xxx'

# 首次执行时自动登录，之后继续使用已有连接
python3 $S exec db 'uptime'
python3 $S exec db 'df -h'

# 排查结束后断开连接
python3 $S exit db
```

配置默认保存在 `~/.config/ssh-mux/hosts.conf`，其中的密码以明文保存。请勿把真实配置提交到公开仓库。

## 作为技能安装

把整个目录放到 `~/.agents/skills/ssh-persistent/`，或项目的 `.agents/skills/ssh-persistent/` 下，供支持此技能目录的助手使用。技能入口为 [SKILL.md](SKILL.md)。

## 按任务查阅

| 要做的事 | 查看位置 |
| --- | --- |
| 配置直连、跳板机或堡垒机 | [添加主机](SKILL.md#添加主机) |
| 执行命令、设置超时、使用独立会话 | [执行命令](SKILL.md#执行命令) |
| 上传、下载文件，配置暂存主机 | [传输文件](SKILL.md#传输文件) |
| 了解命令限制和断线重试 | [使用限制与断线处理](SKILL.md#使用限制与断线处理) |
| 查找日志、修改配置路径和空闲超时 | [工作原理与排查文件](SKILL.md#工作原理与排查文件) |
| 手动编辑配置文件 | [hosts.conf.example](hosts.conf.example) |

## 文件说明

`SKILL.md` 保存完整操作说明，`hosts.conf.example` 说明配置字段，`ssh-mux.py` 执行具体操作。脚本和配置示例都放在技能根目录中。

## 许可证

采用 `MIT` 许可证，见 [LICENSE](LICENSE)。
