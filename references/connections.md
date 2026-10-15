# 主机与连接配置

新增或删除主机、配置跳板机和堡垒机时读取。连接模式选择见[技能入口](../SKILL.md#运行环境与连接方式)。

## 添加主机

配置文件默认位于 `~/.config/ssh-mux/hosts.conf`，可通过环境变量 `SSH_MUX_CONFIG` 更改（`Windows` 下的转发方式见 [Windows 说明](windows.md)）。优先使用 `host add` 和 `host remove` 管理主机，也可以手动编辑文件。

下面的地址和登录信息都是示例。将 `S` 设为本技能目录中 `ssh-mux.sh` 的实际路径；`Windows` 没有 `bash` 时改用 `ssh-mux.bat`：

```bash
S=/path/to/ssh-persistent/ssh-mux.sh

# 直接连接，db 是主机别名
$S host add db --host 7.7.7.7 --user root --password 'xxx'

# 标准跳板机：先添加 jump，再添加通过 jump 访问的 web
$S host add jump --host 5.5.5.5 --port 2222 --user jump --password 'xxx'
$S host add web --host 6.6.6.6 --user root --password 'xxx' \
        --via jump --via-mode jump

# 堡垒机：通过登录名指定目标 IP
$S host add bastion --host 2.2.2.2 --user T123456 \
        --password 'xxx' --routing username
$S host add A --host 3.3.3.3 --user root --password 'xxx' \
        --via bastion --via-mode shell

# 从 A 继续登录 B
$S host add B --host 4.4.4.4 --user root --password 'xxx' \
        --via A --via-mode shell

$S list
$S host remove B
```

`host add` 只保存配置，不连接主机。别名已存在时，需要先删除再添加。如果其他主机的 `via` 引用了某个别名，脚本会拒绝删除该别名。删除配置不会断开已经建立的会话。

脚本保存配置时会将权限设为 `600`，即只有文件所有者可以读写。保存时会重写整个配置文件，原有注释会丢失。密码以明文保存，请勿把真实配置提交到公开仓库。

### 手动编辑配置

配置采用 `INI` 格式：每台主机占一个 `[别名]` 段，下面填写 `字段=值`。各字段的含义、默认值和完整示例统一放在 [hosts.conf.example](../hosts.conf.example) 中，手动编辑时查阅该文件。

`routing=username` 适用于登录名格式为 `<账号>/<目标IP>/any` 的堡垒机。脚本先填写堡垒机密码，再根据目标机的提示填写用户名和密码。

密码中的 `%` 等特殊字符无需转义。手动编辑配置时，不要在密码后面添加行内注释，以免注释被当作密码的一部分。

## 逐段代理

每台主机的 `proxy` 系列字段控制“上一节点 → 该主机”这一段连接，支持 `http`（HTTP `CONNECT`）和 `socks5`。代理不会沿登录链继承或串联，各段可以使用不同类型的代理。

```bash
# db 经 HTTP 代理直连；proxy_user/proxy_password 可省略
$S host add db --host 7.7.7.7 --user root --password 'xxx' \
        --proxy http --proxy-host proxy.corp.example --proxy-port 8080 \
        --proxy-user 'account' --proxy-password 'xxx'

# web 经标准跳板 jump 登录，jump 到 web 这一段走 SOCKS5 代理
$S host add web --host 6.6.6.6 --user root --password 'xxx' \
        --via jump --via-mode jump \
        --proxy socks5 --proxy-host 10.2.2.2 --proxy-port 1080
```

每段的代理按以下顺序决定：

1. `proxy=direct`：显式直连，忽略同主机其余 `proxy_*` 字段和环境变量。
2. `proxy=http` 或 `proxy=socks5`：使用完整的显式配置。
3. 完全没有代理字段时，只有从本机出发的第一段读取环境变量 `SSH_MUX_PROXY`，格式为 `http://主机:端口` 或 `socks5://主机:端口`，不能包含用户名和密码。后续各段默认直连，不读取该变量。

只写 `proxy_*` 字段而没有 `proxy`、端口超出 1-65535、类型未知或写成代理链表达式，都会被拒绝；配置错误时不会改成直连。地址中的空白、回车、换行和 `%` 等字符同样被拒绝，因为地址要作为字面量拼进连接命令。

### 执行位置与 Python 要求

同一段代理由哪一方执行握手，取决于该段的实际执行位置，而不是 `via_mode`：

- 本机出发的第一段：握手程序在本机运行，直接连接代理。
- 标准跳板段（`via_mode=jump`）：本机握手程序经 `ssh -W 代理地址:端口` 复用跳板的连接访问代理。跳板只需转发字节，无需安装 Python。
- 远端终端段（堡垒机链路）：握手程序部署到该段起点主机，该主机需要 Python 3.4 或更新版本及标准库；不满足时报出节点和原因，不会自动安装软件。普通无代理登录不增加这项要求。

混合链示例：`A → B` 是带代理的 `jump`、`B → C` 是 `shell` 时，本机先建立到 `B` 的连接（`A` 无需 Python），再在 `B` 的终端里登录 `C`；只有 `B → C` 使用代理时才在 `B` 上准备远端程序。

### 凭据保存与生命周期

代理用户名和密码只写入私有文件，不进入任何 `ssh`、`sshpass` 或终端命令的参数和环境：

- 本机：运行目录下的 `px_<连接实例>/config.json`，目录权限 `700`，文件权限 `600`。每个连接实例一份，连接停止、建立失败或确认失效后删除；文件丢失时按当前配置重新生成。查看（`status`）和断开（`exit`）不读取凭据文件，也不执行代理握手。
- 远端：段起点主机上的 `/tmp/.ssh_mux_px_*/`，目录权限 `700`，程序和配置权限 `600`。登录会话准备的资源随会话关闭清理；文件传输准备的资源在传输结束（含失败和中断）时清理。清理失败会报告节点和残留路径，请恢复连接后手动删除。

远端资源有两处准备入口：终端登录到下一跳之前，以及传统 `scp` 传输在已有会话中启动复制之前。两处使用同一个准备接口，都只依赖到段起点的现有连接，不需要反向连接。

更改某台主机的代理配置会改变它和依赖它的所有连接的标识。请先 `exit` 断开相关连接再修改，否则新连接与旧连接并存，旧连接仍按各自的空闲超时退出。

### 用户名路由与 `[local]` 的特殊规则

用户名路由堡垒机没有独立终端，本机实际连接的是堡垒机地址。入口段使用堡垒机的代理配置；目标主机上配置的 `http` 或 `socks5` 代理对这段不生效，`list` 和首次建连会提示实际入口别名。目标主机登录下一台时，那段连接按普通远端段处理。

`[local]` 段的代理字段不控制本机出站，只作为说明保留。本机主动连接暂存机时，按暂存机自己的登录链应用代理。
