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
