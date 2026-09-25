"""不依赖 scp 的普通文件传输；连接由 ssh-mux 提供。"""

import base64
import hashlib
import math
import os
import posixpath
import re
import binascii
import shlex
import stat
import sys
import tempfile
import time


class TransferError(Exception):
    pass


def remote_spec(user, host, path):
    """SCP 用方括号包裹 IPv6；文件路径仍按传统协议转义。"""
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = "[" + host + "]"
    escaped = re.sub(r"([^A-Za-z0-9_@%+=:,./-])", r"\\\1", path)
    return user + "@" + host + ":" + escaped


def checked_path(path):
    if not path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise TransferError("文件路径不能为空或包含控制字符")
    return path


def file_digest(file):
    file.seek(0)
    digest, size = hashlib.sha256(), 0
    for block in iter(lambda: file.read(65536), b""):
        digest.update(block)
        size += len(block)
    file.seek(0)
    return size, digest.hexdigest()


class Transfer:
    """execute 返回 exit/output；stream 将文件对象与无终端 SSH 通道连接。"""

    def __init__(self, execute, stream=None, timeout=3600, cleanup_remote=None):
        if timeout <= 0:
            raise TransferError("传输超时必须大于 0 秒")
        self.execute = execute
        self.stream = stream
        self.deadline = time.monotonic() + min(timeout, 7200)
        self.work = None
        self.hash_command = None
        self.cleanup_remote = cleanup_remote

    def remaining(self):
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise TransferError("文件传输超时")
        return max(1, math.ceil(seconds))

    def run(self, command, check=True):
        # 使用子 shell，避免临时变量和 umask 改变持久会话。
        reply = self.execute("(" + command + ")", self.remaining())
        if check and reply["exit"] != 0:
            detail = reply["output"].strip()[-300:]
            raise TransferError('远端传输操作失败（退出码 {}）: {}'.format(reply['exit'], detail))
        return reply

    def output(self, command):
        return self.run(command)["output"]

    def probe(self):
        self.run("command -v wc >/dev/null && command -v cat >/dev/null && "
                 "command -v mkdir >/dev/null && command -v mv >/dev/null && command -v rm >/dev/null")
        code = ("import hashlib,sys\nh=hashlib.sha256()\n"
                "for b in iter(lambda:sys.stdin.buffer.read(65536),b''): h.update(b)\n"
                "print(h.hexdigest())")
        expected = hashlib.sha256(b"abc").hexdigest()
        for command in ("sha256sum", "shasum -a 256", "openssl dgst -sha256",
                        "python3 -c " + shlex.quote(code)):
            reply = self.run("printf '%s' abc | " + command, check=False)
            if reply["exit"] == 0 and self.parse_hash(reply["output"]) == expected:
                self.hash_command = command
                return
        raise TransferError("远端缺少可用的 SHA-256 校验工具（sha256sum、shasum、openssl 或 python3）")

    @staticmethod
    def parse_hash(output):
        values = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", output)
        return values[0].lower() if len(values) == 1 else None

    def metadata_command(self, path):
        path = shlex.quote(path)
        return ("test -f {} && test ! -L {} && printf '__SIZE__' && wc -c < {} && {} < {}".format(path, path, path, self.hash_command, path))

    def parse_metadata(self, output):
        match = re.search(r"^__SIZE__[ \t]*(\d+)[ \t]*$", output, re.M)
        digest = self.parse_hash(output)
        if not match or digest is None:
            raise TransferError("远端返回的文件长度或摘要无法解析")
        return int(match.group(1)), digest

    def metadata(self, path):
        return self.parse_metadata(self.output(self.metadata_command(path)))

    def absolute_remote(self, path):
        checked_path(path)
        if not path.startswith("/"):
            cwd = checked_path(self.output("pwd -P").rstrip("\n"))
            path = posixpath.join(cwd, path)
        return path

    def destination(self, path, basename):
        path = self.absolute_remote(path)
        if self.run("test -d " + shlex.quote(path), check=False)["exit"] == 0:
            path = posixpath.join(path, basename)
        elif path.endswith("/"):
            raise TransferError("远端目标目录不存在")
        qpath = shlex.quote(path)
        self.run('test ! -L {} && {{ test ! -e {} || test -f {}; }}'.format(qpath, qpath, qpath))
        return path

    def make_work(self, parent):
        # 路径在本机生成。断线重试时再次使用同一个目录，不遗留第二个临时目录。
        self.work = posixpath.join(parent, ".ssh_mux_transfer_" + binascii.hexlify(os.urandom(12)).decode("ascii"))
        path, data = shlex.quote(self.work), shlex.quote(self.work + "/data")
        self.run('umask 077; test ! -L {} && {{ test -d {} || mkdir -m 700 {}; }} && {{ test -f {} || : > {}; }}'.format(path, path, path, data, data))

    def cleanup(self):
        if self.work is None:
            return
        if self.cleanup_remote is not None:
            self.cleanup_remote(self.work)
            return
        try:
            reply = self.execute("(rm -rf -- " + shlex.quote(self.work) + ")", 15)
            if reply["exit"] != 0:
                raise TransferError("删除失败")
        except (Exception, SystemExit):
            print('ssh-mux: 临时目录未能清理，恢复连接后请删除: {}'.format(self.work), file=sys.stderr)

    def codec(self, direction, choice):
        self.run("command -v dd >/dev/null")
        sample = bytes((0, 1, 10, 13, 127, 128, 255))
        octal = "".join("\\0%03o" % byte for byte in sample)
        if choice != "octal":
            if direction == "push":
                candidates = ("base64 -d", "base64 -D", "openssl base64 -d -A",
                              "python3 -c " + shlex.quote(
                                  "import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(),validate=True))"))
                encoded = base64.b64encode(sample).decode()
                for command in candidates:
                    reply = self.run("printf '%s' {} | {} | {}".format(shlex.quote(encoded), command, self.hash_command), check=False)
                    if reply["exit"] == 0 and self.parse_hash(reply["output"]) == hashlib.sha256(sample).hexdigest():
                        return "base64", command
            else:
                candidates = ("base64", "openssl base64 -A",
                              "python3 -c " + shlex.quote(
                                  "import base64,sys;sys.stdout.buffer.write(base64.b64encode(sys.stdin.buffer.read()))"))
                for command in candidates:
                    reply = self.run("printf '%b' {} | {}".format(shlex.quote(octal), command), check=False)
                    try:
                        decoded = self.decode(reply["output"], "base64")
                    except TransferError:
                        continue
                    if reply["exit"] == 0 and decoded == sample:
                        return "base64", command
            if choice == "base64":
                raise TransferError("远端没有可用的 base64 编码或解码工具")
        command = "printf '%b' " + shlex.quote(octal)
        if direction == "push":
            reply = self.run(command + " | " + self.hash_command)
            if self.parse_hash(reply["output"]) != hashlib.sha256(sample).hexdigest():
                raise TransferError("远端 printf 不支持所需的八进制解码")
            return "octal", None
        output = self.output(command + " | od -An -v -tx1")
        if self.decode(output, "hex") != sample:
            raise TransferError("远端 od 不支持所需的十六进制输出")
        return "hex", "od -An -v -tx1"

    @staticmethod
    def decode(text, codec):
        try:
            if codec == "base64":
                return base64.b64decode("".join(text.split()), validate=True)
            # Python 3.4 的 fromhex 不接受 od 输出中的换行，先去除分隔空白。
            return bytes.fromhex("".join(text.split()))
        except (ValueError, UnicodeError) as exc:
            raise TransferError("文件块解码失败，目标文件未替换") from exc

    def chunk_command(self, data, offset, codec, decoder):
        part = shlex.quote(self.work + "/chunk")
        target = shlex.quote(self.work + "/data")
        if codec == "base64":
            encoded = base64.b64encode(data).decode()
            producer = "printf '%s' {} | {}".format(shlex.quote(encoded), decoder)
        else:
            encoded = "".join("\\0%03o" % byte for byte in data)
            producer = "printf '%b' " + shlex.quote(encoded)
        # 先确认解码后的长度，再按固定偏移覆盖；重复执行不会追加第二份数据。
        return ('{} > {} && test "$(wc -c < {})" -eq {} && dd if={} of={} bs=1 seek={} conv=notrunc 2>/dev/null'.format(producer, part, part, len(data), part, target, offset))

    def chunk_size(self, codec, decoder, size):
        maximum = 1024 if codec == "base64" else 256
        # 使用最大偏移预估整条命令，给 exec 的长命令阈值留出空间。
        while maximum >= 16:
            cmd = "(" + self.chunk_command(b"x" * maximum, size, codec, decoder) + ")"
            if len(shlex.quote(cmd).encode()) <= 1900:
                return maximum
            maximum //= 2
        raise TransferError("目标路径过长，无法安全分块传输")

    def push(self, local_path, remote_path, transport):
        local_path = os.path.abspath(checked_path(local_path))
        if not stat.S_ISREG(os.lstat(local_path).st_mode):
            raise TransferError("当前传输方式只支持普通文件，不支持符号链接")
        with open(local_path, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise TransferError("当前传输方式只支持普通文件")
            expected = file_digest(source)
            self.probe()
            dest = self.destination(remote_path, os.path.basename(local_path))
            codec = decoder = None
            if transport != "stream":
                codec, decoder = self.codec("push", transport)
            try:
                self.make_work(posixpath.dirname(dest))
                data = self.work + "/data"
                if transport == "stream":
                    self.stream("push", data, source, self.remaining())
                else:
                    block_size = self.chunk_size(codec, decoder, expected[0])
                    offset = 0
                    for block in iter(lambda: source.read(block_size), b""):
                        self.run(self.chunk_command(block, offset, codec, decoder))
                        offset += len(block)
                if self.metadata(data) != expected:
                    raise TransferError("上传文件的长度或 SHA-256 不一致，目标文件未替换")
                # 改名后确认丢失时，可通过最终目标再次确认成功。
                src, dst = shlex.quote(data), shlex.quote(dest)
                output = self.output('test ! -L {} && test ! -d {} && {{ if test -f {}; then mv -f {} {} || exit 1; fi; }} && '.format(dst, dst, src, src, dst)
                                     + self.metadata_command(dest))
                if self.parse_metadata(output) != expected:
                    raise TransferError("上传完成后目标文件发生变化或校验失败")
                return dest
            finally:
                self.cleanup()

    def pull(self, remote_path, local_path, transport):
        checked_path(remote_path)
        if checked_path(local_path).endswith(os.sep) and not os.path.isdir(local_path):
            raise TransferError("本地目标目录不存在")
        local_path = os.path.abspath(checked_path(local_path))
        if os.path.isdir(local_path):
            local_path = os.path.join(local_path, posixpath.basename(remote_path.rstrip("/")))
        if os.path.islink(local_path) or (os.path.exists(local_path) and not os.path.isfile(local_path)):
            raise TransferError("本地目标必须是普通文件或目录，不能是符号链接")
        self.probe()
        remote_path = self.absolute_remote(remote_path)
        expected = self.metadata(remote_path)
        codec = encoder = None
        if transport != "stream":
            codec, encoder = self.codec("pull", transport)
        temp_path = None
        try:
            if transport != "stream":
                self.make_work("/tmp")
            fd, temp_path = tempfile.mkstemp(prefix=".ssh-mux-", dir=os.path.dirname(local_path))
            with os.fdopen(fd, "w+b") as target:
                if transport == "stream":
                    self.stream("pull", remote_path, target, self.remaining())
                else:
                    # 输出块远低于守护进程的缓冲上限，末块必须与预期长度一致。
                    block_size = 32768
                    part = shlex.quote(self.work + "/chunk")
                    for index, offset in enumerate(range(0, expected[0], block_size)):
                        output = self.output('dd if={} of={} bs={} skip={} count=1 2>/dev/null && {} < {}'.format(shlex.quote(remote_path), part, block_size, index, encoder, part))
                        block = self.decode(output, codec)
                        if len(block) != min(block_size, expected[0] - offset):
                            raise TransferError("下载块长度不一致，目标文件未替换")
                        target.write(block)
                target.flush()
                if file_digest(target) != expected or self.metadata(remote_path) != expected:
                    raise TransferError("下载文件校验失败或源文件发生变化，目标文件未替换")
                os.fsync(target.fileno())
            self.remaining()
            os.replace(temp_path, local_path)
            temp_path = None
            return local_path
        finally:
            try:
                if temp_path is not None:
                    os.unlink(temp_path)
            finally:
                self.cleanup()
