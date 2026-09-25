"""在文件所在主机执行一段传输；由本机打包部署，不读取主机配置。"""

import fcntl
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

import ssh_pty as core
from ssh_transfer import Transfer, TransferError, file_digest, remote_spec


class UnsupportedTransport(TransferError):
    pass


class LoginSession(core.PtySession):
    def _wait_for(self, rx, timeout, extra=()):
        # ask 兼容较旧 OpenSSH；仅确认首次连接，主机密钥变化仍由 SSH 拒绝。
        return super()._wait_for(rx, timeout, extra=list(extra) + [(core.YESNO_RX, "yes")])


def write_json(path, value):
    temp = path + ".new"
    with open(temp, "w") as file:
        json.dump(value, file, ensure_ascii=True)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temp, path)


class Channel:
    """SSH 和文件字节均留在执行端；控制终端只返回结果。"""

    def __init__(self, target, directory, timeout):
        self.target = target
        self.directory = directory
        self.deadline = time.monotonic() + timeout
        self.control = os.path.join(directory, "ssh.sock")
        self.session = None
        self.children = set()
        self.scp_options = None
        self.pending_cleanup = set()

    def new_transfer(self):
        return Transfer(self.execute, self.stream, self.remaining(),
                        cleanup_remote=self.pending_cleanup.add)

    def cleanup_pending(self, recover=False):
        """传输结束后独立清理，失败的路径返回协调器。"""
        deadline = time.monotonic() + 15
        if not self.pending_cleanup:
            return []
        if recover:
            try:
                self.session._recover()
            except Exception:
                return sorted(self.pending_cleanup)
        for path in sorted(self.pending_cleanup):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                _, code = self.session.exec("(rm -rf -- " + shlex.quote(path) + ")", remaining)
                if code == 0:
                    self.pending_cleanup.discard(path)
            except Exception:
                pass
        return sorted(self.pending_cleanup)

    def remaining(self, limit=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TransferError("本段传输超时")
        return min(remaining, limit) if limit is not None else remaining

    def base(self):
        h = self.target
        if not h["host"] or h["host"].startswith("-") or any(c in h["host"] for c in "\r\n\x00"):
            raise TransferError("目标地址不合法")
        args = ["ssh", "-o", "StrictHostKeyChecking=ask", "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                "-o", "ControlPath=" + self.control, "-p", str(int(h["port"]))]
        if h.get("password"):
            args += ["-o", "PreferredAuthentications=keyboard-interactive,password"]
        return args

    def address(self):
        return self.target["user"] + "@" + self.target["host"]

    def start(self):
        # 前台 master 由本段独占；关闭它不会影响其他任务的连接。
        args = self.base() + ["-tt", "-M", "-o", "ControlPersist=no", self.address()]
        core.DEBUG_PTY = False
        self.session = LoginSession([(args, [(core.PW_RX, self.target.get("password", ""))])], lambda msg: None)
        try:
            self.session.start()
        except Exception:
            self.close()
            raise TransferError("执行端登录下一跳失败，请检查认证、主机身份及终端权限") from None

    def execute(self, command, limit):
        output, code = self.session.exec(command, self.remaining(limit))
        return {"exit": code, "output": output}

    def run(self, args, limit, stdin=None, stdout=subprocess.PIPE):
        # 旧 Python 在 C locale 下使用 ASCII 文件系统编码；SSH 参数统一发送 UTF-8。
        args = [arg.encode("utf-8") if isinstance(arg, str) else arg for arg in args]
        proc = subprocess.Popen(args, stdin=stdin if stdin is not None else subprocess.DEVNULL,
                                stdout=stdout, stderr=subprocess.PIPE, start_new_session=True)
        self.children.add(proc)
        try:
            output, error = proc.communicate(timeout=self.remaining(limit))
            return proc.returncode, output or b"", error
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            raise
        finally:
            self.children.discard(proc)

    def stream(self, action, path, file, limit):
        qpath = shlex.quote(path)
        command = ('umask 077; cat > {}'.format(qpath) if action == "push" else
                   'test -f {} && test ! -L {} && cat < {}'.format(qpath, qpath, qpath))
        args = self.base() + ["-T", "-o", "BatchMode=yes", self.address(), command]
        code, _, _ = self.run(args, limit, stdin=file if action == "push" else None,
                              stdout=subprocess.DEVNULL if action == "push" else file)
        if code:
            raise TransferError('远端之间的 SSH 文件流失败，退出码 {}'.format(code))

    def scp(self, action, local, remote, limit):
        # 连接在前面的终端登录中完成，复制过程不再通过控制终端输入密码。
        remote_arg = remote_spec(self.target["user"], self.target["host"], remote)
        args = ["scp"] + self.scp_options + ["-q", "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "ControlPath=" + self.control,
                "-P", str(int(self.target["port"]))]
        args += [local, remote_arg] if action == "push" else [remote_arg, local]
        code, _, error = self.run(args, limit)
        if code:
            detail = error.decode("utf-8", "replace").lower()
            if any(word in detail for word in ("exec request failed", "subsystem request failed",
                                               "administratively prohibited")):
                raise UnsupportedTransport("下一跳不允许 SCP 命令通道")
            raise TransferError('远端之间的 SCP 失败，退出码 {}'.format(code))

    def select(self, choice, action):
        transfer = self.new_transfer()
        transfer.probe()
        if choice in ("base64", "octal"):
            transfer.codec(action, choice)
            return choice
        if choice in ("auto", "scp"):
            available = shutil.which("scp") and self.execute("command -v scp >/dev/null", 10)["exit"] == 0
            if available:
                code, output, error = self.run(["scp", "-O"], 10)
                self.scp_options = ([] if re.search(r"(?:unknown|illegal|invalid) option", (output + error).decode("utf-8", "replace"), re.I) else ["-O"])
                try:
                    self.sample("scp", transfer)
                    return "scp"
                except UnsupportedTransport:
                    if choice == "scp":
                        raise
            if choice == "scp":
                raise TransferError("指定 SCP，但本段两端未提供 scp")
        # 只在已经完成认证的连接上探测能否打开无终端命令通道。
        code, output, error = self.run(self.base() + ["-T", "-o", "BatchMode=yes",
                                       self.address(), "printf SSHMUX_STREAM_OK"], 15)
        if code == 0 and output == b"SSHMUX_STREAM_OK":
            self.sample("stream", transfer)
            return "stream"
        if choice == "stream":
            raise TransferError("本段不允许无终端 SSH 命令，无法使用 stream")
        detail = error.decode("utf-8", "replace").lower()
        if "permission denied" in detail or "host key" in detail or "connection" in detail:
            raise TransferError("探测无终端连接失败，未切换协议")
        codec, _ = transfer.codec(action, "auto")
        return "base64" if codec == "base64" else "octal"

    def sample(self, mode, transfer):
        """真实传送任意字节样本，避免将安装了命令误认为协议可用。"""
        sample = bytes(range(256))
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            source, target = os.path.join(directory, "source"), os.path.join(directory, "target")
            with open(source, "wb") as file:
                file.write(sample)
            try:
                transfer.make_work("/tmp")
                remote = transfer.work + "/data"
                if mode == "scp":
                    self.scp("push", source, remote, self.remaining())
                    self.scp("pull", target, remote, self.remaining())
                else:
                    with open(source, "rb") as file:
                        self.stream("push", remote, file, self.remaining())
                    with open(target, "wb") as file:
                        self.stream("pull", remote, file, self.remaining())
                with open(target, "rb") as file:
                    if file.read() != sample:
                        raise TransferError("协议探测的二进制样本不一致")
            finally:
                transfer.cleanup()

    def transfer(self, request, mode):
        action, src, dst = request["action"], request["src"], request["dst"]
        expected = tuple(request["expected"])
        transfer = self.new_transfer()
        transfer.probe()
        if action == "push":
            with open(src, "rb") as file:
                original = file_digest(file)
        else:
            original = transfer.metadata(src)
        if original != expected:
            raise TransferError("本段源文件与原始文件摘要不一致")
        if mode != "scp":
            method = transfer.push if action == "push" else transfer.pull
            result = method(src, dst, mode)
        else:
            # dst 始终是协调器分配的暂存文件，不能是用户最终目标。
            self.scp(action, src if action == "push" else dst,
                     dst if action == "push" else src, self.remaining())
            result = dst
        if action == "push":
            if self.execute("chmod 600 " + shlex.quote(result), self.remaining())["exit"]:
                raise TransferError("无法设置中转文件权限")
            final = transfer.metadata(result)
        else:
            with open(result, "rb") as file:
                final = file_digest(file)
            os.chmod(result, 0o600)
        if final != expected:
            raise TransferError("本段目标文件与原始文件摘要不一致")
        return result

    def close(self):
        for proc in list(self.children):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        if self.session is not None:
            self.session.close()


def run_job(directory, channel_type=Channel):
    """锁和最终结果保证同一个启动命令重发时不会重复传输。"""
    os.umask(0o077)
    directory = os.path.abspath(directory)
    info = os.lstat(directory)
    if os.path.islink(directory) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise TransferError("任务目录必须属于当前用户、权限为 700 且不是符号链接")
    with open(os.path.join(directory, "lock"), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        result_path = os.path.join(directory, "result.json")
        if os.path.exists(result_path):
            return 0
        request_path = os.path.join(directory, "request.json")
        channel = None
        request = {}
        stopped = threading.Event()
        result = {"status": "error", "error": "任务未完成"}

        def interrupted(signum, frame):
            raise TransferError("任务取消或超过总超时")

        old_handlers = {sig: signal.signal(sig, interrupted) for sig in
                        (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
        try:
            with open(request_path) as file:
                request = json.load(file)
            os.unlink(request_path)
            timeout = min(float(request["timeout"]), 7200)
            if timeout <= 0:
                raise TransferError("传输超时必须大于 0")
            write_json(os.path.join(directory, "state.json"),
                       {"status": "running", "id": request["id"]})
            signal.setitimer(signal.ITIMER_REAL, timeout)
            def watch_cancel():
                while not stopped.wait(0.2):
                    if os.path.exists(os.path.join(directory, "cancel")):
                        os.kill(os.getpid(), signal.SIGTERM)
                        return
            threading.Thread(target=watch_cancel, daemon=True).start()
            channel = channel_type(request["target"], directory, timeout)
            channel.start()
            mode = channel.select(request["transport"], request["action"])
            result = {"status": "ok", "id": request["id"], "transport": mode}
            if request["op"] == "transfer":
                result["path"] = channel.transfer(request, mode)
                result["expected"] = request["expected"]
        except BaseException as exc:
            # 不返回终端尾部或完整异常参数，认证提示和命令可能含隐私。
            result = {"status": "error", "id": request.get("id"),
                      "error": str(exc) if isinstance(exc, TransferError) else type(exc).__name__}
        finally:
            stopped.set()
            signal.setitimer(signal.ITIMER_REAL, 0)
            if channel is not None:
                signal.setitimer(signal.ITIMER_REAL, 15)
                try:
                    result["leftovers"] = channel.cleanup_pending(recover=result["status"] != "ok")
                except Exception:
                    result["leftovers"] = sorted(channel.pending_cleanup)
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    channel.close()
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
            write_json(result_path, result)
        return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(run_job(sys.argv[1]))
