"""混合传输的本机协调器；每个远端段由外层主机上的独立脚本执行。"""

import contextlib
import hashlib
import importlib.util
import io
import json
import math
import os
import posixpath
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import zipfile


def module_file(name):
    spec = importlib.util.spec_from_file_location("ssh_hybrid_" + name,
                                                os.path.join(os.path.dirname(__file__), name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


transfer_module = module_file("ssh_transfer")
Transfer, TransferError = transfer_module.Transfer, transfer_module.TransferError


class UnsupportedTransport(TransferError):
    pass


def protocol_rejected(message):
    return any(word in message.lower() for word in
               ("exec request failed", "subsystem request failed", "administratively prohibited"))


def plan_route(mux, cp, host, overrides):
    chain = mux.build_chain(cp, host.alias)
    hops = mux.shell_hops(chain)
    names = ["@local"] + [h.alias for h in hops]
    edges = list(zip(names, names[1:]))
    selected = {}
    for value in overrides:
        match = re.fullmatch(r"(@local|[A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)=(auto|scp|stream|base64|octal)", value)
        if not match:
            raise TransferError("--leg 格式为 A:B=scp；本机使用 @local")
        a, b, mode = match.groups()
        if (a, b) not in edges or (a, b) in selected:
            raise TransferError("--leg 必须指定未重复的相邻端点")
        selected[(a, b)] = mode
    pure_jump = all(not h.routing and (not h.via or h.via_mode == "jump") for h in chain)
    if pure_jump and not overrides:
        return [{"outer": "@local", "inner": host.alias, "transport": "auto"}]
    return [{"outer": a, "inner": b, "transport": selected.get((a, b), "auto")} for a, b in edges]


def worker_bundle():
    directory = os.path.dirname(__file__)
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source, target in (("ssh_worker.py", "__main__.py"), ("ssh_pty.py", "ssh_pty.py"),
                               ("ssh_transfer.py", "ssh_transfer.py")):
            with open(os.path.join(directory, source), "rb") as file:
                archive.writestr(target, file.read())
    return data.getvalue()


class Endpoint:
    def __init__(self, owner, host):
        self.owner, self.host = owner, host
        chain = owner.mux.build_chain(owner.cp, host.alias)
        self.jump = all(not h.routing and (not h.via or h.via_mode == "jump") for h in chain)
        self.session = "hy-" + owner.task[:12] + "-" + hashlib.sha256(host.alias.encode()).hexdigest()[:8]
        self.work = None
        self.bundle = None
        self.worker = Transfer(self.execute, self.stream if self.jump else None, owner.remaining())
        self.job_dirs = []
        self.job_targets = {}
        self.reported_leftovers = set()
        self.used = False

    def ssh_args(self, command):
        m, h = self.owner.mux, self.host
        m.jump_connect(self.owner.cp, h, quiet=True)
        return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ControlPath=" + m.jump_sock_file(self.owner.cp, h),
                "-p", str(h.port), h.user + "@" + h.host, command]

    def execute(self, command, limit):
        self.used = True
        budget = self.owner.cleanup_deadline if self.owner.cleaning else self.owner.deadline
        remaining = budget - time.monotonic()
        if remaining <= 0:
            raise TransferError("任务执行或清理时间已用完")
        limit = min(limit, remaining)
        if not self.jump:
            return self.owner.mux.shell_exec(self.host.alias, self.session, command, max(1, math.ceil(limit)))
        result = subprocess.run(self.ssh_args(command), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=limit)
        return {"exit": result.returncode,
                "output": (result.stdout + result.stderr).decode("utf-8", "replace").replace("\r", "")}

    def run(self, command):
        self.worker.deadline = self.owner.deadline
        return self.worker.output(command)

    def stream(self, action, path, file, limit):
        qpath = shlex.quote(path)
        command = f"cat > {qpath}" if action == "push" else f"cat < {qpath}"
        result = subprocess.run(self.ssh_args(command), stdin=file if action == "push" else subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL if action == "push" else file,
                                stderr=subprocess.PIPE, timeout=limit)
        if result.returncode:
            raise TransferError("本机与端点之间的 SSH 文件流失败")

    def prepare(self, parent="/tmp"):
        self.worker.deadline = self.owner.deadline
        self.worker.probe()
        try:
            self.worker.make_work(parent)
        finally:
            self.work = self.worker.work
            # 该目录由协调器统一清理，避免下一次 Transfer 操作改变引用。
            self.worker.work = None

    def metadata(self, path):
        self.worker.deadline = self.owner.deadline
        return self.worker.metadata(path)

    def put_bytes(self, data, remote):
        with tempfile.NamedTemporaryFile(dir=self.owner.local_dir) as file:
            file.write(data)
            file.flush()
            worker = Transfer(self.execute, self.stream if self.jump else None, self.owner.remaining())
            worker.push(file.name, remote, "stream" if self.jump else "auto")

    def deploy(self):
        if self.bundle:
            return
        self.run("python3 -c " + shlex.quote(
            "import sys,pty,fcntl,zlib; assert sys.version_info >= (3,4)"))
        self.bundle = self.work + "/worker.pyz"
        self.put_bytes(self.owner.bundle, self.bundle)

    def job(self, target, action, mode, op="probe", src=None, dst=None, expected=None):
        self.deploy()
        job_id = secrets.token_hex(8)
        directory = self.work + "/job-" + job_id
        self.run("mkdir -m 700 " + shlex.quote(directory))
        self.job_dirs.append(directory)
        self.job_targets[directory] = target.alias
        request = {"id": job_id, "target": {"host": target.host, "port": target.port,
                   "user": target.user, "password": target.password}, "action": action,
                   "transport": mode, "op": op, "src": src, "dst": dst, "expected": expected}
        # 部署完成后再开始远端任务计时，认证信息只写入权限为 600 的私有请求文件。
        request["timeout"] = self.owner.remaining()
        self.put_bytes(json.dumps(request).encode(), directory + "/request.json")
        launcher = ("import os,subprocess,sys;os.umask(0o077);"
                    "f=open(sys.argv[3],'ab');"
                    "subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]],"
                    "stdin=subprocess.DEVNULL,stdout=f,stderr=f,start_new_session=True)")
        command = "python3 -c " + shlex.quote(launcher) + " " + " ".join(map(shlex.quote,
                         (self.bundle, directory, directory + "/worker.log")))
        # 启动命令即使被守护进程重发，远端任务锁也会阻止重复执行。
        self.run(command)
        while True:
            text = self.run("if test -f " + shlex.quote(directory + "/result.json") + "; then cat " +
                            shlex.quote(directory + "/result.json") + "; fi")
            if text.strip():
                result = json.loads(text)
                if result.get("id") != job_id:
                    raise TransferError("远端任务结果标识不匹配")
                self.report_leftovers(directory, result)
                if result["status"] != "ok":
                    raise TransferError(f"{self.host.alias} 执行本段失败: {result['error']}")
                return result
            time.sleep(min(0.5, self.owner.remaining()))

    def report_leftovers(self, directory, result):
        for path in result.get("leftovers", []):
            key = (directory, path)
            if key not in self.reported_leftovers:
                alias = self.job_targets[directory]
                print(f"ssh-mux: 下一跳临时目录未清理 {alias}:{path}；恢复连接后请删除", file=sys.stderr)
                self.reported_leftovers.add(key)

    def stop_jobs(self):
        if not self.job_dirs:
            return True
        # 通过任务目录中的取消标记通知执行器，不依据远端 pid 杀进程。
        pending = False
        try:
            for directory in self.job_dirs:
                qdir = shlex.quote(directory)
                result = self.execute(f"if test ! -f {qdir}/result.json; then : > {qdir}/cancel; fi", 5)
                if result["exit"]:
                    pending = True
            deadline = time.monotonic() + 20
            while self.job_dirs:
                checks = " && ".join("test -f " + shlex.quote(path + "/result.json") for path in self.job_dirs)
                if self.execute(checks, 5)["exit"] == 0:
                    break
                if time.monotonic() >= deadline:
                    pending = True
                    break
                time.sleep(0.5)
            if pending:
                raise TransferError("任务结束状态未确认")
            # 超时或取消时 job() 可能未读到结果；删除日志前再收集全部残留路径。
            commands = ["cat " + shlex.quote(path + "/result.json") + "; printf '\\n'"
                        for path in self.job_dirs]
            result = self.execute("; ".join(commands), 5)
            lines = result["output"].splitlines()
            if result["exit"] or len(lines) != len(self.job_dirs):
                raise TransferError("无法读取完整清理结果")
            for directory, line in zip(self.job_dirs, lines):
                self.report_leftovers(directory, json.loads(line))
            return True
        except (Exception, SystemExit):
            return False

    def cleanup(self, stopped=True):
        if not self.work:
            return
        try:
            if not stopped:
                raise TransferError("写入进程状态未知")
            if self.execute("rm -rf -- " + shlex.quote(self.work), 10)["exit"]:
                raise TransferError("清理失败")
        except (Exception, SystemExit):
            print(f"ssh-mux: 未清理 {self.host.alias}:{self.work}；请确认任务已结束后删除", file=sys.stderr)


class Coordinator:
    def __init__(self, mux, cp, host, action, src, dst, timeout, overrides, plan_only=False):
        if timeout <= 0:
            raise TransferError("传输超时必须大于 0")
        self.mux, self.cp, self.host = mux, cp, host
        self.action, self.src, self.dst = action, src, dst
        self.deadline = time.monotonic() + min(timeout, 7200)
        self.task = secrets.token_hex(12)
        self.legs = plan_route(mux, cp, host, overrides)
        self.plan_only = plan_only
        self.endpoints = {}
        self.bundle = worker_bundle()
        self.local_dir = None
        self.cleaning = False
        self.cleanup_deadline = None

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TransferError("混合传输超过总超时")
        return max(1, math.ceil(remaining))

    def endpoint(self, alias):
        if alias not in self.endpoints:
            self.endpoints[alias] = Endpoint(self, self.mux.get_host(self.cp, alias))
        return self.endpoints[alias]

    def local_select(self, endpoint, choice):
        if choice == "auto":
            if endpoint.jump:
                remote = endpoint.execute("command -v scp >/dev/null", self.remaining())["exit"] == 0
                if shutil.which("scp") and remote:
                    try:
                        self.local_sample(endpoint, "scp")
                        return "scp"
                    except UnsupportedTransport:
                        pass
                self.local_sample(endpoint, "stream")
                return "stream"
            codec, _ = endpoint.worker.codec(self.action, "auto")
            choice = "base64" if codec == "base64" else "octal"
        if choice == "stream" and not endpoint.jump:
            raise TransferError("本机至首个端点只有终端，不能指定 stream")
        if choice in ("base64", "octal"):
            endpoint.worker.codec(self.action, choice)
        if choice == "scp":
            if endpoint.jump:
                if not shutil.which("scp") or endpoint.execute("command -v scp >/dev/null", 10)["exit"]:
                    raise TransferError("本机至首个端点缺少 scp")
            else:
                self.mux.xfer_endpoint(self.cp)
        self.local_sample(endpoint, choice)
        return choice

    def local_sample(self, endpoint, mode):
        """首段也实际传送样本，包含传统 SCP 的反向连接和暂存路径。"""
        sample = bytes(range(256))
        remote = endpoint.work + "/probe-" + secrets.token_hex(6)
        with tempfile.TemporaryDirectory(dir=self.local_dir) as directory:
            source, target = os.path.join(directory, "source"), os.path.join(directory, "target")
            with open(source, "wb") as file:
                file.write(sample)
            for action, src, dst in (("push", source, remote), ("pull", remote, target)):
                if mode == "scp" and endpoint.jump:
                    result = self.mux.jump_scp(self.cp, endpoint.host, action, src, dst, capture=True)
                    if result.returncode:
                        message = result.stdout + result.stderr
                        if protocol_rejected(message):
                            raise UnsupportedTransport("首段不允许 SCP 命令通道")
                        raise TransferError("首段 SCP 样本传输失败，未切换协议")
                elif mode == "scp":
                    output, error = io.StringIO(), io.StringIO()
                    try:
                        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                            code = self.mux.transfer_file(self.cp, endpoint.host, action, src, dst,
                                                         endpoint.session, self.remaining(), "scp")
                        if code:
                            raise TransferError("首段 SCP 样本传输失败")
                    except SystemExit:
                        raise TransferError("首段 SCP 样本传输失败，请检查反向连接、认证和暂存配置") from None
                else:
                    worker = Transfer(endpoint.execute, endpoint.stream if endpoint.jump else None, self.remaining())
                    getattr(worker, action)(src, dst, mode)
            with open(target, "rb") as file:
                if file.read() != sample:
                    raise TransferError("首段协议探测的样本不一致")
            endpoint.run("rm -f -- " + shlex.quote(remote))

    def local_leg(self, endpoint, src, dst, mode):
        if mode == "scp":
            with contextlib.redirect_stdout(io.StringIO()):
                code = self.mux.transfer_file(self.cp, endpoint.host, self.action, src, dst,
                                             endpoint.session, self.remaining(), "scp")
            if code:
                raise TransferError("本机与首个端点的 SCP 传输失败")
        else:
            worker = Transfer(endpoint.execute, endpoint.stream if endpoint.jump else None, self.remaining())
            getattr(worker, self.action)(src, dst, mode)

    def run(self):
        with tempfile.TemporaryDirectory(prefix="ssh-hybrid-") as directory:
            self.local_dir = directory
            def expired(signum, frame):
                raise TransferError("混合传输或清理超过总超时")
            previous = signal.signal(signal.SIGALRM, expired)
            signal.setitimer(signal.ITIMER_REAL, self.remaining())
            try:
                return self.perform()
            finally:
                self.cleaning = True
                self.cleanup_deadline = time.monotonic() + 30
                signal.setitimer(signal.ITIMER_REAL, 30)
                try:
                    # 先停止所有可能写入的任务，再清理作为接收端的暂存文件。
                    stopped = [endpoint.stop_jobs() for endpoint in self.endpoints.values()]
                    for endpoint in reversed(list(self.endpoints.values())):
                        endpoint.cleanup(all(stopped))
                    for endpoint in self.endpoints.values():
                        if endpoint.used and not endpoint.jump and time.monotonic() < self.cleanup_deadline:
                            with contextlib.redirect_stdout(io.StringIO()):
                                try:
                                    self.mux.cmd_exit(self.cp, endpoint.host.alias, endpoint.session)
                                except (Exception, SystemExit):
                                    pass
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    signal.signal(signal.SIGALRM, previous)

    def perform(self):
        local_path = self.src if self.action == "push" else self.dst
        remote_path = self.dst if self.action == "push" else self.src
        transfer_module.checked_path(local_path)
        transfer_module.checked_path(remote_path)
        target = self.endpoint(self.host.alias)
        target.worker.probe()
        remote_path = target.worker.absolute_remote(remote_path)
        if self.action == "push":
            local_path = os.path.abspath(local_path)
            if os.path.islink(local_path) or not os.path.isfile(local_path):
                raise TransferError("混合传输只支持普通文件")
            with open(local_path, "rb") as file:
                expected = transfer_module.file_digest(file)
            final_path = target.worker.destination(remote_path, os.path.basename(local_path))
        else:
            expected = target.metadata(remote_path)
            if local_path.endswith(os.sep) and not os.path.isdir(local_path):
                raise TransferError("本地目标目录不存在")
            local_path = os.path.abspath(local_path)
            if os.path.isdir(local_path):
                local_path = os.path.join(local_path, posixpath.basename(remote_path))
            if os.path.islink(local_path) or (os.path.exists(local_path) and not os.path.isfile(local_path)):
                raise TransferError("本地目标必须为普通文件")
            final_path = local_path

        # 所有端点先验证和准备，再开始传输用户文件。
        for leg in self.legs:
            endpoint = self.endpoint(leg["inner"])
            parent = posixpath.dirname(final_path) if self.action == "push" and endpoint is target else "/tmp"
            endpoint.prepare(parent)
        for leg in self.legs:
            if leg["outer"] == "@local":
                leg["transport"] = self.local_select(self.endpoint(leg["inner"]), leg["transport"])
            else:
                outer = self.endpoint(leg["outer"])
                result = outer.job(self.mux.get_host(self.cp, leg["inner"]), self.action, leg["transport"])
                leg["transport"] = result["transport"]
        print("混合传输计划（远端各段直接连接，不经本机转发文件）：")
        for leg in self.legs:
            a, b = leg["outer"], leg["inner"]
            direction = f"{a} → {b}" if self.action == "push" else f"{b} → {a}"
            print(f"  {direction}  {leg['transport']}  连接发起端={a}")
        if self.plan_only:
            return 0

        staged_local = None
        try:
            if self.action == "pull":
                fd, staged_local = tempfile.mkstemp(prefix=".ssh-hybrid-", dir=os.path.dirname(final_path))
                os.close(fd)
            ordered = self.legs if self.action == "push" else list(reversed(self.legs))
            current = local_path if self.action == "push" else remote_path
            for leg in ordered:
                inner = self.endpoint(leg["inner"])
                outer = None if leg["outer"] == "@local" else self.endpoint(leg["outer"])
                destination = (inner.work + "/data" if self.action == "push" else
                               outer.work + "/data" if outer else staged_local)
                if outer is None:
                    self.local_leg(inner, current, destination, leg["transport"])
                else:
                    outer.job(inner.host, self.action, leg["transport"], "transfer", current, destination, expected)
                if self.action == "push":
                    inner.run("chmod 600 " + shlex.quote(destination))
                    received = inner.metadata(destination)
                elif outer:
                    received = outer.metadata(destination)
                else:
                    with open(destination, "rb") as file:
                        received = transfer_module.file_digest(file)
                if tuple(received) != tuple(expected):
                    raise TransferError("中转副本与原始文件摘要不一致，最终目标未替换")
                current = destination
            if self.action == "push":
                with open(local_path, "rb") as file:
                    if transfer_module.file_digest(file) != expected:
                        raise TransferError("传输期间原始文件发生变化")
                src, dst = shlex.quote(current), shlex.quote(final_path)
                try:
                    result = target.run(f"test ! -L {dst} && test ! -d {dst} && "
                                        f"{{ if test -f {src}; then chmod 600 {src} && mv -f {src} {dst} || exit 1; fi; }} && "
                                        + target.worker.metadata_command(final_path))
                except (Exception, SystemExit, KeyboardInterrupt):
                    raise TransferError("最终提交状态未知，请核对目标文件；不能假定目标尚未替换") from None
                if target.worker.parse_metadata(result) != expected:
                    raise TransferError("最终提交结果无法确认，请核对目标文件")
            else:
                if target.metadata(remote_path) != expected:
                    raise TransferError("传输期间远端原始文件发生变化")
                self.remaining()
                os.chmod(staged_local, 0o600)
                os.replace(staged_local, final_path)
                staged_local = None
            print("混合传输完成，全部分段及最终文件的长度和 SHA-256 校验通过")
            return 0
        finally:
            if staged_local is not None:
                os.unlink(staged_local)
