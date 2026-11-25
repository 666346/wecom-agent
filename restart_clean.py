#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""干净环境重启 8765 本地服务（今后一律用这个脚本）。

- 剔除 PYTHONPATH 里的 WorkBuddy / sandbox-center-runtime-kit / shim 路径
- 剔除 CODEBUDDY_* / TOOL_CALL_ID / NODE_OPTIONS 等沙盒会话变量
- pythonw.exe -E 启动（忽略所有 PYTHON* 环境变量，不加载 sitecustomize）
- CREATE_NO_WINDOW + DETACHED_PROCESS，0 黑框，不打开浏览器
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import wecom_tools as T  # noqa: E402

PYW = ROOT / ".venv" / "Scripts" / "pythonw.exe"
APP = ROOT / "web_app.py"
BASE = "http://127.0.0.1:8765"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def listening_pid():
    try:
        raw = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                             capture_output=True, timeout=20,
                             creationflags=_NO_WINDOW).stdout
        # netstat 中文版输出是 GBK；数字 / LISTENING 与编码无关，容错解码即可
        out = raw.decode("gbk", errors="replace")
    except Exception:
        return None
    for line in out.splitlines():
        if "127.0.0.1:8765" in line and "LISTENING" in line:
            try:
                return int(line.split()[-1])
            except (ValueError, IndexError):
                return None
    return None


def health():
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with op.open(BASE + "/api/health", timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def main():
    pid = listening_pid()
    if pid:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                       capture_output=True, timeout=20,
                       creationflags=_NO_WINDOW)
        for _ in range(20):
            if not listening_pid():
                break
            time.sleep(0.2)

    env = T._clean_env()
    env["WECOM_NO_BROWSER"] = "1"
    for key in list(env):
        if key.upper() == "PYTHONPATH":
            env.pop(key, None)   # -E 已经隔离，再彻底清一次

    # 走 Windows Shell 启动链路（与桌面启动器一致）：WScript.Shell.Run 拉起的
    # pythonw 是独立进程，不会随本脚本/工具会话退出而被清理。
    launcher = ROOT / "launch_web.vbs"
    proc = subprocess.Popen(
        ["wscript.exe", "//B", str(launcher)],
        cwd=str(ROOT), env=env, creationflags=_NO_WINDOW,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True)

    for _ in range(80):
        if health():
            break
        time.sleep(0.5)

    result = {
        "ok": health(), "launcher_pid": proc.pid, "launcher": str(launcher),
        "pythonpath": env.get("PYTHONPATH", ""),
        "isolated_flag": "-E",
        "clean_env_vars_removed": sorted(
            k for k in ("PYTHONPATH", "CODEBUDDY_SESSION_ID", "TOOL_CALL_ID",
                        "NODE_OPTIONS", "LSBOX_AUDIT_SHMEM")
            if k not in env),
    }
    if health():
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with op.open(BASE + "/api/sandbox-status", timeout=5) as resp:
                result["server_sandbox_status"] = json.loads(
                    resp.read().decode("utf-8"))
        except Exception as exc:
            result["server_sandbox_status_error"] = str(exc)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
