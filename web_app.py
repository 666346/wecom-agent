#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""企微 AI 导出工具 · 本地 Web 服务。

只监听 127.0.0.1:8765，不对外网开放；复用现有 .venv 与 wecom_tools.py。
用标准库 http.server，无需额外安装 FastAPI / Flask / Streamlit。
"""
import json
import os
import shutil
import sys
import threading
import time
import traceback
import urllib.request
import uuid
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, quote

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import wecom_tools as T  # noqa: E402

HOST = "127.0.0.1"
PORT = 8765
RUNTIME = ROOT / "runtime"
RUNTIME.mkdir(parents=True, exist_ok=True)
LOG_FILE = RUNTIME / "web.log"
UI_FILE = ROOT / "web_ui.html"

LOG_BUFFER = deque(maxlen=600)
LOG_LOCK = threading.Lock()
TASKS = {}
TASKS_LOCK = threading.Lock()
SYNC_STOP = threading.Event()
SYNC_THREAD = None
SYNC_ENABLED = False
SYNC_LOCK = threading.Lock()
SERVER = None


def log(message):
    line = f"[{time.strftime('%H:%M:%S')}] {message}"
    with LOG_LOCK:
        LOG_BUFFER.append(line)
        try:
            with LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass


# ---------------------------------------------------------------- 异步任务

TASK_TIMEOUT_SECONDS = 240  # 任何任务超过 4 分钟仍未收敛就自动置为 error


def start_task(fn, **kwargs):
    task_id = uuid.uuid4().hex[:8]
    with TASKS_LOCK:
        TASKS[task_id] = {"status": "running", "log": [], "result": None,
                          "error": None, "started_at": time.time(),
                          "timeout_s": TASK_TIMEOUT_SECONDS}

    def emit(message):
        with TASKS_LOCK:
            task = TASKS.get(task_id)
            if task is not None:
                task["log"].append(str(message))
        log(f"[task {task_id}] {message}")

    def fail(reason, detail=""):
        """把 running 收敛为 error；只在仍是 running 时生效，避免覆盖正常完成。"""
        with TASKS_LOCK:
            task = TASKS.get(task_id)
            if task is None or task["status"] != "running":
                return False
            task["error"] = reason
            task["status"] = "error"
            task["log"].append(f"[错误] {reason}")
        log(f"[task {task_id}] ERROR {reason}")
        if detail:
            log(f"[task {task_id}] TRACE {detail[-1000:]}")
        return True

    def runner():
        try:
            result = fn(emit, **kwargs)
        except BaseException as exc:
            # SystemExit / KeyboardInterrupt 等 BaseException 也必须收敛。
            # 外部运行时可能把 shutil.rmtree 包装成带守卫的版本，守卫拒绝时
            # 抛的正是 SystemExit；只捕获 Exception 会让线程静默死亡、任务
            # 永远停在 running，前端就一直卡在「正在导出…」。
            fail(f"{type(exc).__name__}: {exc}", traceback.format_exc())
            return
        with TASKS_LOCK:
            task = TASKS.get(task_id)
            if task is not None and task["status"] == "running":
                task["result"] = result
                task["status"] = "done"

    def watchdog():
        """万一将来还有未知阻塞，兜底把任务从 running 收敛掉。"""
        deadline = time.monotonic() + TASK_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(2)
            with TASKS_LOCK:
                task = TASKS.get(task_id)
                if task is None or task["status"] != "running":
                    return
        fail(f"任务超时（超过 {TASK_TIMEOUT_SECONDS} 秒仍未完成），已自动结束；"
             "请查看服务日志定位卡点")

    threading.Thread(target=runner, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    return task_id


def task_export(emit, cid, account, name, ids, zip_mode="timestamp", lite_mode="auto",
                items=None):
    cfg = T.load_config()
    if items:
        # 多会话合并：以第一个会话的账号/ cid 作为兼容字段，实际消息池由 items 决定
        account = str(items[0].get("account") or account)
        cid = str(items[0].get("cid") or cid)
    acc = next((a for a in cfg["accounts"] if a["id"] == account), None)
    if acc is None:
        raise RuntimeError(f"账号 {account} 不在配置中，请先点「重新扫描企微账号与密钥」")
    selected = (sum(len(x.get("ids") or []) for x in items)
                if items else len(ids))
    emit(f"开始导出：{name or cid}（已勾选 {selected} 条消息）")
    if items:
        emit(f"多会话合并模式：{len(items)} 个会话按真实时间统一排序，"
             "附件全局连续编号，打包成 1 个 ZIP…")
    emit("在 runtime/tmp_export 临时目录生成聊天记录和编号附件，随后打包为单个 ZIP…")
    result = T.precise_export(cfg, acc, cid, name, ids,
                              zip_mode=zip_mode, lite_mode=lite_mode,
                              progress=emit, items=items)
    emit(f"聊天导出完成：{result['messages']} 条消息 / {result['attachments_ok']} 个附件"
         f"（扫描缓存 {result['cache_files_scanned']} 个文件，只取命中项）")
    ai = result.get("all_for_ai") or {}
    counts = result.get("counts") or {}
    emit(f"ALL_FOR_AI.md 已在 ZIP 内生成（{ai.get('size_kb')} KB，"
         f"展开 {ai.get('documents')} 个文档正文 / {ai.get('images')} 张图片 / "
         f"{ai.get('other_files')} 个其它原格式文件）")
    emit(f"卡片递归展开：{ai.get('forward_cards', 0)} 张（合并转发/图文混排）共 "
         f"{ai.get('forward_subs', 0)} 条子消息（含各层）；卡片附件 "
         f"{counts.get('card_total_files', 0)} 个 = 已匹配 {counts.get('card_matched', 0)} 个 "
         f"+ 未缓存 {counts.get('card_missing', 0)} 个")
    emit(f"统计自检：实际打包 {counts.get('attachments', 0)} = 分类合计 "
         f"{counts.get('classified', 0)}，未下载 {counts.get('missing', 0)} 个")
    extra = result.get("extra_scan") or {}
    hits = extra.get("hits") or []
    if hits:
        emit(f"来自补扫目录命中 {len(hits)} 个（企微 Cache 未命中，已在本机常用目录精准找回）：")
        for item in hits[:10]:
            emit(f"  · {item['name']} ← {item['dir']}"
                 f"（{item['size']:,} 字节 / 消息期望 {item['expected_size']:,} 字节）")
        emit(f"补扫统计：{len(extra.get('dirs') or [])} 个目录 / "
             f"扫描 {extra.get('scanned_files')} 个文件 / 耗时 {extra.get('elapsed_ms')} ms"
             + ("（达到上限已截断）" if extra.get("truncated") else ""))
    emit(f"ZIP 已生成：{result['zip_path']}"
         f"（{result['zip_size_kb']} KB / {len(result['zip_entries'])} 个包内条目）")
    lite = result.get("lite") or {}
    if lite.get("generated"):
        emit(f"网页 AI 轻量包已生成：{lite['zip_path']}（{lite['zip_size_kb']} KB，"
             f"为完整包的 {lite.get('ratio_pct')}%，节省 {lite.get('saved_kb')} KB）"
             f"【触发原因：{lite.get('reason')}】")
        emit(f"轻量包处理：大图瘦身 {len(lite.get('shrunk') or [])} 张（长边≤1600px / JPG 82%）"
             f" / 超大原件跳过 {len(lite.get('skipped') or [])} 个"
             f" / 原样保留 {lite.get('kept_count')} 个；编号与聊天顺序同完整包完全一致")
        for item in (lite.get("skipped") or [])[:10]:
            emit(f"  · 跳过 {item['name']}（{item['size_mb']} MB）→ 已在 000_chat.md / ALL_FOR_AI.md 原位标注")
    else:
        reason = {"under_20mb": "完整包 ≤20MB，无需额外生成轻量包",
                  "off": "轻量包已关闭"}.get(lite.get("reason"), "未生成轻量包")
        emit(f"轻量包：{reason}")
    emit("临时目录已清理；导出根目录只新增本次的 ZIP，不再生成群文件夹"
         if result.get("temp_dir_cleaned") else
         "临时目录清理未完成（已登记待清理，不影响本次导出结果）")
    emit(f"missing 附件 {len(result.get('missing') or [])} 个"
         "（合并转发里的图片需在企业微信点开卡片查看原图/下载文件后重新导出）")
    return result


def task_rescan(emit):
    emit("正在扫描 WXWork.exe 进程内存（约 1–2 分钟，有时间上限），请确保企业微信已登录并运行…")
    result = T.rescan()
    for line in result.get("scan_lines", []):
        emit(line)
    if result.get("scan_limited"):
        emit("扫描达到时间上限，已保留本次与历史 key；如需找更多账号，可切换企微账号后再点一次")
    for item in result.get("refreshed", []):
        emit(f"账号 {item['account']}：刷新 {item['conversations']} 个会话")
    for error in result.get("errors", []):
        emit(f"跳过：{error}")
    emit(f"完成：解锁 key {len(result.get('keys', []))} 把，新增账号 {len(result.get('added', []))} 个")
    return result


# ---------------------------------------------------------------- 内置 5 分钟同步

def sync_worker():
    log("[sync] 自动同步已开启（间隔 300 秒）")
    while not SYNC_STOP.is_set():
        try:
            cfg = T.load_config()
            result = T.sync(cfg)
            if result.get("skipped"):
                log(f"[sync] 检查完成：无变化（{result.get('reason', '')}）")
            else:
                log(f"[sync] 刷新完成 @ {result.get('time')}，变化账号 {', '.join(result.get('changed', [])) or '无'}")
                for item in result.get("results", []):
                    if item.get("messages"):
                        log(f"[sync]   {item.get('name')} → {item['messages']} 条 / "
                            f"{item.get('attachments_ok', 0)} 附件 / ZIP {item.get('zip_name', '')} / "
                            f"missing {len(item.get('missing') or [])}")
                for error in result.get("errors", []):
                    log(f"[sync]   ERR {error}")
        except Exception as exc:
            log(f"[sync] 异常：{exc}")
        SYNC_STOP.wait(300)
    log("[sync] 自动同步已停止")


def set_sync(enabled):
    global SYNC_THREAD, SYNC_ENABLED
    with SYNC_LOCK:
        if enabled and not SYNC_ENABLED:
            SYNC_STOP.clear()
            SYNC_THREAD = threading.Thread(target=sync_worker, daemon=True)
            SYNC_THREAD.start()
            SYNC_ENABLED = True
        elif not enabled and SYNC_ENABLED:
            SYNC_STOP.set()
            SYNC_ENABLED = False
        return SYNC_ENABLED


# ---------------------------------------------------------------- HTTP

class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = "WeComLocal/1.0"

    def log_message(self, fmt, *args):
        pass  # 不刷控制台

    def _send(self, code, body, content_type):
        data = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control",
                         "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False, indent=2),
                   "application/json; charset=utf-8")

    def _send_zip(self, target):
        size = target.stat().st_size
        filename = target.name
        ascii_name = filename.encode("ascii", "replace").decode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header(
            "Content-Disposition",
            f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename, safe='')}",
        )
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control",
                         "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        try:
            with target.open("rb") as source:
                shutil.copyfileobj(source, self.wfile, 1024 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _handle(self, method):
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        body = self._body() if method == "POST" else {}
        try:
            if method == "GET":
                if path in ("/", "/index.html"):
                    return self._send(200, UI_FILE.read_text(encoding="utf-8"),
                                      "text/html; charset=utf-8")
                if path == "/api/health":
                    return self._json({"ok": True, "port": PORT,
                                       "time": time.strftime("%Y-%m-%d %H:%M:%S")})
                if path == "/api/sandbox-status":
                    return self._json({
                        "sandbox": T.sandbox_status(),
                        "pythonpath": os.environ.get("PYTHONPATH", ""),
                        "ignore_environment": bool(sys.flags.ignore_environment),
                        "sitecustomize_loaded": "sitecustomize" in sys.modules,
                        "isolated": ("workbuddy" not in
                                     os.environ.get("PYTHONPATH", "").lower()
                                     and "shim" not in
                                     os.environ.get("PYTHONPATH", "").lower()),
                    })
                if path == "/api/codex/status":
                    return self._json(T.codex_status())
                if path == "/api/status":
                    return self._json(T.account_status(T.load_config()))
                if path == "/api/conversations":
                    return self._json(T.list_conversations(T.load_config()))
                if path == "/api/preview":
                    cid = query.get("cid", [""])[0]
                    account = query.get("account", [""])[0]
                    cfg = T.load_config()
                    acc = next((a for a in cfg["accounts"] if a["id"] == account), None)
                    if acc is None:
                        raise RuntimeError(f"账号 {account} 不在配置中")
                    return self._json(T.preview_messages(cfg, acc, cid, 20))
                if path == "/api/messages":
                    cid = query.get("cid", [""])[0]
                    account = query.get("account", [""])[0]
                    range_key = query.get("range", ["all"])[0]
                    start = query.get("start", [""])[0]
                    end = query.get("end", [""])[0]
                    cfg = T.load_config()
                    acc = next((a for a in cfg["accounts"] if a["id"] == account), None)
                    if acc is None:
                        raise RuntimeError(f"账号 {account} 不在配置中")
                    return self._json(T.messages_window(cfg, acc, cid, range_key, start, end))
                if path == "/api/changes":
                    # 前端 8 秒静默轮询：水印检查 + WAL 增量补丁，不做全量解析
                    cid = query.get("cid", [""])[0]
                    account = query.get("account", [""])[0]
                    last_id = query.get("last_id", [""])[0]
                    cfg = T.load_config()
                    acc = next((a for a in cfg["accounts"] if a["id"] == account), None)
                    if acc is None:
                        raise RuntimeError(f"账号 {account} 不在配置中")
                    return self._json(T.check_changes(cfg, acc, cid, last_id))
                if path == "/api/thumb":
                    # 合并转发里的图片缩略图：只按 会话+消息+序号 反查本机缓存
                    cid = query.get("cid", [""])[0]
                    account = query.get("account", [""])[0]
                    mid = query.get("mid", [""])[0]
                    try:
                        sub_i, file_i = int(query.get("i", ["0"])[0]), int(query.get("j", ["0"])[0])
                    except ValueError:
                        raise RuntimeError("缩略图序号无效")
                    cfg = T.load_config()
                    acc = next((a for a in cfg["accounts"] if a["id"] == account), None)
                    if acc is None:
                        raise RuntimeError(f"账号 {account} 不在配置中")
                    source, ext = T.forward_thumb(acc, cid, mid, sub_i, file_i)
                    if source is None:
                        return self._send(404, "图片尚未缓存", "text/plain; charset=utf-8")
                    if source.stat().st_size > 20 * 1024 * 1024:
                        return self._send(413, "图片过大", "text/plain; charset=utf-8")
                    mime = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
                            ".gif": "image/gif", ".webp": "image/webp"}.get(ext, "image/jpeg")
                    return self._send(200, source.read_bytes(), mime)
                if path == "/api/watch":
                    return self._json(T.watch_get())
                if path == "/api/sync-status":
                    data = T.sync_status()
                    with SYNC_LOCK:
                        data["enabled"] = SYNC_ENABLED
                    return self._json(data)
                if path == "/api/logs":
                    n = int(query.get("n", ["80"])[0])
                    with LOG_LOCK:
                        lines = list(LOG_BUFFER)[-n:]
                    return self._json({"lines": lines})
                if path == "/api/task":
                    task_id = query.get("id", [""])[0]
                    with TASKS_LOCK:
                        task = dict(TASKS.get(task_id, {"status": "missing",
                                                        "error": "任务不存在", "log": []}))
                    return self._json(task)
                if path == "/api/extra-scan-dirs":
                    cfg = T.load_config()
                    return self._json({"dirs": T.get_extra_scan_dirs(cfg),
                                       "defaults": T.default_extra_scan_dirs(cfg),
                                       "initialized": "extra_scan_dirs" in cfg})
                if path == "/api/voice":
                    target = T.resolve_voice_audio(query.get("path", [""])[0])
                    data, _ = T.silk_to_mp3(target)
                    if not data:
                        raise RuntimeError("语音转 MP3 失败，请检查 pysilk / ffmpeg 是否可用")
                    return self._send(200, data, "audio/mpeg")
                if path in ("/api/download-zip", "/api/download-lite"):
                    target = T.resolve_export_zip(query.get("path", [""])[0])
                    return self._send_zip(target)

            if method == "POST":
                if path == "/api/extra-scan-dirs":
                    dirs = body.get("dirs")
                    if dirs is None:
                        # 兼容单条增删
                        current = T.get_extra_scan_dirs(T.load_config())
                        action, value = body.get("action"), str(body.get("path") or "").strip()
                        if action == "add" and value:
                            if value.casefold() not in {x.casefold() for x in current}:
                                current.append(value)
                            dirs = current
                        elif action == "remove" and value:
                            dirs = [x for x in current if x.casefold() != value.casefold()]
                        else:
                            raise RuntimeError("缺少 dirs / action+path")
                    saved = T.save_extra_scan_dirs(dirs)
                    log(f"[ui] 补扫目录已更新：{len(saved)} 个")
                    return self._json({"dirs": saved, "ok": True})
                if path == "/api/sandbox-selftest":
                    return self._json(T.sandbox_delete_selftest())
                if path == "/api/codex/start":
                    return self._json(T.codex_start(body))
                if path == "/api/codex/refresh":
                    return self._json({"project": T.codex_refresh(body.get("id") or "")})
                if path == "/api/codex/quick-sync":
                    return self._json(T.codex_quick_sync(body.get("id") or ""))
                if path == "/api/codex/rename-note":
                    return self._json(T.codex_rename_note(
                        body.get("id") or "", body.get("alias_note") or ""))
                if path == "/api/codex/mark-sent":
                    return self._json(T.codex_mark_sent(
                        body.get("id") or "", body.get("count")))
                if path == "/api/codex/pull-dm":
                    return self._json(T.codex_pull_dm(body.get("id") or ""))
                if path == "/api/codex/toggle-lock":
                    return self._json(T.codex_toggle_lock(
                        body.get("id") or "", body.get("cid"),
                        body.get("locked")))
                if path == "/api/codex/transfer":
                    return self._json(T.codex_transfer(
                        body.get("id") or "", body.get("target") or "codex"))
                if path == "/api/codex/stop":
                    return self._json(T.codex_stop(body.get("id") or ""))
                if path == "/api/codex/open":
                    return self._json(T.codex_open(body.get("id") or ""))
                if path == "/api/codex/open-root":
                    return self._json(T.codex_open_root(
                        body.get("target") or "codex"))
                if path == "/api/codex/root":
                    return self._json(T.codex_set_root(
                        body.get("root") or "", body.get("target") or "codex"))
                if path == "/api/codex/tick":
                    return self._json(T.codex_tick())
                if path == "/api/export":
                    cid, account = body.get("cid"), body.get("account")
                    ids = body.get("ids") or []
                    items = body.get("items") or []
                    zip_mode = body.get("zip_mode") or "timestamp"
                    lite_mode = body.get("lite_mode") or "auto"
                    if items:
                        if len(items) < 2:
                            raise RuntimeError("合并导出至少需要 2 个会话")
                        clean_items = [{
                            "account": str(x.get("account") or ""),
                            "cid": str(x.get("cid") or ""),
                            "name": str(x.get("name") or ""),
                            "ids": [str(i) for i in (x.get("ids") or [])],
                        } for x in items]
                        if any(not x["account"] or not x["cid"] or not x["ids"]
                               for x in clean_items):
                            raise RuntimeError("合并导出里有会话缺少账号 / cid / 已选消息")
                        return self._json({"task_id": start_task(
                            task_export, cid=clean_items[0]["cid"],
                            account=clean_items[0]["account"],
                            name=body.get("name"), ids=[], zip_mode=zip_mode,
                            lite_mode=lite_mode, items=clean_items)})
                    if not cid or not account:
                        raise RuntimeError("缺少 cid / account")
                    if not ids:
                        raise RuntimeError("没有勾选任何消息，请先在右侧列表里选择")
                    return self._json({"task_id": start_task(
                        task_export, cid=cid, account=account, name=body.get("name"),
                        ids=[str(x) for x in ids], zip_mode=zip_mode,
                        lite_mode=lite_mode)})
                if path == "/api/rescan":
                    return self._json({"task_id": start_task(task_rescan)})
                if path == "/api/refresh":
                    cfg = T.load_config()
                    result = T.list_conversations(cfg, force=True)
                    log(f"[ui] 会话缓存已刷新：{result['count']} 个会话")
                    return self._json({"count": result["count"]})
                if path == "/api/watch":
                    return self._json(T.watch_set(body.get("ids") or []))
                if path == "/api/sync-control":
                    return self._json({"enabled": set_sync(bool(body.get("enabled")))})
                if path == "/api/open-folder":
                    return self._json(T.open_folder(body.get("path") or ""))
                if path == "/api/prune-cache":
                    target = body.get("path") or ""
                    if not target:
                        raise RuntimeError("缺少 path")
                    result = T.prune_cache(target)
                    log(f"[ui] 清理旧缓存：{result.get('removed', 0)} 个文件（保留 {result.get('kept', 0)} 个）")
                    return self._json(result)
                if path == "/api/shutdown":
                    self._json({"stopping": True})
                    threading.Thread(target=lambda: SERVER.shutdown(), daemon=True).start()
                    return None
            return self._json({"error": "未知路径 " + path}, 404)
        except Exception as exc:
            return self._json({"error": str(exc), "trace": traceback.format_exc()[-700:]}, 500)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


def codex_worker():
    """按配置间隔静默检查水印；只做文件 stat 比对，纯 Python 线程不启子进程（0 黑框）。"""
    log(f"[codex] 实时在办目录监控已启动（{T.CODEX_INTERVAL_SECONDS}s 水印检查）")
    while True:
        try:
            outcome = T.codex_tick()
            if outcome.get("refreshed"):
                log(f"[codex] 增量刷新 {len(outcome['refreshed'])} 个项目"
                    f"，精准跳过 {len(outcome.get('skipped') or [])} 个")
        except Exception as exc:
            log(f"[codex] tick 异常: {exc}")
        time.sleep(T.CODEX_INTERVAL_SECONDS)


def main():
    global SERVER
    url = f"http://{HOST}:{PORT}"
    try:
        SERVER = Server((HOST, PORT), Handler)
    except OSError:
        try:
            with urllib.request.urlopen(url + "/api/health", timeout=2) as response:
                if response.status == 200:
                    print("An instance is already running; opening the existing page.", flush=True)
                    webbrowser.open_new(url)
                    return
        except Exception:
            pass
        print(f"[ERROR] Port {PORT} is occupied by another program.", flush=True)
        sys.exit(2)

    log("=" * 56)
    log(f"本地服务启动：{url}")
    _sb = T.sandbox_status()
    log(f"[sandbox] sitecustomize_loaded={_sb['shim_loaded']} "
        f"restored_delete_primitives={_sb['restored']} "
        f"ignore_environment={bool(sys.flags.ignore_environment)}")
    threading.Thread(target=codex_worker, daemon=True).start()
    print(f"WeCom AI Export Tool running at {url}", flush=True)
    print("Keep this window open. Close it or press Ctrl+C to stop the service.", flush=True)
    if os.environ.get("WECOM_NO_BROWSER") != "1":
        threading.Thread(target=lambda: (time.sleep(1.0), webbrowser.open_new(url)),
                         daemon=True).start()
    try:
        SERVER.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        set_sync(False)
        SERVER.server_close()
        log("本地服务已停止")


if __name__ == "__main__":
    main()
