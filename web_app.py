#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""企微 AI 导出工具 · 本地 Web 服务。

只监听 127.0.0.1:8765，不对外网开放；复用现有 .venv 与 wecom_tools.py。
用标准库 http.server，无需额外安装 FastAPI / Flask / Streamlit。
"""
import json
import os
import queue
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
TASK_QUEUE = queue.Queue()   # 常驻 worker，HTTP 入口只入队，绝不现开线程
_TASK_FAIL = {}
SYNC_STOP = threading.Event()
_STATUS_CACHE = {"at": 0.0, "data": None}
_STATUS_LOCK = threading.Lock()
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
            # 标记前台耗时任务：3 秒同步 / 5 分钟自动同步见到就主动让路
            with T.front_busy():
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

    _TASK_FAIL[task_id] = fail
    TASK_QUEUE.put(runner)   # 常驻线程池消费；HTTP 线程 0.1 秒内返回 task_id
    return task_id


def task_worker():
    while True:
        runner = TASK_QUEUE.get()
        try:
            runner()
        finally:
            TASK_QUEUE.task_done()


def task_watchdog():
    """单一常驻巡检替代每任务一个 watchdog 线程，避免入口现开线程。"""
    while True:
        time.sleep(2)
        now = time.time()
        expired = []
        with TASKS_LOCK:
            for task_id, task in TASKS.items():
                if (task.get("status") == "running"
                        and now - float(task.get("started_at") or 0)
                        > TASK_TIMEOUT_SECONDS):
                    expired.append(task_id)
        for task_id in expired:
            fail = _TASK_FAIL.get(task_id)
            if fail:
                fail(f"任务超时（超过 {TASK_TIMEOUT_SECONDS} 秒仍未完成），"
                     "已自动结束；请查看服务日志定位卡点")


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


def task_refresh(emit):
    """异步刷新会话列表：HTTP 入口 <0.1s 返回 task_id，不阻塞请求线程。"""
    emit("正在刷新会话与媒体缓存…")
    cfg = T.load_config()
    T.invalidate_media_caches()
    result = T.list_conversations(cfg, force=True)
    log(f"[ui] 会话与媒体缓存已刷新：{result['count']} 个会话")
    return {"count": result["count"]}


def status_refresher():
    """后台刷新顶部状态快照；HTTP 只读内存，绝不因 tasklist/目录枚举卡住。"""
    while True:
        try:
            data = T.account_status(T.load_config())
            with _STATUS_LOCK:
                _STATUS_CACHE.update({"at": time.time(), "data": data})
        except Exception as exc:
            log(f"[status] 快照刷新异常：{exc}")
        time.sleep(2)


def task_codex_refresh(emit, project_id):
    """异步刷新单个在办项目，避免 HTTP 线程里重导大目录。"""
    emit("正在刷新该在办项目…")
    return {"project": T.codex_refresh(project_id)}


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
    log("[sync] 自动同步已开启（间隔 300 秒，后台非阻塞让路）")
    while not SYNC_STOP.is_set():
        try:
            if T.front_is_busy():
                log("[sync] 前台操作进行中，后台本轮让路")
            else:
                cfg = T.load_config()
                result = T.sync(cfg, background=True)
                if result.get("skipped"):
                    log(f"[sync] 检查完成：无变化（{result.get('reason', '')}）")
                else:
                    log(f"[sync] 刷新完成 @ {result.get('time')}，变化账号 "
                        f"{', '.join(result.get('changed', [])) or '无'}")
                    for item in result.get("results", []):
                        if item.get("messages"):
                            log(f"[sync]   {item.get('name')} → {item['messages']} 条 / "
                                f"{item.get('attachments_ok', 0)} 附件 / ZIP "
                                f"{item.get('zip_name', '')} / missing "
                                f"{len(item.get('missing') or [])}")
                    for error in result.get("errors", []):
                        log(f"[sync]   ERR {error}")
        except T.BusySkip as exc:
            log(f"[sync] {exc}")
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
                    return self._json({
                        "ok": True, "port": PORT,
                        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "heartbeat_age": round(
                            time.time() - T._CODEX_LAST_TICK["at"], 2),
                        "tick_runs": T._CODEX_LAST_TICK["runs"],
                        "front_busy": T.front_is_busy()})
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
                    # 100% 只读后台已算好的内存快照：HTTP 线程零 stat / 零子进程
                    with _STATUS_LOCK:
                        data = _STATUS_CACHE["data"]
                    return self._json(data or {"accounts": [],
                                               "locked_accounts": [],
                                               "wecom_running": False,
                                               "total_accounts": 0})
                if path == "/api/conversations":
                    # 只读会话缓存快照，高频轮询 100% 无锁、毫秒返回
                    return self._json(T.list_conversations_cached(
                        T.load_config()))
                if path == "/api/preview":
                    cid = query.get("cid", [""])[0]
                    account = query.get("account", [""])[0]
                    cfg = T.load_config()
                    acc = next((a for a in cfg["accounts"] if a["id"] == account), None)
                    if acc is None:
                        raise RuntimeError(f"账号 {account} 不在配置中")
                    return self._json(T.preview_messages(cfg, acc, cid, 20))
                if path == "/api/messages":
                    _m0 = time.perf_counter()
                    cid = query.get("cid", [""])[0]
                    account = query.get("account", [""])[0]
                    range_key = query.get("range", ["all"])[0]
                    start = query.get("start", [""])[0]
                    end = query.get("end", [""])[0]
                    cfg = T.load_config()
                    acc = next((a for a in cfg["accounts"] if a["id"] == account), None)
                    if acc is None:
                        raise RuntimeError(f"账号 {account} 不在配置中")
                    result = T.messages_window(
                        cfg, acc, cid, range_key, start, end, allow_stale=True)
                    if time.perf_counter() - _m0 > 1:
                        log(f"[msg-http] 慢请求 {cid} {time.perf_counter()-_m0:.2f}s")
                    return self._json(result)
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
                    return self._json({"task_id": start_task(
                        task_codex_refresh, project_id=body.get("id") or "")})
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
                if path == "/api/codex/add-scope":
                    return self._json(T.codex_add_scope(
                        body.get("project_id") or body.get("id") or "",
                        body.get("account") or "",
                        body.get("cid") or "",
                        name=body.get("name") or "",
                        range_key=body.get("range") or "7d",
                        start=body.get("start"),
                        end=body.get("end"),
                    ))
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
                    # 全部耗时任务异步化：HTTP <0.1s 返回 task_id
                    return self._json({"task_id": start_task(task_refresh)})
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
    """3 秒心跳：后台非阻塞让路 + 独立 watchdog 自检，异常绝不静默假死。"""
    log(f"[codex] 实时在办目录监控已启动（{T.CODEX_INTERVAL_SECONDS}s 水印检查）")

    def watchdog():
        while True:
            time.sleep(15)
            gap = time.time() - T._CODEX_LAST_TICK["at"]
            if gap > 30:
                log(f"[codex][watchdog] 心跳停滞 {gap:.0f}s，清冷却并记录告警")
                T._CODEX_PENDING_COOLDOWN.clear()
                T._CODEX_LAST_TICK["at"] = time.time()

    threading.Thread(target=watchdog, daemon=True).start()
    while True:
        try:
            outcome = T.codex_tick(background=True)
            if outcome.get("refreshed"):
                log(f"[codex] 增量刷新 {len(outcome['refreshed'])} 个项目"
                    f"，精准跳过 {len(outcome.get('skipped') or [])} 个")
            elif outcome.get("skipped_reason"):
                log(f"[codex] {outcome['skipped_reason']}")
        except T.BusySkip as exc:
            log(f"[codex] {exc}")
        except Exception as exc:
            log(f"[codex] tick 异常：{type(exc).__name__}: {exc}")
            T._CODEX_PENDING_COOLDOWN.clear()
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
                    if os.environ.get("WECOM_NO_BROWSER") != "1":
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
    # 启动时补一次派生库索引：30 万行消息表没有会话索引会全表扫 1~80 秒
    try:
        _cfg_boot = T.load_config()
        for _acc in _cfg_boot.get("accounts") or []:
            T._ensure_message_index(_acc, _cfg_boot)
    except Exception as exc:
        log(f"[db] 消息表索引预热失败（不影响启动）：{exc}")
    # 启动时同步预热 7 个正式项目会话的消息快照（约 12 秒），
    # 服务开始监听后首次打开/复测就是完整数据，不再出现 pending 空窗。
    try:
        _warm_t0 = time.perf_counter()
        _seen = set()
        for _project in _cfg_boot.get("codex_projects") or []:
            if _project.get("status") != "running":
                continue
            for _entry in T._codex_scope_entries(_project.get("scope")):
                _aid, _cid = str(_entry.get("account") or ""), str(_entry.get("cid") or "")
                if (_aid, _cid) in _seen or not _cid:
                    continue
                _seen.add((_aid, _cid))
                _acc = T._find_acc(_cfg_boot, _aid)
                if _acc:
                    T._message_index(_cfg_boot, _acc, _cid, allow_stale=False)
        log(f"[msg-index] 启动预热 {len(_seen)} 个会话完成"
            f"（{time.perf_counter() - _warm_t0:.1f}s）")
    except Exception as exc:
        log(f"[msg-index] 启动预热跳过：{exc}")
    # 启动时补齐/核对各在办项目的 000_状态看板.md 与两个根目录的 000_全部单子总览.md（内容不变不写盘）
    try:
        _dash_res = T.refresh_codex_dashboards(T.load_config())
        log(f"[dashboard] 启动核对完成：看板更新 {len(_dash_res.get('boards_updated') or [])} 个 / "
            f"总览更新 {len(_dash_res.get('overviews_updated') or [])} 个")
    except Exception as exc:
        log(f"[dashboard] 启动核对跳过：{exc}")
    # 顶部状态预热 + 后台 2 秒刷新：/api/status 永远是毫秒级内存命中
    try:
        _STATUS_CACHE.update({"at": time.time(),
                              "data": T.account_status(T.load_config())})
    except Exception as exc:
        log(f"[status] 首次快照失败：{exc}")
    for _ in range(4):
        threading.Thread(target=task_worker, daemon=True).start()
    threading.Thread(target=task_watchdog, daemon=True).start()
    threading.Thread(target=status_refresher, daemon=True).start()
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
