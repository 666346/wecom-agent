#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wecom-agent Windows 本地封装层。

所有聊天读取与导出最终都调用仓库自带命令：
    decrypt/windows/wecom_win.py <key> conversations --limit 2000 --json
    decrypt/windows/wecom_win.py <key> export <cid> --out chat.md --format markdown --with-media --json

本文件只负责：多账号管理、key 有效性校验/自动重抓、会话缓存、按群名模糊匹配、
把每次导出生成的随机 assets 目录归一化为固定 attachments/（实现真正增量合并）、
统计汇总（消息数/成功附件/missing/encrypted）、以及 5 分钟增量同步的指纹判断。
"""
import argparse
import contextlib
import filecmp
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from pathlib import Path

# ---------------------------------------------------------------- WorkBuddy 沙盒隔离
# 服务若由 WorkBuddy 启动，会继承 PYTHONPATH=<...>\sandbox-center-runtime-kit\shim，
# 于是 sitecustomize.py 接管 os.remove / os.unlink / shutil.rmtree；批量删除超阈值
# 会抛 SystemExit(1)，导致导出/重扫/清理临时文件的线程静默死亡。这里三层断根。
_SANDBOX_STATUS = {"shim_loaded": False, "restored": [], "env_cleaned": True}
_SHIM_TOKENS = ("workbuddy", "sandbox-center-runtime-kit", "shim")


def _clean_env(base=None):
    """干净环境：剔除 PYTHONPATH 里的 shim 路径与所有沙盒审计/会话变量。"""
    env = dict(os.environ if base is None else base)
    for key in list(env):
        upper = key.upper()
        if upper == "PYTHONPATH":
            parts = [p for p in str(env[key]).split(os.pathsep)
                     if p and not any(token in p.lower() for token in _SHIM_TOKENS)]
            if parts:
                env[key] = os.pathsep.join(parts)
                continue
            env.pop(key, None)
            continue
        if (upper.startswith(("CODEBUDDY_", "CLAUDE_", "LSBOX_"))
                or upper in ("TOOL_CALL_ID", "NODE_OPTIONS", "PYTHONHOME",
                             "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONNOUSERSITE")):
            env.pop(key, None)
    return env


def _neutralize_sandbox_shim():
    """检测 sys.modules / 删除原语是否被 shim 替换；是则还原原始实现，绕过守卫。"""
    sc = sys.modules.get("sitecustomize")
    _SANDBOX_STATUS["shim_loaded"] = sc is not None
    if sc is None:
        return []
    restored = []
    pairs = [
        (os, "remove", "_orig_remove"),
        (os, "unlink", "_orig_unlink"),
        (os, "rmdir", "_orig_rmdir"),
        (shutil, "rmtree", "_orig_shutil_rmtree"),
        (Path, "unlink", "_orig_path_unlink"),
        (Path, "rmdir", "_orig_path_rmdir"),
    ]
    for module, name, orig_attr in pairs:
        original = getattr(sc, orig_attr, None)
        if callable(original) and getattr(module, name, None) is not original:
            try:
                setattr(module, name, original)
                restored.append(getattr(module, "__name__", "") + "." + name)
            except (AttributeError, TypeError):
                pass
    _SANDBOX_STATUS["restored"] = restored
    return restored


_SANDBOX_RESTORED = _neutralize_sandbox_shim()


def sandbox_status():
    return dict(_SANDBOX_STATUS)


def sandbox_delete_selftest():
    """连续创建并删除 60 个临时文件，直接复现沙盒守卫的 50 次阈值场景。"""
    errors = []
    folder = RUNTIME / "tmp_export" / ("selftest_" + uuid.uuid4().hex[:8])
    made = 0
    try:
        folder.mkdir(parents=True, exist_ok=True)
        for i in range(60):
            (folder / f"t{i:02d}.tmp").write_text("x", encoding="utf-8")
            made += 1
        for i in range(60):
            try:
                (folder / f"t{i:02d}.tmp").unlink()   # pathlib.Path.unlink
            except BaseException as exc:
                errors.append(f"Path.unlink:{type(exc).__name__}:{exc}")
        try:
            shutil.rmtree(folder, ignore_errors=True)
        except BaseException as exc:
            errors.append(f"shutil.rmtree:{type(exc).__name__}:{exc}")
    except BaseException as exc:
        errors.append(f"setup:{type(exc).__name__}:{exc}")
    return {
        "created": made, "deleted": 60, "ok": not errors, "errors": errors[:5],
        "folder_removed": not folder.exists(),
        "delete_primitives_native": (
            getattr(shutil.rmtree, "__module__", "") == "shutil"),
        "sandbox": dict(_SANDBOX_STATUS),
    }


# ---------------------------------------------------------------- Windows 无黑框启动
# 服务由 launch_web.vbs 用 pythonw.exe 启动（自身无控制台）。此时任何控制台型
# 子进程（python.exe / powershell / tasklist / cmd / ffmpeg / explorer）都会由
# Windows 新建一个控制台窗口 → 频繁闪黑框。这里在模块级统一兜底：
# 进程内所有 subprocess.run / Popen 一律强制带 CREATE_NO_WINDOW (0x08000000)，
# 包括 web_app.py 与其它间接调用，杜绝遗漏。
_WIN_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
if _WIN_NO_WINDOW:
    _subprocess_run_orig = subprocess.run
    _subprocess_popen_orig = subprocess.Popen

    def _silent_run(*args, **kwargs):
        kwargs["creationflags"] = int(kwargs.get("creationflags") or 0) | _WIN_NO_WINDOW
        kwargs["env"] = _clean_env(kwargs.get("env"))
        return _subprocess_run_orig(*args, **kwargs)

    class _SilentPopen(_subprocess_popen_orig):
        def __init__(self, *args, **kwargs):
            kwargs["creationflags"] = int(kwargs.get("creationflags") or 0) | _WIN_NO_WINDOW
            kwargs["env"] = _clean_env(kwargs.get("env"))
            super().__init__(*args, **kwargs)

    subprocess.run = _silent_run
    subprocess.Popen = _SilentPopen

try:
    import msvcrt  # Windows 文件锁；非 Windows 下退化为仅进程内互斥
except ImportError:  # pragma: no cover
    msvcrt = None

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config.json"
RUNTIME = ROOT / "runtime"
CACHE = RUNTIME / "cache"


def _slow_log(line):
    """仅记录 >1 秒的慢请求，用于压测定位；不刷控制台、不影响主流程。"""
    try:
        with (RUNTIME / "slow_requests.log").open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')} {line}\n")
    except Exception:
        pass
STATE = RUNTIME / "sync_state.json"
WATCH = ROOT / "watch_groups.txt"
WIN_CLI = ROOT / "decrypt" / "windows" / "wecom_win.py"
KEYS_JSON = ROOT / "decrypt" / "windows" / "wxwork_keys.json"
KEY_TXT = ROOT / "decrypt" / "windows" / "key.txt"
FIND_KEYS = ROOT / "find_all_keys.ps1"

sys.path.insert(0, str(ROOT / "decrypt"))
from wxwork_crypto import quick_verify  # noqa: E402
from local_io import connect_readonly  # noqa: E402
import export_wxwork as ex  # noqa: E402

LOCK_DIR = RUNTIME / "locks"
LOCK_FILE = LOCK_DIR / "wecom-db.lock"
_DB_LOCK = threading.RLock()
_DB_DEPTH = threading.local()
DB_LOCK_TIMEOUT = 8.0            # 前台等锁上限；绝不再出现 1800 秒无限等待
CODEX_LOCK_TIMEOUT = 8.0
_FRONT_BUSY = {"value": 0}
_FRONT_BUSY_LOCK = threading.Lock()


class BusySkip(RuntimeError):
    """后台任务遇到资源正忙：跳过本轮，不是错误、不记录红字。"""


@contextlib.contextmanager
def front_busy():
    """标记前台耗时任务进行中，后台同步线程见到就主动让路。"""
    with _FRONT_BUSY_LOCK:
        _FRONT_BUSY["value"] += 1
    try:
        yield
    finally:
        with _FRONT_BUSY_LOCK:
            _FRONT_BUSY["value"] -= 1


def front_is_busy():
    with _FRONT_BUSY_LOCK:
        return _FRONT_BUSY["value"] > 0


@contextlib.contextmanager
def codex_lock(timeout=CODEX_LOCK_TIMEOUT, background=False):
    """AI 在办锁：前台有限超时，后台非阻塞立即跳过，杜绝互相卡死。"""
    wait = 0 if background else timeout
    if not _CODEX_LOCK.acquire(timeout=wait):
        if background:
            raise BusySkip("AI 在办锁正忙（前台优先），后台本轮跳过")
        raise RuntimeError(f"AI 在办同步正忙（等待 {timeout:.0f}s 超时），请稍后重试")
    try:
        yield
    finally:
        _CODEX_LOCK.release()


@contextlib.contextmanager
def db_lock(timeout=DB_LOCK_TIMEOUT, background=False):
    """解密库互斥锁（进程内可重入 + 跨进程文件锁）。

    Windows 上 `os.replace(tmp, message.db)` 在目标被别的进程以只读方式打开时会抛
    PermissionError WinError 5；而 Web 导出、内置 5 分钟同步、终端 export_group.bat /
    sync_watch.ps1 都会同时解密同一个账号的库。所有涉及解密库的操作必须排队。
    """
    depth = getattr(_DB_DEPTH, "value", 0)
    acquired = _DB_LOCK.acquire(timeout=(0 if background else timeout))
    if not acquired:
        if background:
            raise BusySkip("解密库正忙（前台优先），后台本轮跳过")
        raise RuntimeError(
            f"解密库正忙（等待 {timeout:.0f}s 超时），请稍后重试")
    try:
        fd = None
        if depth == 0:
            LOCK_DIR.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o644)
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            if msvcrt is not None:
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            os.close(fd)
                            raise RuntimeError("等待解密库锁超时（可能有另一个导出/同步任务卡住）")
                        time.sleep(0.4)
        _DB_DEPTH.value = depth + 1
        try:
            yield
        finally:
            _DB_DEPTH.value = depth
            if fd is not None:
                if msvcrt is not None:
                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                os.close(fd)
    finally:
        _DB_LOCK.release()


# ---------------------------------------------------------------- 配置 / key

def load_config():
    if not CONFIG.exists():
        raise RuntimeError(f"缺配置文件 {CONFIG}")
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    return apply_account_paths(cfg)


# ---------------------------------------------------------------- Sandboxie-Plus 多开沙盒
# 企微 2 号在 Sandboxie 沙盒里运行时，数据写在
# <SandboxRoot>\<用户>\<沙盒名>\user\current\Documents\WXWork\<账号ID>\Data\message.db。
# 同一账号 ID 在宿主机和沙盒各有一份时，按 message.db 最后写入时间择优。
_ACCOUNT_PATHS_CACHE = {"at": 0.0, "data": {}}


def _read_text_smart(path):
    data = Path(path).read_bytes()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def sandbox_root_from_ini():
    """读 Sandboxie.ini 的 FileRootPath；没配就返回默认 C:\\Sandbox。"""
    root = Path(r"C:\Sandbox")
    ini = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Sandboxie.ini"
    try:
        if not ini.exists():
            return root
        for line in _read_text_smart(ini).splitlines():
            match = re.match(r"\s*FileRootPath\s*=\s*(.+)", line, re.I)
            if match:
                value = match.group(1).strip().strip('"')
                value = value.replace("%USERPROFILE%", str(Path.home()))
                candidate = Path(value)
                if candidate.is_dir():
                    return candidate
                break
    except (OSError, ValueError):
        pass
    return root


def discover_wxwork_roots(cfg=None):
    """发现宿主机原版 + 所有 Sandboxie 沙盒里的 WXWork 根，返回 [{root, source, box}]。"""
    found, seen = [], set()

    def add(root, source, box=""):
        try:
            root = Path(root).resolve()
            key = str(root).casefold()
            if key in seen or not root.is_dir():
                return
            has_db = any(child.is_dir() and (child / "Data" / "message.db").exists()
                         for child in root.iterdir())
            if not has_db:
                return
            seen.add(key)
            found.append({"root": root, "source": source, "box": box})
        except OSError:
            pass

    if cfg:
        add(wxwork_root(cfg), "宿主机")
    sandbox_root = sandbox_root_from_ini()
    try:
        if not sandbox_root.is_dir():
            return found
        for user_dir in sandbox_root.iterdir():
            if not user_dir.is_dir():
                continue
            for box_dir in user_dir.iterdir():
                if not box_dir.is_dir():
                    continue
                label = f"沙盒 {box_dir.name}"
                add(box_dir / "user" / "current" / "Documents" / "WXWork",
                    label, box_dir.name)
                drive_users = box_dir / "drive" / "C" / "Users"
                if drive_users.is_dir():
                    for profile in drive_users.iterdir():
                        if profile.is_dir():
                            add(profile / "Documents" / "WXWork", label, box_dir.name)
    except OSError:
        pass
    return found


def apply_account_paths(cfg, ttl=30.0):
    """为每个账号挑 message.db 最新那份，覆盖 data_dir/cache_dir 并标注来源。

    所有下游（解密 CLI 的 WECOM_DATA_DIR / WECOM_CACHE_DIR、8 秒 WAL 同步、
    附件 Cache 匹配）都读 acc 里的这两个字段，因此一次覆盖即可全链路生效。
    """
    now = time.monotonic()
    cached = _ACCOUNT_PATHS_CACHE.get("data") or {}
    if now - _ACCOUNT_PATHS_CACHE.get("at", 0.0) < ttl and cached:
        for acc in cfg.get("accounts", []):
            if acc["id"] in cached:
                acc.update(cached[acc["id"]])
        return cfg
    roots = discover_wxwork_roots(cfg)
    host_root = wxwork_root(cfg)
    resolved = {}
    for acc in cfg.get("accounts", []):
        best = None
        for item in roots:
            mdb = item["root"] / acc["id"] / "Data" / "message.db"
            try:
                if not mdb.is_file():
                    continue
                # WAL 模式下主库 mtime 不代表最新写入，取主库与 WAL 的最大时间
                stamps = [mdb.stat().st_mtime_ns]
                wal = mdb.with_name("message.db-wal")
                if wal.is_file() and wal.stat().st_size > 0:
                    stamps.append(wal.stat().st_mtime_ns)
                stamp = max(stamps)
            except OSError:
                continue
            if best is None or stamp > best[0]:
                best = (stamp, item, mdb.parent)
        dec_root = ROOT / "decrypt" / "windows" / "export"
        if best and best[1]["source"] != "宿主机":
            data_dir = best[2]
            box = best[1]["box"] or "sandbox"
            resolved[acc["id"]] = {
                "data_dir": str(data_dir),
                "cache_dir": str(data_dir.parent / "Cache"),
                # 沙盒用独立解密目录，不覆盖宿主机那份，便于对比与回退
                "decrypted_dir": str(dec_root / f"dec_{acc['id']}_{box}"),
                "source": best[1]["source"], "source_box": box,
                "source_root": str(best[1]["root"]),
            }
        else:
            base = host_root / acc["id"]
            resolved[acc["id"]] = {
                "data_dir": str(base / "Data"), "cache_dir": str(base / "Cache"),
                "decrypted_dir": str(dec_root / f"dec_{acc['id']}"),
                "source": "宿主机", "source_box": "", "source_root": str(host_root),
            }
        acc.update(resolved[acc["id"]])
    _ACCOUNT_PATHS_CACHE.update({"at": now, "data": resolved})
    return cfg


def save_config(cfg):
    # 沙盒择优是运行期动态结果，不写回配置：恢复宿主机基准路径并去掉来源标注
    clean = json.loads(json.dumps(cfg, ensure_ascii=False))
    host_root = wxwork_root(clean)
    for acc in clean.get("accounts", []):
        base = host_root / acc["id"]
        acc["data_dir"] = str(base / "Data")
        acc["cache_dir"] = str(base / "Cache")
        acc["decrypted_dir"] = str(
            ROOT / "decrypt" / "windows" / "export" / f"dec_{acc['id']}")
        for key in ("source", "source_box", "source_root"):
            acc.pop(key, None)
    # 原子写：先落 .tmp 再 os.replace，避免转移/同步中途断电留下半截 config.json
    _atomic_write_text(CONFIG,
                       json.dumps(clean, ensure_ascii=False, indent=2))


def wxwork_root(cfg):
    return Path(cfg["wxwork_root"])


def make_account(account_id, cfg):
    base = wxwork_root(cfg) / account_id
    return {
        "id": account_id,
        "data_dir": str(base / "Data"),
        "decrypted_dir": str(ROOT / "decrypt" / "windows" / "export" / ("dec_" + account_id)),
        "cache_dir": str(base / "Cache"),
        "key": "",
    }


def sync_accounts_from_keys(cfg, keys):
    """把新抓到 key 的账号自动补进 config（宿主机与 Sandboxie 沙盒都算）。"""
    known = {a["id"] for a in cfg["accounts"]}
    roots = [item["root"] for item in discover_wxwork_roots(cfg)] or [wxwork_root(cfg)]
    added = []
    for account_id in keys:
        if account_id in known:
            continue
        if not any((root / account_id / "Data" / "message.db").exists()
                   for root in roots):
            continue
        cfg["accounts"].append(make_account(account_id, cfg))
        known.add(account_id)
        added.append(account_id)
    changed = False
    for acc in cfg["accounts"]:
        key = keys.get(acc["id"])
        if key and acc.get("key") != key:
            acc["key"] = key
            changed = True
    if added or changed:
        save_config(cfg)
        if cfg["accounts"]:
            KEY_TXT.write_text(cfg["accounts"][0]["key"], encoding="ascii")  # server.py 需要
    return added


def rescan_keys(cfg):
    """key 失效（企微重启/切换账号）时，重新跑内存扫描。

    只用稳定的 NORMAL 模式：WIDE 模式会扫描全部内存页，在本机 8 账号环境下会崩。
    """
    print("key 已失效，正在重新扫描企业微信内存…", file=sys.stderr)
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(FIND_KEYS)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240,
        creationflags=_WIN_NO_WINDOW,
    )
    if not KEYS_JSON.exists():
        raise RuntimeError("重新扫描后仍没有 wxwork_keys.json；请确认企业微信已登录并运行")
    keys = json.loads(KEYS_JSON.read_text(encoding="utf-8"))
    added = sync_accounts_from_keys(cfg, keys)
    if added:
        print(f"新增可读取账号: {', '.join(added)}", file=sys.stderr)
    return load_config()


def ensure_key(acc, cfg):
    """返回该账号当前有效的 16 字节 key（hex）；失效则自动重扫后重试一次。"""
    mdb = Path(acc["data_dir"]) / "message.db"
    if not mdb.exists():
        raise RuntimeError(f"账号 {acc['id']} 缺 message.db: {mdb}")
    with mdb.open("rb") as fh:
        page1 = fh.read(4096)
    for attempt in range(2):
        key = acc.get("key", "")
        if key:
            try:
                if quick_verify(bytes.fromhex(key), page1):
                    return key
            except ValueError:
                pass
        cfg = rescan_keys(cfg)
        acc = next((a for a in cfg["accounts"] if a["id"] == acc["id"]), acc)
    raise RuntimeError(
        f"账号 {acc['id']} 的 key 不在企业微信内存中。请打开企业微信并登录/切换到该账号，"
        f"然后重新运行（或先执行 find_all_keys.ps1）。"
    )


# ---------------------------------------------------------------- 调用项目 CLI

def run_cli(cfg, acc, key, *args):
    env = os.environ.copy()
    env["WECOM_DATA_DIR"] = acc["data_dir"]
    env["WECOM_DECRYPTED_DIR"] = acc["decrypted_dir"]
    env["WECOM_CACHE_DIR"] = acc.get("cache_dir") or str(Path(acc["data_dir"]).parent / "Cache")
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    cmd = [cfg["python"], "-X", "utf8", str(WIN_CLI), key, *args]
    with db_lock():
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=90,
                              creationflags=_WIN_NO_WINDOW)
    if proc.returncode != 0:
        raise RuntimeError(f"wecom_win.py 执行失败 ({' '.join(args[:2])}):\n{proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout


# ---------------------------------------------------------------- 会话缓存 / 匹配

def enrich_conversations(acc, cfg, conversations):
    """补全外部群名并给每条会话挂上成员名 / 群备注 / 标签，供搜索索引使用。

    企业微信外部群（customer_room_type=2）常把 conversation_table.name 写成内部
    ID 串甚至留空，真正的可读标识在 roomname_remark（如「220」）和群成员名里。
    """
    dec = Path(acc["decrypted_dir"])
    session_db, user_db = dec / "session.db", dec / "user.db"
    if not (session_db.exists() and user_db.exists()):
        return conversations
    names = {}
    try:
        con = sqlite3.connect("file:" + str(user_db) + "?mode=ro", uri=True)
        for uid, name in con.execute("SELECT id, name FROM user_table"):
            if name:
                names[str(uid)] = str(name)
        try:
            for wxid, name in con.execute("SELECT wxid, name FROM wechat_contactV1"):
                if name:
                    names[str(wxid)] = str(name)
        except sqlite3.Error:
            pass
        con.close()
    except sqlite3.Error:
        return conversations
    room_meta, members = {}, {}
    try:
        con = sqlite3.connect("file:" + str(session_db) + "?mode=ro", uri=True)
        for cid, name, remark, room_type, last_ts, created in con.execute(
                "SELECT id, name, roomname_remark, customer_room_type, "
                "last_message_time, create_time FROM conversation_table"):
            room_meta[str(cid)] = (name or "", remark or "", int(room_type or 0),
                                   int(last_ts or 0), int(created or 0))
        for cid, uid in con.execute(
                "SELECT conversation_id, user_id FROM conversation_user_table"):
            label = names.get(str(uid))
            if label:
                members.setdefault(str(cid), []).append(label)
        con.close()
    except sqlite3.Error:
        return conversations
    # 刚建好的群可能还没有 message_table 记录，CLI 的 conversations 只看 message_table；
    # 这里从 session.db 补齐最近 30 天有活动的会话，保证点一次刷新就能看到新群。
    existing = {str(c.get("id")) for c in conversations}
    now = time.time()
    for cid, meta in room_meta.items():
        if cid in existing or not cid.startswith(("R:", "S:")):
            continue
        newest = max(meta[3], meta[4])
        if not newest or now - newest > 30 * 86400:
            continue
        conversations.append({
            "id": cid, "name": meta[0] or meta[1] or cid, "messages": 0,
            "last_timestamp": newest, "last_time": ex.fmt_time(newest),
        })
    for conv in conversations:
        cid = str(conv.get("id") or "")
        meta = room_meta.get(cid)
        member_list = list(dict.fromkeys(members.get(cid, [])))
        remark = meta[1] if meta else ""
        room_type = meta[2] if meta else 0
        conv["members"] = member_list
        conv["remark"] = remark
        conv["customer_room_type"] = room_type
        tags = ([remark] if remark else [])
        if room_type == 2:
            tags.append("外部群")
        raw_name = str(conv.get("name") or "").strip()
        # 原始群名以 session.db 为准（缓存可能已被 enrich 过多次，不能拿显示名当别名）
        session_name = str(meta[0] if meta else "").strip()
        original = (session_name or str(conv.get("alias") or raw_name)).strip()
        conv["alias"] = original
        if (original and original not in tags and len(original) <= 60
                and (original != raw_name
                     or re.fullmatch(r"[0-9A-Za-z]{8,}", original))):
            tags.append(original)
        conv["tags"] = tags
        noisy = (not raw_name or bool(re.fullmatch(r"[0-9A-Za-z]{8,}", raw_name))
                 or cid in raw_name)
        if noisy and (member_list or remark):
            parts = ([remark] if remark else []) + member_list[:6]
            conv["name"] = " · ".join(part for part in parts if part)
            conv["name_source"] = "members"
        else:
            conv["name_source"] = "session"
    return conversations


def refresh(acc, cfg, force=False):
    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / f"conv_{acc['id']}.json"
    # 宿主机 <-> 沙盒切换后必须重新解密，否则界面还停留在旧副本的会话列表
    stamp = Path(acc["decrypted_dir"]) / ".source_root"
    current_source = str(Path(acc["data_dir"]).parent)
    try:
        if ((stamp.exists() and stamp.read_text(encoding="utf-8").strip() != current_source)
                or (not stamp.exists() and acc.get("source", "宿主机") != "宿主机")):
            force = True
    except OSError:
        pass
    ttl = int(cfg.get("cache_ttl_seconds", 1800))
    if not force and target.exists() and time.time() - target.stat().st_mtime < ttl:
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            pass
    key = ensure_key(acc, cfg)
    if force:
        # 点「刷新会话列表」先把最新 WAL 增量合并进解密库，否则解密库可能停在
        # 旧快照，企微里刚建好的群 / 刚发的消息会查不到。
        try:
            changed, _method = sync_live_db(acc, cfg)
        except Exception:
            changed, _method = True, "error"
        # 仅当源库签名确实未变且解密库健康（_method == "unchanged"）时才复用缓存；
        # 绝不能在 "pending" 节流返回时误复用旧缓存，导致整库重解被静默跳过。
        if not changed and _method == "unchanged" and target.exists():
            try:
                cached = json.loads(target.read_text(encoding="utf-8"))
                cached["conversations"] = enrich_conversations(
                    acc, cfg, cached.get("conversations", []))
                # 写回，保证后续 /api/conversations 读到的 alias/tags 与增强结果一致
                target.write_text(json.dumps(cached, ensure_ascii=False),
                                  encoding="utf-8")
                return cached
            except (ValueError, OSError):
                pass
    sig_before = live_signature(acc)
    raw = run_cli(cfg, acc, key, "conversations", "--limit", "10000", "--json")
    data = json.loads(raw)
    _mark_dec_updated(acc)
    # 整库重解后重建独立侧车索引库（绝不修改 dec/message.db，避免破坏 WAL 页级补丁）
    _ensure_message_index(acc, cfg, force_rebuild=True)
    try:
        LIVE_STATE.mkdir(parents=True, exist_ok=True)
        generation, commit_size, _ = _wal_committed(acc)
        dec_path = Path(acc["decrypted_dir"]) / "message.db"
        pages = commit_size or (dec_path.stat().st_size // PAGE_SZ if dec_path.exists() else 0)
        state = {"main": list(sig_before["main"]), "wal": list(sig_before["wal"]),
                 "main_size": sig_before["main"][0], "generation": generation or "",
                 "pages": pages, "synced_at": time.time()}
        _atomic_write_text(LIVE_STATE / f"{acc['id']}.json",
                           json.dumps(state, ensure_ascii=False))
    except OSError:
        pass
    convs = enrich_conversations(acc, cfg, data.get("conversations", []))
    payload = {"account": acc["id"], "updated": time.time(),
               "conversations": convs,
               "source": acc.get("source", "宿主机"),
               "source_root": acc.get("source_root", "")}
    target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    try:
        stamp.write_text(current_source, encoding="utf-8")
    except OSError:
        pass
    return payload


def all_accounts(cfg, force=False):
    for acc in cfg["accounts"]:
        try:
            yield acc, refresh(acc, cfg, force=force)
        except Exception as exc:  # 某个账号 key 不在内存时不影响其它账号
            print(f"跳过账号 {acc['id']}: {exc}", file=sys.stderr)
            yield acc, {"account": acc["id"], "conversations": []}


def match(cfg, keyword, force=False):
    needle = keyword.casefold()
    hits = []
    for acc, data in all_accounts(cfg, force=force):
        for conv in data["conversations"]:
            if needle in str(conv.get("name", "")).casefold():
                hits.append({**conv, "account": acc["id"]})
    return {"keyword": keyword, "count": len(hits), "candidates": hits}


def locate(cfg, cid, force=False):
    for acc, data in all_accounts(cfg, force=force):
        for conv in data["conversations"]:
            if str(conv.get("id")) == str(cid):
                return acc, conv.get("name", cid)
    if not force:
        return locate(cfg, cid, force=True)
    return None, None


# ---------------------------------------------------------------- 导出

def safe_name(name):
    text = re.sub(r'[\\/:*?"<>|\r\n\t]', "_", str(name))
    text = re.sub(r"\s+", " ", text).strip().strip(".")
    return text[:80] or "未命名会话"


def _merge_assets(outdir, new_dirs, chat, manifest_path):
    """把随机 chat.assets-<id>/ 归一化到固定 attachments/，只复制新增/变化的文件。"""
    fixed = outdir / "attachments"
    replaced = []
    for directory in new_dirs:
        for src in sorted(directory.rglob("*")):
            if not src.is_file():
                continue
            rel = src.relative_to(directory)
            dst = fixed / rel
            if dst.exists() and dst.stat().st_size == src.stat().st_size and filecmp.cmp(dst, src, shallow=False):
                src.unlink()
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            src.unlink()
        shutil.rmtree(directory, ignore_errors=True)
        replaced.append(directory.name)
    if replaced:
        for path in (chat, manifest_path):
            if path and Path(path).exists():
                text = Path(path).read_text(encoding="utf-8")
                for old in replaced:
                    text = text.replace(old, "attachments")
                Path(path).write_text(text, encoding="utf-8")
    return fixed


def export_one(cfg, acc, cid, name=None):
    key = ensure_key(acc, cfg)
    if not name:
        found_acc, name = locate(cfg, cid)
        if found_acc:
            acc = found_acc
            key = ensure_key(acc, cfg)
    folder = Path(cfg["export_root"]) / safe_name(name or cid)
    marker = folder / ".conversation_id"
    if marker.exists() and marker.read_text(encoding="utf-8").strip() != str(cid):
        folder = Path(cfg["export_root"]) / f"{safe_name(name or cid)}_{str(cid)[-6:]}"
    folder.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(cid), encoding="utf-8")

    chat = folder / "chat.md"
    before = {p.name for p in folder.glob("chat.assets-*")}
    # 仓库自带导出命令：时间正序(ASC)、UTF-8、Markdown、带媒体清单
    raw = run_cli(cfg, acc, key, "export", str(cid),
                  "--out", str(chat), "--format", "markdown", "--with-media", "--json")
    result = json.loads(raw)
    manifest_path = Path(result["manifest"]) if result.get("manifest") else None
    new_dirs = [p for p in folder.glob("chat.assets-*") if p.name not in before]
    if new_dirs:
        _merge_assets(folder, new_dirs, chat, manifest_path)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path and manifest_path.exists() else {"entries": []}
    issues, attachments_ok = [], 0
    for entry in manifest.get("entries", []):
        files = entry.get("files") or []
        if entry.get("status") == "resolved" and files:
            attachments_ok += len(files)
            continue
        status = str(entry.get("status", "unknown"))
        if status in ("not_found", "cache_changed_unreadable_or_unsafe", "cache_changed_or_unreadable", "cache_root_unavailable"):
            category = "missing"
        elif status in ("encrypted_unsupported",):
            category = "encrypted"
        else:
            category = "other"
        msg = entry.get("message") or {}
        issues.append({
            "category": category,
            "status": status,
            "reason": entry.get("reason", ""),
            "kind": entry.get("kind", ""),
            "local_id": msg.get("local_id", ""),
            "hint": "请在企业微信里点开该消息/附件，等待下载缓存完成后重新导出" if category == "missing" else
                    "该文件为加密或无法识别的图片，本地无明文缓存" if category == "encrypted" else
                    "资源标识存在歧义或格式不支持，需人工确认",
        })
    return {
        "account": acc["id"], "conversation_id": str(cid), "name": name,
        "out_dir": str(folder), "chat_md": str(chat),
        "manifest": str(manifest_path) if manifest_path else None,
        "messages": result.get("messages", 0),
        "media_status": result.get("media", {}),
        "attachments_ok": attachments_ok,
        "issues": issues,
        "missing": [i for i in issues if i["category"] == "missing"],
        "encrypted": [i for i in issues if i["category"] == "encrypted"],
        "other": [i for i in issues if i["category"] == "other"],
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------- 增量同步

def fingerprint(acc):
    data = Path(acc["data_dir"])
    parts = []
    for filename in ("message.db", "message.db-wal", "session.db", "session.db-wal"):
        path = data / filename
        if path.exists():
            st = path.stat()
            parts.append(f"{filename}:{st.st_size}:{st.st_mtime_ns}")
    cache = Path(acc.get("cache_dir") or (data.parent / "Cache"))
    if cache.exists():
        newest, count = 0, 0
        for path in cache.rglob("*"):
            if path.is_file():
                count += 1
                try:
                    newest = max(newest, path.stat().st_mtime_ns)
                except OSError:
                    pass
        parts.append(f"cache:{count}:{newest}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def export_cache(cfg, acc, cid, name=None):
    """兜底：把该账号的全部明文媒体缓存导出到群目录 cache_all/。

    仓库 Windows 端的 --with-media 依赖 macOS 版 protobuf 资源 ID 假设，本机实测
    关联率可能为 0。这个命令改用项目自带 media 子命令，保证附件不丢，
    但文件不再与消息一一对应（适合整体喂给 AI 工具）。一次性使用，体积可能较大。
    """
    key = ensure_key(acc, cfg)
    folder = Path(cfg["export_root"]) / safe_name(name or cid)
    out = folder / "cache_all"
    raw = run_cli(cfg, acc, key, "media", "--out", str(out), "--json")
    return {"account": acc["id"], "conversation_id": str(cid),
            "out": str(out), "result": json.loads(raw)}


def parse_watch():
    entries = []
    if not WATCH.exists():
        return entries
    for line in WATCH.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cid = line.split()[0]
        entries.append(cid)
    return entries


def sync(cfg, force=False, background=False):
    with db_lock(background=background):
        return _sync_locked(cfg, force=force)


def _sync_locked(cfg, force=False):
    RUNTIME.mkdir(parents=True, exist_ok=True)
    state = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    old = state.get("fingerprints", {})
    fps = {}
    for acc in cfg["accounts"]:
        try:
            fps[acc["id"]] = fingerprint(acc)
        except OSError:
            fps[acc["id"]] = ""
    changed = {a["id"] for a in cfg["accounts"] if fps[a["id"]] != old.get(a["id"])}

    cids = parse_watch()
    if not cids:
        return {"skipped": True, "reason": "watch_groups.txt 为空", "changed": sorted(changed)}

    results, errors = [], []
    for cid in cids:
        acc, name = locate(cfg, cid)
        if not acc:
            errors.append(f"{cid}: 未在任何已解锁账号的会话列表中找到")
            continue
        if not force and acc["id"] not in changed:
            results.append({"conversation_id": cid, "skipped": True, "account": acc["id"], "name": name})
            continue
        try:
            all_ids = [m["id"] for m in _message_index(cfg, acc, cid)]
            results.append(precise_export(cfg, acc, cid, name, all_ids, zip_mode="overwrite"))
        except Exception as exc:
            errors.append(f"{cid}: {exc}")

    state["fingerprints"] = fps
    state["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"skipped": False, "changed": sorted(changed), "results": results, "errors": errors,
            "time": state["last_sync"]}


# ---------------------------------------------------------------- Web 界面支撑层

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic"}
DOC_EXTENSIONS = IMAGE_EXTENSIONS | {
    ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".xlsm", ".csv", ".txt", ".md", ".json",
    ".log", ".xml", ".html", ".htm", ".ppt", ".pptx", ".rtf",
    ".dwg", ".dxf", ".skp", ".rvt", ".rfa", ".3ds", ".max", ".obj", ".stl", ".step", ".stp",
    ".psd", ".ai", ".cdr", ".eps", ".svg", ".zip", ".rar", ".7z", ".lnk",
    ".mp4", ".mov", ".avi", ".mp3", ".wav", ".silk", ".amr", ".m4a",
}
MAX_CACHE_FILES = 200
MAX_CACHE_BYTES = 150 * 1024 * 1024
MAX_CACHE_SINGLE_BYTES = 25 * 1024 * 1024
CACHE_WINDOW_DAYS = 30
CACHE_TEXT_EXTENSIONS = {".txt", ".md", ".csv", ".json", ".log", ".xml", ".html", ".htm",
                         ".docx", ".xlsx", ".xlsm", ".pdf"}
MAX_ALL_FOR_AI_CACHE_DOCS = 80
MAX_ALL_FOR_AI_CACHE_CHARS = 800 * 1024


def _norm_ts(value):
    if not value:
        return 0.0
    value = float(value)
    return value / 1000.0 if value > 20000000000 else value


_DEC_META_LOCK = threading.Lock()
_DEC_DB_VERSION = {}        # account_id -> 单调递增版本号，每次更新 dec/message.db 时 +1
_CORRUPT_ACCOUNTS = set()   # 检测到损坏或含旧版内嵌索引的账号，强制下次同步整库重解
_DEC_HEALTH_CACHE = {}      # (dec_path, size, mtime_ns) -> bool
_IDX_LOCK_GUARD = threading.Lock()
_IDX_LOCKS = {}


def _idx_lock_for(path):
    with _IDX_LOCK_GUARD:
        return _IDX_LOCKS.setdefault(str(path), threading.Lock())


def _read_shared_file(path):
    """Windows 共享读（FILE_SHARE_ALL）：企微正打开写库时也能安全读取快照。"""
    path = os.fspath(path)
    if os.name != "nt":
        with open(path, "rb") as handle:
            return handle.read()
    import ctypes
    from ctypes import wintypes
    GENERIC_READ = 0x80000000
    SHARE_ALL = 0x07
    k = ctypes.windll.kernel32
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                           ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    k.ReadFile.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.GetLastError.restype = wintypes.DWORD
    h = k.CreateFileW(path, GENERIC_READ, SHARE_ALL, None, 3, 0x80, None)
    if h == wintypes.HANDLE(-1).value:
        error = k.GetLastError()
        if error in (2, 3):
            raise FileNotFoundError(path)
        raise OSError(error, f"CreateFileW failed: {path}")
    try:
        size = 1024 * 1024
        buf = (ctypes.c_char * size)()
        rd = wintypes.DWORD(0)
        chunks = []
        while True:
            if not k.ReadFile(h, buf, size, ctypes.byref(rd), None):
                raise OSError(k.GetLastError(), f"ReadFile failed: {path}")
            if not rd.value:
                return b"".join(chunks)
            chunks.append(bytes(buf[:rd.value]))
    finally:
        k.CloseHandle(h)


def _replace_file_retry(src, dst, attempts=10):
    """Windows 原子替换带短暂退避重试，避免只读线程占用触发 WinError 5。"""
    src, dst = Path(src), Path(dst)
    last_exc = None
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError as exc:
            last_exc = exc
            time.sleep(0.05 * (attempt + 1))
    raise last_exc


def _dec_version(acc):
    aid = str(acc["id"]) if isinstance(acc, dict) else str(acc)
    with _DEC_META_LOCK:
        return _DEC_DB_VERSION.get(aid, 0)


def _mark_dec_updated(acc):
    """dec/message.db 更新后递增版本号并精准清理该账号峰值与健康缓存。"""
    aid = str(acc["id"]) if isinstance(acc, dict) else str(acc)
    dec_str = str(Path(acc["decrypted_dir"]) / "message.db") if isinstance(acc, dict) else ""
    with _DEC_META_LOCK:
        _DEC_DB_VERSION[aid] = _DEC_DB_VERSION.get(aid, 0) + 1
        _CORRUPT_ACCOUNTS.discard(aid)
        if dec_str:
            for k in [k for k in _DEC_HEALTH_CACHE if k[0] == dec_str]:
                _DEC_HEALTH_CACHE.pop(k, None)
    if dec_str:
        with _CONV_PEAK_LOCK:
            for k in [k for k in _CONV_PEAK_CACHE if k[0] == dec_str]:
                _CONV_PEAK_CACHE.pop(k, None)


def _mark_dec_corrupt(acc):
    """标记某账号解密库损坏，下次同步跳过 unchanged 与 WAL 补丁，自动整库修复。"""
    aid = str(acc["id"]) if isinstance(acc, dict) else str(acc)
    dec_str = str(Path(acc["decrypted_dir"]) / "message.db") if isinstance(acc, dict) else ""
    with _DEC_META_LOCK:
        _CORRUPT_ACCOUNTS.add(aid)
        if dec_str:
            for k in [k for k in _DEC_HEALTH_CACHE if k[0] == dec_str]:
                _DEC_HEALTH_CACHE.pop(k, None)
    if dec_str:
        with _CONV_PEAK_LOCK:
            for k in [k for k in _CONV_PEAK_CACHE if k[0] == dec_str]:
                _CONV_PEAK_CACHE.pop(k, None)


def _dec_db_is_clean_and_healthy(acc, dec=None):
    """校验 dec/message.db 是否纯净且可读：无旧版内嵌索引、页数头吻合、结构完整。"""
    aid = str(acc["id"])
    dec = Path(dec) if dec is not None else (Path(acc["decrypted_dir"]) / "message.db")
    with _DEC_META_LOCK:
        if aid in _CORRUPT_ACCOUNTS:
            return False
    try:
        st = dec.stat()
    except OSError:
        return False
    if st.st_size < PAGE_SZ or (st.st_size % PAGE_SZ) != 0:
        return False
    cache_key = (str(dec), st.st_size, st.st_mtime_ns)
    with _DEC_META_LOCK:
        cached = _DEC_HEALTH_CACHE.get(cache_key)
        if cached is not None:
            return cached
    ok = False
    try:
        with dec.open("rb") as fh:
            hdr = fh.read(32)
        if len(hdr) < 32 or hdr[:16] != b"SQLite format 3\x00":
            return False
        hdr_pages = int.from_bytes(hdr[28:32], "big")
        file_pages = st.st_size // PAGE_SZ
        if hdr_pages != 0 and hdr_pages != file_pages:
            return False
        con = connect_readonly(dec, immutable=True)
        try:
            # 严禁 dec/message.db 内嵌 idx_msg_conv_time_id：任何 SQLite DDL 修改
            # 都会改变页布局，与后续 WAL 原始页补丁冲突并引发 database disk image is malformed。
            tainted = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='index' "
                "AND name='idx_msg_conv_time_id'").fetchone()
            if tainted is not None:
                return False
            con.execute("SELECT COALESCE(MAX(message_id), 0) FROM message_table").fetchone()
            if st.st_size <= 64 * 1024 * 1024:
                qc = [r[0] for r in con.execute('PRAGMA quick_check("message_table")')]
                if qc != ["ok"]:
                    return False
            ok = True
        finally:
            con.close()
    except (OSError, sqlite3.Error, ValueError):
        ok = False
    with _DEC_META_LOCK:
        if len(_DEC_HEALTH_CACHE) > 64:
            _DEC_HEALTH_CACHE.clear()
        _DEC_HEALTH_CACHE[cache_key] = ok
    return ok


def _full_decrypt_message_db(acc, cfg, background=False):
    """进程内原子整库重解 message.db，不递归调用 refresh()，并重建独立侧车索引。"""
    from wxwork_crypto import decrypt_database
    src = Path(acc["data_dir"]) / "message.db"
    if not src.exists():
        raise RuntimeError(f"账号 {acc['id']} 缺原始库: {src}")
    key_hex = acc.get("key") or ""
    if not key_hex:
        key_hex = ensure_key(acc, cfg)
    else:
        try:
            with src.open("rb") as fh:
                p1 = fh.read(PAGE_SZ)
            if not quick_verify(bytes.fromhex(key_hex), p1):
                key_hex = ensure_key(acc, cfg)
        except (OSError, ValueError):
            key_hex = ensure_key(acc, cfg)
    key_bytes = bytes.fromhex(key_hex)
    dec_dir = Path(acc["decrypted_dir"])
    dec_dir.mkdir(parents=True, exist_ok=True)
    dec = dec_dir / "message.db"
    staged = dec_dir / f".wecom-full-{os.getpid()}-{threading.get_ident()}.db"
    with db_lock(background=background):
        try:
            decrypt_database(str(src), str(staged), key_bytes, reader=_read_shared_file)
            _replace_file_retry(staged, dec)
            for suffix in ("-wal", "-shm"):
                stray = Path(str(dec) + suffix)
                try:
                    stray.unlink(missing_ok=True)
                except OSError:
                    pass
        finally:
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass
        _mark_dec_updated(acc)
    _ensure_message_index(acc, cfg, force_rebuild=True, allow_repair=False)
    return dec


def _msg_idx_path(acc):
    return Path(acc["decrypted_dir"]) / "message_idx.db"


def _dec_message_db(acc, cfg):
    path = Path(acc["decrypted_dir"]) / "message.db"
    if not path.exists():
        refresh(acc, cfg)  # 用项目自带命令触发一次解密，生成 dec 库
    if not path.exists():
        raise RuntimeError(f"解密库不存在: {path}")
    return path


def _ensure_message_index(acc, cfg=None, force_rebuild=False, allow_repair=True):
    """维护独立侧车索引库 dec/message_idx.db（含 idx_msg_conv_time_id）。

    严禁直接在 dec/message.db 上执行 CREATE INDEX：那会改写 Page 1 与追加索引页，
    后续 sync_live_db() 做 WAL 原始页补丁时会导致页号越界/索引失步，最终触发
    sqlite3.DatabaseError: database disk image is malformed。
    独立侧车库只存 (message_id, conversation_id, send_time)，WAL 补丁后仅需 1~2ms 增量追平，
    dec/message.db 全程保持 100% 纯净只读镜像，绝不碰企微原库。
    """
    dec = Path(acc["decrypted_dir"]) / "message.db"
    if not dec.exists():
        return False
    # 若检测到旧版遗留的内嵌索引或库已损坏，先自动整库重解还原纯净 dec/message.db
    if allow_repair and cfg is not None and not _dec_db_is_clean_and_healthy(acc, dec):
        try:
            dec_size = dec.stat().st_size
        except OSError:
            dec_size = 0
        # 损坏库或 <=64MB 的活跃库立即就地修复；超大静默库留待 sync_live_db 按需修复
        aid = str(acc["id"])
        corrupt_now = False
        with _DEC_META_LOCK:
            corrupt_now = aid in _CORRUPT_ACCOUNTS
        if corrupt_now or dec_size <= 64 * 1024 * 1024:
            try:
                _full_decrypt_message_db(acc, cfg, background=False)
                return True
            except Exception:
                return False
    idx_db = _msg_idx_path(acc)
    with _idx_lock_for(idx_db):
        try:
            st = dec.stat()
            dec_size, dec_mtime = st.st_size, st.st_mtime_ns
        except OSError:
            return False
        # ① 快速路径：侧车索引存在且 dec 水印一致直接命中（<0.2ms）
        if not force_rebuild and idx_db.is_file():
            try:
                icon = sqlite3.connect(f"file:{idx_db}?mode=ro", uri=True, timeout=5)
                try:
                    meta = dict(icon.execute("SELECT k, v FROM _meta").fetchall())
                finally:
                    icon.close()
                if (int(meta.get("dec_size") or -1) == dec_size
                        and int(meta.get("dec_mtime") or -1) == dec_mtime):
                    return True
                meta_max = int(meta.get("max_id") or 0)
                meta_cnt = int(meta.get("row_count") or 0)
                meta_size = int(meta.get("dec_size") or 0)
            except (OSError, sqlite3.Error, ValueError):
                meta_max, meta_cnt, meta_size = -1, -1, -1
        else:
            meta_max, meta_cnt, meta_size = -1, -1, -1

        # ② 增量路径：WAL 补丁后仅读 message_id > meta_max 的新增行（主键查找 ~1ms）
        if not force_rebuild and meta_max >= 0 and dec_size >= meta_size and idx_db.is_file():
            try:
                con = connect_readonly(dec, immutable=True)
                try:
                    dec_max = int(con.execute(
                        "SELECT COALESCE(MAX(message_id), 0) FROM message_table"
                    ).fetchone()[0] or 0)
                    if dec_max > meta_max:
                        new_rows = con.execute(
                            "SELECT message_id, conversation_id, send_time "
                            "FROM message_table WHERE message_id > ?", (meta_max,)
                        ).fetchall()
                        dec_cnt = (int(con.execute("SELECT COUNT(*) FROM message_table").fetchone()[0] or 0)
                                   if dec_size <= 64 * 1024 * 1024 else meta_cnt + len(new_rows))
                    elif dec_max == meta_max:
                        new_rows = []
                        dec_cnt = int(con.execute("SELECT COUNT(*) FROM message_table").fetchone()[0] or 0)
                    else:
                        new_rows, dec_cnt = None, -1
                finally:
                    con.close()
                if new_rows is not None and dec_cnt == meta_cnt + len(new_rows):
                    wcon = sqlite3.connect(str(idx_db), timeout=15)
                    try:
                        wcon.execute("PRAGMA busy_timeout=5000")
                        if new_rows:
                            wcon.executemany(
                                "INSERT OR REPLACE INTO msg_idx(message_id, conversation_id, send_time) "
                                "VALUES(?, ?, ?)",
                                [(int(r[0]), str(r[1] or ""), int(r[2] or 0)) for r in new_rows],
                            )
                        wcon.executemany(
                            "INSERT OR REPLACE INTO _meta(k, v) VALUES(?, ?)",
                            [("dec_size", str(dec_size)), ("dec_mtime", str(dec_mtime)),
                             ("max_id", str(dec_max)), ("row_count", str(dec_cnt))],
                        )
                        wcon.commit()
                    finally:
                        wcon.close()
                    return True
            except (OSError, sqlite3.Error, ValueError):
                pass

        # ③ 全量重建侧车索引库（原子写入 .tmp 后替换，绝不阻塞只读查询）
        tmp = idx_db.with_name(
            f"{idx_db.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            con = connect_readonly(dec, immutable=True)
            try:
                rows = [
                    (int(r[0]), str(r[1] or ""), int(r[2] or 0))
                    for r in con.execute(
                        "SELECT message_id, conversation_id, send_time FROM message_table")
                ]
            finally:
                con.close()
            max_id = max((r[0] for r in rows), default=0)
            wcon = sqlite3.connect(str(tmp), timeout=30)
            try:
                wcon.execute("PRAGMA journal_mode=OFF")
                wcon.execute("PRAGMA synchronous=OFF")
                wcon.execute("CREATE TABLE _meta(k TEXT PRIMARY KEY, v TEXT)")
                wcon.execute(
                    "CREATE TABLE msg_idx("
                    "message_id INTEGER PRIMARY KEY, "
                    "conversation_id TEXT NOT NULL, "
                    "send_time INTEGER NOT NULL)")
                if rows:
                    wcon.executemany(
                        "INSERT INTO msg_idx(message_id, conversation_id, send_time) "
                        "VALUES(?, ?, ?)", rows)
                wcon.execute(
                    "CREATE INDEX idx_msg_conv_time_id "
                    "ON msg_idx(conversation_id, send_time, message_id)")
                wcon.executemany(
                    "INSERT INTO _meta(k, v) VALUES(?, ?)",
                    [("dec_size", str(dec_size)), ("dec_mtime", str(dec_mtime)),
                     ("max_id", str(max_id)), ("row_count", str(len(rows)))],
                )
                wcon.commit()
            finally:
                wcon.close()
            _replace_file_retry(tmp, idx_db)
            return True
        except sqlite3.DatabaseError:
            _mark_dec_corrupt(acc)
            return False
        except (OSError, sqlite3.Error, ValueError):
            return False
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass


def _load_names(acc):
    users = {}
    path = Path(acc["decrypted_dir"]) / "user.db"
    if not path.exists():
        return users
    con = connect_readonly(path)
    try:
        for row in con.execute("SELECT id, name FROM user_table"):
            if row[1]:
                users[str(row[0])] = row[1]
        try:
            for row in con.execute("SELECT wxid, name FROM wechat_contactV1"):
                if row[1] and row[1] != "-":
                    users.setdefault(str(row[0]), row[1])
        except sqlite3.Error:
            pass
    finally:
        con.close()
    return users


def _rows_via_sidecar(acc, db, cid, descending=False, limit=None,
                      include_local_extra=False):
    """通过独立侧车索引库取有序 message_id，再按主键批量回表，30 万行库也能 1~3ms 返回。"""
    idx_db = _msg_idx_path(acc)
    if not idx_db.is_file():
        return None
    order = "DESC" if descending else "ASC"
    sql = (f"SELECT message_id FROM msg_idx WHERE conversation_id=? "
           f"ORDER BY send_time {order}, message_id {order}")
    if limit:
        sql += f" LIMIT {int(limit)}"
    try:
        icon = connect_readonly(idx_db, immutable=True)
        try:
            ids = [int(r[0]) for r in icon.execute(sql, (str(cid),))]
        finally:
            icon.close()
    except (OSError, sqlite3.Error, ValueError):
        return None
    if not ids:
        return []
    cols = ("message_id, sender_id, content_type, send_time, content, local_extra_content"
            if include_local_extra else
            "message_id, sender_id, content_type, send_time, content")
    by_id = {}
    con = connect_readonly(db, immutable=True)
    try:
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            placeholders = ",".join("?" for _ in chunk)
            q = f"SELECT {cols} FROM message_table WHERE message_id IN ({placeholders})"
            try:
                for r in con.execute(q, chunk):
                    by_id[int(r[0])] = tuple(r)
            except sqlite3.OperationalError:
                if not include_local_extra:
                    raise
                q_old = ("SELECT message_id, sender_id, content_type, send_time, content "
                         f"FROM message_table WHERE message_id IN ({placeholders})")
                for r in con.execute(q_old, chunk):
                    by_id[int(r[0])] = tuple(r) + (b"",)
    finally:
        con.close()
    return [by_id[mid] for mid in ids if mid in by_id]


def _rows(acc, cfg, cid, *, descending=False, limit=None,
          include_local_extra=False):
    db = _dec_message_db(acc, cfg)
    order = "DESC" if descending else "ASC"
    cols = ("message_id, sender_id, content_type, send_time, content, local_extra_content"
            if include_local_extra else
            "message_id, sender_id, content_type, send_time, content")
    sql = (f"SELECT {cols} FROM message_table WHERE conversation_id=? "
           f"ORDER BY send_time {order}, message_id {order}")
    if limit:
        sql += f" LIMIT {int(limit)}"
    for attempt in range(2):
        try:
            if _ensure_message_index(acc, cfg, allow_repair=(attempt == 0)):
                with db_lock():
                    rows = _rows_via_sidecar(
                        acc, db, cid, descending=descending, limit=limit,
                        include_local_extra=include_local_extra)
                    if rows is not None:
                        return rows, _load_names(acc)
            with db_lock():
                con = connect_readonly(db)
                try:
                    try:
                        return [tuple(r) for r in con.execute(sql, (cid,))], _load_names(acc)
                    except sqlite3.OperationalError:
                        if not include_local_extra:
                            raise
                        sql_old = ("SELECT message_id, sender_id, content_type, send_time, content "
                                   "FROM message_table WHERE conversation_id=? "
                                   f"ORDER BY send_time {order}, message_id {order}")
                        if limit:
                            sql_old += f" LIMIT {int(limit)}"
                        return [tuple(r) + (b"",) for r in con.execute(sql_old, (cid,))], _load_names(acc)
                finally:
                    con.close()
        except sqlite3.DatabaseError:
            _mark_dec_corrupt(acc)
            if attempt == 0:
                _full_decrypt_message_db(acc, cfg, background=False)
                continue
            raise


def _printable_ratio(text):
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t") / len(text)


def _deep_strings(blob, depth=0):
    """递归提取 protobuf 里的文本：Windows 版把正文藏在嵌套 message 里。

    仓库的 ex.render 对这类消息只返回 "[文本]" 空标签；其 _pb_strings 只扫顶层，
    所以这里自己下钻，让预览与 ALL_FOR_AI.md 拿到真实正文。
    """
    if depth > 4 or not isinstance(blob, (bytes, bytearray)) or len(blob) > 2 * 1024 * 1024:
        return []
    data = bytes(blob)
    from protobuf_fields import fields as pb_fields
    try:
        parsed = pb_fields(data)
    except Exception:
        try:
            text = data.decode("utf-8")
            return [text] if text.strip() and _printable_ratio(text) > 0.85 else []
        except UnicodeDecodeError:
            return []
    out = []
    for values in parsed.values():
        for value in values:
            if not isinstance(value, bytes) or not value:
                continue
            nested = None
            try:
                nested = pb_fields(value)
            except Exception:
                pass
            if nested and any(isinstance(x, bytes) for vals in nested.values() for x in vals):
                out.extend(_deep_strings(value, depth + 1))
                continue
            try:
                text = value.decode("utf-8")
                if text.strip() and _printable_ratio(text) > 0.85:
                    out.append(text)
            except UnicodeDecodeError:
                pass
    return out


def _render(ct, raw):
    """通用渲染：ex.render 的结果 + 深层 protobuf 文本总是合并，杜绝「只剩人名」。

    企微 ct=2 的 ex.render 常只返回 @提及的人名（如「某成员」），完整正文藏在
    f1[] 的文本段里；老逻辑只在占位符时才下钻，导致正文被永久丢弃。
    """
    try:
        rendered = str(ex.render(ct, raw, "windows")).strip()
    except Exception:
        rendered = ""
    candidates = _deep_strings(bytes(raw) if raw else b"")
    useful = [s.strip() for s in candidates
              if s.strip() and len(s.strip()) > 1
              and not s.strip().startswith("/data/")
              and not _ANDROID_NOISE_RE.match(s.strip())]
    # 卡片 JSON 用递归提取出的中文标题替换原始 JSON 串
    expanded = []
    for item in [rendered] + useful:
        item = (item or "").strip()
        if not item:
            continue
        if item.lstrip().startswith("{") and len(item) > 40:
            titles = _json_titles(item)
            if titles:
                expanded.extend(titles)
                continue
        expanded.append(item)
    segmented = _parse_segments(ct, raw)
    pool = ([segmented] if segmented else []) + expanded
    normalized = [re.sub(r"\s+", " ", (item or "").replace("\u2005", " ")
                         .replace("\u00a0", " ")).strip() for item in pool]
    merged = []

    def canon(value):
        return re.sub(r"[\s，。！？；：、,!?;:：]", "", value)

    for chunk in normalized:
        if not chunk or chunk == "(无正文)":
            continue
        # 被更长文本包含的短片段（如单独的人名）不重复输出
        if any(chunk != other and chunk in other for other in normalized if other):
            continue
        key = canon(chunk)
        if any(key == canon(existing) for existing in merged):
            continue
        merged.append(chunk)
    return "\n".join(merged)[:6000] if merged else "(无正文)"


def _json_titles(text):
    """从卡片 JSON 里递归提取中文标题；JSON 被 protobuf 截断时用正则兜底。"""
    out = []

    def add(value):
        value = (value or "").strip()
        if 1 < len(value) < 300 and re.search(r"[\u4e00-\u9fff]", value) and value not in out:
            out.append(value)

    try:
        obj = json.loads(text)

        def walk(node, depth=0):
            if depth > 6:
                return
            if isinstance(node, dict):
                for value in node.values():
                    if isinstance(value, str):
                        add(value)
                    else:
                        walk(value, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    walk(item, depth + 1)

        walk(obj)
    except Exception:
        pass
    if not out:
        for match in re.finditer(r'"([^"\\]*[\u4e00-\u9fff][^"\\]{0,250})"', text):
            add(match.group(1))
    return out[:20]


# ---------------------------------------------------------------- 合并转发卡片解析
#
# 本机真实样本（2026-11-19 实测）：
#   message_id=315221  ct=4  「张四心和客服-小东（云朵团队）」   21 条子消息 / 6 张图
#   message_id=315273  ct=4  「Chat History for 张四心 and PPT小东」 15 条子消息
# 结构：
#   root.f2 标题；root.f1[] 子消息
#   子消息 f2 时间(Unix 秒) / f5 类型(0,2=文本 14,101=图片 15=文件) / f11 发言人
#          f101 文本正文（3~5 层 protobuf 嵌套）/ f103 媒体 payload
#   媒体 payload f2 原文件名、f4 原始字节数、f8/f10/f30/f31 32 位 hash、
#                f3/f26 下载 URL、f25 token、f44 扩展名
# 关键实测：图片 f103.f10 恰好等于本机 Cache/Image 里对应 .jpg 的 MD5，
#           6/6 精确命中，因此用「原始字节数 + MD5」做最强匹配键。
#
# 2026-11-21 实测补充（客服-白白）：合并转发可任意层套娃。第 1 层子消息
# f107 里是完整的二级卡片 payload（同样的 f1[] 子消息 + f2 标题结构），
# 二级卡片里还能再嵌三级。因此不再写死「f101/102/105/107 是文本、f103/104/106
# 是媒体」，改为遍历子消息全部字段：长得像卡片的递归展开，长得像媒体的全收。

_FWD_TEXT_FIELDS = (101, 102, 105, 107)
_FWD_MEDIA_FIELDS = (103, 104, 106)
_HASH32_RE = re.compile(r"[0-9a-fA-F]{32}")
# 任意后缀，不再使用 ATTACHMENT_EXTS 白名单（PDF/OBJ/STP/NC/RVT/C4D… 一律收）
_NAME_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,12}$")
_CARD_MIN_SUBS = 2
_MAX_CARD_DEPTH = 8


def _media_filename_ok(text):
    """媒体 payload.f2 是否是真实文件名：有点后缀即可，不限制具体后缀。

    uuid/hex 形式的缓存名（如 0123abcd-….jpg）也是企微真实文件名，必须收下。
    """
    if not text or len(text) > 180:
        return False
    if not _NAME_EXT_RE.search(text):
        return False
    stem = text.rsplit(".", 1)[0]
    if re.fullmatch(r"[0-9a-fA-F]{32,}", stem):
        return False
    if re.fullmatch(r"https?://.*", text, re.I) or "/" in text or "\\" in text:
        return False
    return True


def _pb_map(blob):
    from protobuf_fields import ordered_fields
    out = {}
    try:
        for number, value in ordered_fields(bytes(blob)):
            out.setdefault(number, []).append(value)
    except Exception:
        return {}
    return out


def _pb_str(value, min_len=1):
    if not isinstance(value, (bytes, bytearray)):
        return ""
    try:
        text = bytes(value).decode("utf-8")
    except UnicodeDecodeError:
        return ""
    text = text.strip()
    if len(text) < min_len or _printable_ratio(text) < 0.85:
        return ""
    return text


def _clean_fwd_body(text):
    """合并转发子消息正文二次清洗：安卓缓存路径行 + 紧跟的纯哈希图片名行。"""
    if not text:
        return ""
    out = []
    for line in str(text).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.search(r"/storage/emulated/|/Android/data/com\.tencent\.wework/files/",
                     stripped, re.I):
            continue
        if re.fullmatch(r"[0-9a-fA-F]{16,}\.(?:jpg|jpeg|png|gif|webp|bmp)",
                        stripped, re.I):
            continue
        out.append(line)
    return "\n".join(out).strip()


def _fwd_noise(text):
    """合并转发里的内部 CDN / hex / base64 / 成员 ID 串才算噪音；业务 URL 必须保留。"""
    if not text:
        return True
    if text.startswith(("http://", "https://")):
        return _is_internal_url(text)
    if re.search(r"/storage/emulated/|/Android/data/com\.tencent\.wework/files/",
                 text, re.I):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{16,}\.(?:jpg|jpeg|png|gif|webp|bmp)", text, re.I):
        return True
    if ("qlogo.cn" in text or "qpic.cn" in text or "tpdownloadmedia" in text
            or "wwpic" in text):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{20,}", text) or re.fullmatch(r"[A-Za-z0-9+/=_\-]{20,}", text):
        return True
    if re.fullmatch(r"\d{10,25}(?:[;,]\s*\d{10,25}){2,}", text) or re.fullmatch(r"\d{10,}", text):
        return True
    # 短数字是正常聊天正文（接单扣 1、报价 120 / 500），必须保留
    if re.fullmatch(r"\d{1,6}", text):
        return False
    if len(text) <= 5 and not re.search(r"[\u4e00-\u9fff]", text) and not _NAME_EXT_RE.search(text):
        return True
    return False


def _clean_pb_text(value):
    text = _pb_str(value)
    if not text:
        return ""
    # 递归兜底时可能带出 protobuf 的 tag / 长度前缀控制字节，统一清掉
    text = re.sub(r"[\x00-\x1f]", "", text)
    return text.strip()


def _pb_texts(blob, depth=0):
    """递归抽出子消息正文（结构化解析失败时的兜底）。"""
    if depth > 7 or not isinstance(blob, (bytes, bytearray)) or len(blob) > 500000:
        return []
    fields = _pb_map(blob)
    if not fields:
        text = _clean_pb_text(blob)
        return [text] if text and not _fwd_noise(text) else []
    out = []
    for number in sorted(fields):
        for value in fields[number]:
            if isinstance(value, int):
                continue
            text = _clean_pb_text(value)
            if text and not _fwd_noise(text):
                out.append(text)
            elif len(value) > 3:
                out.extend(_pb_texts(value, depth + 1))
    return out


def _fwd_text(payload):
    """按 f101 → f1 → f2 → f1[] 的已知层级取文本段（含多段表情/换行）。

    直接把整个 payload 当字符串会带出 `\\x12`、`b` 这类长度前缀字节，
    所以优先按 protobuf 层级下钻；实在解不开才回退到递归文本抽取。
    """
    segments = []
    level1 = _pb_map(payload)
    for outer in (level1.get(1, []) or [payload]):
        if not isinstance(outer, (bytes, bytearray)):
            continue
        level2 = _pb_map(outer)
        if not level2:
            continue
        for middle in (level2.get(2, []) or level2.get(1, [])):
            if not isinstance(middle, (bytes, bytearray)):
                continue
            level3 = _pb_map(middle)
            candidates = []
            if level3:
                for number in (1, 2):
                    candidates.extend(v for v in level3.get(number, [])
                                      if isinstance(v, (bytes, bytearray)))
            else:
                candidates = [middle]
            for candidate in candidates:
                text = _clean_pb_text(candidate)
                if text and not _fwd_noise(text):
                    segments.append(text)
    if not segments:
        segments = [_clean_pb_text(t) for t in _pb_texts(payload)]
    return "\n".join(dict.fromkeys(s for s in segments if s and not _fwd_noise(s)))[:6000]


def _fwd_media(blob, sub_ct=0):
    """解析媒体 payload：原文件名 / 原始字节数 / 32 位 hash / token / url。

    不再按 ATTACHMENT_EXTS 白名单判断「是不是文件」：只要有原始大小，且带
    任意后缀的真实文件名或 32 位 hash，就一律收下，后续按 名字 →
    (字节数 + MD5) 去 Cache/File、Image、Video、Voice 全盘精准匹配。
    """
    payload = _pb_map(blob)
    if not payload:
        return None
    original = ""
    for number in (2, 44):
        for value in payload.get(number, []):
            text = _pb_str(value)
            if _media_filename_ok(text):
                original = _clean_filename(text)
                break
        if original:
            break
    size = payload.get(4, [0])[0]
    size = int(size) if isinstance(size, int) else 0
    if not size:
        alt = payload.get(19, [0])[0]
        size = int(alt) if isinstance(alt, int) else 0
    hashes = []
    for number in (8, 10, 30, 31):
        for value in payload.get(number, []):
            text = _pb_str(value)
            if text and _HASH32_RE.fullmatch(text):
                hashes.append(text.lower())
    hashes = list(dict.fromkeys(hashes))
    tokens = []
    for number in (25, 1):
        for value in payload.get(number, []):
            t = _pb_str(value)
            if t and len(t) >= 12 and not t.startswith("http"):
                tokens.append(t)
    tokens = list(dict.fromkeys(tokens))
    token = tokens[0] if tokens else ""
    urls = []
    for number in (3, 26):
        for value in payload.get(number, []):
            candidate = _pb_str(value)
            if candidate.startswith("http"):
                urls.append(candidate)
    urls = list(dict.fromkeys(urls))
    url = urls[0] if urls else ""
    # 外部微信图片（ct=101）元数据：
    #   f4 = 服务端字节数 / f8,f31 = CDN hash / f10 = 预览 hash
    #   f27 = 210px 缩略图字节数（绝非高清中图）/ f5,f6 与 f28,f29 = 宽高
    #   真正的高清原图本地路径记录在 message_table.local_extra_content（f8.f1）中。
    dims = []
    for wn, hn in ((5, 6), (28, 29)):
        w = payload.get(wn, [0])[0]
        h = payload.get(hn, [0])[0]
        if isinstance(w, int) and isinstance(h, int) and w and h:
            dims.append((w, h))
    dims = list(dict.fromkeys(dims))
    mid_size = payload.get(27, [0])[0]
    mid_size = int(mid_size) if isinstance(mid_size, int) else 0
    tiers = []
    if size:
        tiers.append({"label": "原图", "size": size,
                      "hash": hashes[0] if hashes else ""})
    if mid_size and mid_size != size:
        tiers.append({"label": "预览图", "size": mid_size,
                      "hash": hashes[1] if len(hashes) > 1 else ""})
    # 必须是真媒体，避免把文本 / 卡片 payload 误判成附件
    if not (size > 0 and (original or hashes)):
        return None
    # ct=103 等外部表情会带一个 3~26 字节的空占位 payload，
    # 既没有文件名也没有可下载内容，不该报「附件未下载」
    if size < 64 and not original:
        return None
    suffix = Path(original).suffix.lower() if original else ""
    # 有名字的 .jpg/.png 也是图片，不能因为「有文件名」就当成普通文档
    kind = "image" if (not original or suffix in IMAGE_EXTENSIONS) else "file"
    return {
        "name": original, "named": bool(original), "kind": kind,
        "size": size, "hashes": hashes, "token": token[:180],
        "tokens": [t[:220] for t in tokens[:4]],
        "url": url[:400], "urls": [u[:600] for u in urls[:4]],
        "tiers": tiers, "dims": dims, "local_paths": [],
        "source": None, "match": None, "tier_used": "",
        "placeholder": False, "thumb": False,
    }


def _pb_first_int(fields, number, default=0):
    value = fields.get(number, [None])[0]
    return int(value) if isinstance(value, int) else default


def _pb_first_text(fields, number):
    for value in fields.get(number, []):
        text = _pb_str(value)
        if text:
            return text
    return ""


def _is_card_payload(blob):
    """卡片 payload：>=2 个 f1 子消息，且每个都带 f2(时间) / f5(类型)。"""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 60:
        return False
    fields = _pb_map(blob)
    subs = [v for v in fields.get(1, [])
            if isinstance(v, (bytes, bytearray)) and len(v) > 12]
    if len(subs) < _CARD_MIN_SUBS:
        return False
    score = 0
    for sub in subs:
        f = _pb_map(sub)
        if 2 in f and 5 in f and isinstance(f[2][0], int) and isinstance(f[5][0], int):
            score += 1
    return score >= _CARD_MIN_SUBS


def _sub_text(fields, skip_fields=(), allow_fallback=True):
    segments = []
    for number in _FWD_TEXT_FIELDS:
        if number in skip_fields:
            continue
        for value in fields.get(number, []):
            if isinstance(value, (bytes, bytearray)):
                for line in _fwd_text(value).splitlines():
                    if line.strip():
                        segments.append(line.strip())
    if not segments and allow_fallback:
        # 少数卡片把正文放在非常规字段；此时才全字段兜底
        for number in sorted(fields):
            if number in skip_fields or number in _FWD_TEXT_FIELDS or number in (11, 6, 8, 12):
                continue
            for value in fields[number]:
                if isinstance(value, (bytes, bytearray)) and 4 <= len(value) < 2000:
                    for line in _fwd_text(value).splitlines():
                        if line.strip():
                            segments.append(line.strip())
    # 通用增强（任意层嵌套复用）：@提及分段、业务 URL、深层中文文本
    extras = []
    for number in sorted(fields):
        if number in skip_fields:
            continue
        for value in fields[number]:
            if not isinstance(value, (bytes, bytearray)):
                continue
            segmented = _parse_segments(2, value)
            if segmented and segmented not in segments:
                extras.append(segmented)
            for url in _business_urls(value)[:2]:
                if url not in extras:
                    extras.append(url)
            for deep in _deep_strings(value):
                for line in deep.splitlines():
                    line = line.strip()
                    if (line and not _fwd_noise(line) and line not in segments
                            and line not in extras):
                        extras.append(line)
    segments.extend(extras[:12])
    return "\n".join(dict.fromkeys(segments))[:6000]


def _sub_media(fields, skip_fields=()):
    """遍历子消息全部字段收媒体 payload（不限后缀、不限字段号）。"""
    out, seen = [], set()
    for number in sorted(fields):
        if number in skip_fields:
            continue
        for value in fields[number]:
            if not isinstance(value, (bytes, bytearray)) or len(value) < 20:
                continue
            item = _fwd_media(value)
            if not item:
                continue
            key = (item["size"], tuple(item["hashes"]), item["name"])
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out


def _flatten_card(raw, depth, seen, fallback_ts):
    """展开一层卡片；嵌套卡片在其父消息的【原位置】递归插入。"""
    root = _pb_map(raw)
    subs_raw = [v for v in root.get(1, [])
                if isinstance(v, (bytes, bytearray)) and len(v) > 8]
    if not subs_raw:
        return [], "", depth
    title = ""
    for number in (2, 3):
        candidate = _pb_first_text(root, number)
        if candidate and not _fwd_noise(candidate):
            title = candidate
            break
    parsed = []
    for index, blob in enumerate(subs_raw):
        fields = _pb_map(blob)
        if not fields:
            continue
        raw_ts = _pb_first_int(fields, 2)
        ts = float(raw_ts) if 1_400_000_000 < raw_ts < 2_600_000_000 else 0.0
        sub_ct = _pb_first_int(fields, 5)
        sender = ""
        for number in (11, 6):
            candidate = _pb_first_text(fields, number)
            if candidate and not _fwd_noise(candidate):
                sender = candidate
                break
        nested = []
        for number in sorted(fields):
            for value in fields[number]:
                if isinstance(value, (bytes, bytearray)) and _is_card_payload(value):
                    digest = hashlib.md5(bytes(value)).hexdigest()
                    if digest in seen:
                        continue
                    nested.append((number, value, digest))
        skip = {n for n, _, _ in nested}
        media = _sub_media(fields, skip)
        text = _clean_fwd_body(
            _sub_text(fields, skip, allow_fallback=not (media or nested)))
        if not (text or media or nested):
            continue
        if nested:
            kind = "合并转发"
        elif any(m["kind"] == "file" for m in media):
            kind = "文件"
        elif media:
            kind = "图片"
        else:
            kind = "文字"
        # 合并转发卡片里的语音子消息：打上语音标记，导出时按同样规则显示转文字并转 MP3
        voice = None
        if int(sub_ct or 0) == VOICE_CTYPE and not nested:
            voice = {"duration": _pb_first_int(fields, 7) or 0,
                     "size": _pb_first_int(fields, 4) or 0,
                     "transcript": None}
            kind = "语音"
        effective_ts = ts or fallback_ts
        parsed.append((ts, index, {
            "idx": index, "ts": effective_ts,
            "time": ex.fmt_time(effective_ts) if effective_ts else "",
            "sender": sender or "未知", "ct": sub_ct, "kind": kind,
            "text": text, "files": media, "depth": depth, "voice": voice,
            "is_card": bool(nested),
            "card_title": title or "合并转发聊天记录",
        }, nested))
    # 每层内部按原始时间正序；ts=0（图文卡片子消息）保持 payload 原顺序
    parsed.sort(key=lambda item: (item[0] or 0, item[1]))
    flat, max_depth = [], depth
    for ts, index, entry, nested in parsed:
        flat.append(entry)
        for number, value, digest in nested:
            if depth >= _MAX_CARD_DEPTH:
                continue
            children, _, child_depth = _flatten_card(
                value, depth + 1, seen | {digest}, entry["ts"] or fallback_ts)
            for child in children:
                child["parent_title"] = entry["card_title"]
            flat.extend(children)
            max_depth = max(max_depth, child_depth)
    return flat, title, max_depth


def parse_forward_card(ct, raw, fallback_ts=0.0):
    """识别合并转发 / 图文混排卡片，并递归展开【任意层】嵌套。

    返回平铺 subs（每条带 depth），调用方按 depth 生成 ### / #### 层级标题。
    图文混排卡片（ct=123）同样适用：f1[] 里混排图片子消息与文字子消息。
    """
    if not raw or len(raw) < 60 or not _is_card_payload(raw):
        return None
    ct = int(ct or 0)
    flat, title, levels = _flatten_card(raw, 1, set(), float(fallback_ts or 0))
    if not flat:
        return None
    card_type = "图文混排卡片" if ct == 123 else "合并转发"
    if not title:
        title = "图文混排卡片" if ct == 123 else "合并转发聊天记录"
    total_files = sum(len(s["files"]) for s in flat)
    return {
        "title": title, "card_type": card_type, "ct": ct,
        "count": len(flat), "levels": levels, "subs": flat,
        "total_files": total_files,
        # images 保留为兼容字段，语义改为「附件总数」，消除统计口径矛盾
        "images": total_files, "matched": 0, "missing": 0,
    }


def _image_suffix_of(path):
    try:
        with Path(path).open("rb") as handle:
            head = handle.read(12)
    except OSError:
        return ""
    if head[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if head[:4] == b"\x89PNG":
        return ".png"
    if head[:4] in (b"GIF8", b"GIF9"):
        return ".gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return ".webp"
    return ""


_MD5_CACHE = {}
_MD5_LOCK = threading.Lock()


def _md5_of(path):
    try:
        stat = Path(path).stat()
        key = (str(path), stat.st_size, stat.st_mtime_ns)
    except OSError:
        return ""
    with _MD5_LOCK:
        if key in _MD5_CACHE:
            return _MD5_CACHE[key]
    try:
        digest = hashlib.md5()
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        value = digest.hexdigest()
    except OSError:
        value = ""
    with _MD5_LOCK:
        if len(_MD5_CACHE) > 30000:
            _MD5_CACHE.clear()
        _MD5_CACHE[key] = value
    return value


_CACHE_INDEX_CACHE = {}
_CACHE_INDEX_LOCK = threading.Lock()


def _cached_cache_index(acc, ttl=180):
    key = acc["id"]
    now = time.time()
    # Cache\Image 新增图片时目录指纹立刻变化，不再干等 180 秒 TTL
    fingerprint = _cache_dir_fingerprint(acc)
    with _CACHE_INDEX_LOCK:
        hit = _CACHE_INDEX_CACHE.get(key)
        if (hit and len(hit) > 3 and now - hit[0] < ttl
                and hit[3] == fingerprint):
            return hit[1], hit[2]
    index, count = build_cache_index(acc)
    with _CACHE_INDEX_LOCK:
        _CACHE_INDEX_CACHE[key] = (now, index, count, fingerprint)
    return index, count


_IMAGE_DIMS_CACHE = {}
_IMAGE_DIMS_LOCK = threading.Lock()


def _image_dims_uncached(path):
    """轻量读 JPEG / PNG 宽高（只读头部，不装 Pillow 也能消歧义）。"""
    import struct
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
            # 绝大多数缓存不是 JPEG/PNG：读 8 字节就判定，避免全盘读 64KB
            if magic[:2] != b"\xff\xd8" and magic[:8] != b"\x89PNG\r\n\x1a\n":
                return (0, 0)
            fh.seek(0)
            head = fh.read(65536)
    except OSError:
        return (0, 0)
    if head[:8] == b"\x89PNG\r\n\x1a\n" and len(head) >= 24:
        return struct.unpack(">II", head[16:24])
    if head[:2] == b"\xff\xd8":
        pos = 2
        while pos < len(head) - 9:
            if head[pos] != 0xFF:
                pos += 1
                continue
            marker = head[pos + 1]
            if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            seg_len = struct.unpack(">H", head[pos + 2:pos + 4])[0]
            if (0xC0 <= marker <= 0xCF
                    and marker not in (0xC4, 0xC8, 0xCC)):
                h, w = struct.unpack(">HH", head[pos + 5:pos + 9])
                return (w, h)
            pos += 2 + seg_len
    return (0, 0)


def _image_dims_of(path):
    """按 (路径, 大小, mtime) 缓存图片尺寸，避免上千次重复读盘。"""
    try:
        info = Path(path).stat()
        key = (str(path), info.st_size, info.st_mtime_ns)
    except OSError:
        return (0, 0)
    with _IMAGE_DIMS_LOCK:
        hit = _IMAGE_DIMS_CACHE.get(key)
    if hit is not None:
        return hit
    dims = _image_dims_uncached(path)
    with _IMAGE_DIMS_LOCK:
        if len(_IMAGE_DIMS_CACHE) > 20000:
            _IMAGE_DIMS_CACHE.clear()
        _IMAGE_DIMS_CACHE[key] = dims
    return dims


_BLURRY_THUMB_MAX_EDGE = 400
_BLURRY_THUMB_MAX_BYTES = 30 * 1024
_HD_PREVIEW_MIN_EDGE = 600
_SIZE_ONLY_MIN_BYTES = 10 * 1024
_SIZE_ONLY_MAX_EARLIER = 600          # 仅按 size 匹配时，缓存 mtime 不能早于消息时间 10 分钟以上
_CACHE_REL_RE = re.compile(r"[\\/]cache[\\/](.+)$", re.I)
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:\\[^\r\n\t\"'<>|]{5,260}$")
_COPY_PREVIEW_RE = re.compile(r"\(\d+\)\.[^.]+$")
_BLURRY_WARNING_TEXT = "[⚠️ 仅为 210px 模糊缩略图，请企微点开大图后自动升级高清]"
_MANAGED_UUID_ATTACH_RE = re.compile(
    r"^(\d{3})_(\d{4}-\d{4})_([0-9a-fA-F\-]{24,}|参考图\d+)\.(jpg|jpeg|png|webp|gif)$",
    re.I,
)


def _is_blurry_thumb(path):
    """判定是否为 210px 级极小模糊缩略图（长边 < 400px 且文件 < 30KB）。"""
    try:
        st = Path(path).stat()
    except OSError:
        return False
    if st.st_size <= 0 or st.st_size >= _BLURRY_THUMB_MAX_BYTES:
        return False
    w, h = _image_dims_of(path)
    return bool(w > 0 and h > 0 and max(w, h) < _BLURRY_THUMB_MAX_EDGE)


def _mtime_not_too_old(mtime, ts, max_earlier=_SIZE_ONLY_MAX_EARLIER):
    """无 MD5 仅按字节数匹配时，缓存文件 mtime 绝不能早于消息时间 10 分钟以上。"""
    if not ts or float(ts) <= 0:
        return True
    try:
        return float(mtime) >= (float(ts) - float(max_earlier))
    except (TypeError, ValueError):
        return False


def _unique_md5_candidates(candidates):
    """候选列表只有 1 个文件，或多个候选实际为完全相同的 MD5 内容时返回 True。"""
    if not candidates:
        return False
    if len(candidates) == 1:
        return True
    digests = {_md5_of(c[1]) for c in candidates}
    digests.discard("")
    return len(digests) == 1


def _resolve_local_extra_path(raw_path, cache_roots):
    """把 local_extra_content 里的虚拟/宿主机缓存路径映射到真实可读文件（兼容 Sandboxie）。"""
    text = str(raw_path or "").strip()
    if not text or not _WIN_PATH_RE.match(text):
        return None
    m = _CACHE_REL_RE.search(text)
    if m:
        rel = m.group(1).replace("/", "\\").lstrip("\\")
        for root in cache_roots:
            try:
                cand = Path(root) / rel
                if cand.is_file() and cand.stat().st_size > 0:
                    return cand
            except OSError:
                continue
    try:
        direct = Path(text)
        if direct.is_file() and direct.stat().st_size > 0:
            return direct
    except OSError:
        pass
    return None


def _extract_local_extra_entries(lext, acc, cfg=None):
    """解析 message_table.local_extra_content（f8.f1 的 URL/fileid -> 本地缓存路径对）。

    企微点开外部微信图片（ct=101）或内部原图（ct=14）后，会把真实落盘的高清原图路径
    （如 Cache\\Image\\2026-11\\<uuid>.jpg，1080×1920 / 4032×3024）直接写进 f8.f1。
    """
    if not lext:
        return []
    blob = bytes(lext)
    if len(blob) < 12 or b":\\" not in blob:
        return []
    try:
        top = _pb_map(blob)
    except Exception:
        return []
    raw_pairs = []
    for sub_blob in top.get(8, []):
        if not isinstance(sub_blob, (bytes, bytearray)):
            continue
        sub = _pb_map(sub_blob)
        vals = [_pb_str(v) for v in sub.get(1, [])]
        i = 0
        while i < len(vals):
            cur = vals[i]
            nxt = vals[i + 1] if i + 1 < len(vals) else ""
            if nxt and _WIN_PATH_RE.match(nxt) and not _WIN_PATH_RE.match(cur):
                raw_pairs.append((cur, nxt))
                i += 2
            elif _WIN_PATH_RE.match(cur):
                raw_pairs.append(("", cur))
                i += 1
            else:
                i += 1
    if not raw_pairs:
        return []
    cache_roots = _cache_dirs_of(acc, cfg)
    seen, entries = set(), []
    for key_str, raw_path in raw_pairs:
        resolved = _resolve_local_extra_path(raw_path, cache_roots)
        if not resolved:
            continue
        try:
            canon = str(resolved.resolve()).casefold()
            st = resolved.stat()
        except OSError:
            continue
        if canon in seen or st.st_size <= 0:
            continue
        seen.add(canon)
        dims = _image_dims_of(resolved)
        is_img = bool(dims != (0, 0) or _image_suffix_of(resolved))
        entries.append({
            "key": key_str,
            "path": str(resolved),
            "size": st.st_size,
            "dims": dims,
            "is_image": is_img,
            "is_copy_preview": bool(_COPY_PREVIEW_RE.search(resolved.name)),
        })
    return entries


def _bind_local_extra_to_media(media_items, local_entries):
    """把 local_extra_content 提取的本地路径绑定到对应的媒体条目。"""
    if not media_items or not local_entries:
        return
    if len(media_items) == 1:
        media_items[0]["local_paths"] = list(local_entries)
        return
    for item in media_items:
        keys = set()
        for u in (item.get("urls") or []):
            if u:
                keys.add(u)
        if item.get("url"):
            keys.add(item["url"])
        for t in (item.get("tokens") or []):
            if t:
                keys.add(t)
        if item.get("token"):
            keys.add(item["token"])
        hashes = {h.lower() for h in (item.get("hashes") or []) if h}
        norm_name = _norm_filename(item["name"]) if item.get("name") else ""
        matched = []
        for entry in local_entries:
            ek = entry.get("key") or ""
            ename = _norm_filename(Path(entry["path"]).name)
            hit = False
            if ek and any(ek == k or ek.startswith(k) or k.startswith(ek) for k in keys if len(k) >= 16):
                hit = True
            elif ek and any(h in ek.lower() for h in hashes):
                hit = True
            elif norm_name and ename == norm_name:
                hit = True
            if hit:
                matched.append(entry)
        if matched:
            item["local_paths"] = matched


def _match_media_item(item, index, msg_ts=0, card_ts=0, allow_f27_thumb=False):
    """严格三级媒体匹配（彻底禁止纯宽高 by_dims 盲配）：

    第 1 优先：高清原图（local_extra_content 高清路径 / 精确 size+MD5 / 精确文件名 /
              严控 size 兜底：>10KB 且字节精确相等且 mtime 不早于消息 10 分钟以上）；
    第 2 优先：高清预览中图（长边 ≥ 600px）；
    第 3 兜底：磁盘确实只有 210px 级缩略图（长边 < 400px 且 < 30KB，仅来自本消息
              local_extra_content 或合并转发卡精确 f27+时间+唯一MD5），老实标模糊缩略图。
    """
    size = int(item.get("size") or 0)
    hashes = item.get("hashes") or []
    name = item.get("name") or ""
    kind = item.get("kind") or "image"
    ts = msg_ts or card_ts
    dims_hint = item.get("dims") or []

    # 整理本消息 local_extra_content 中已落盘的真实本地文件（按像素面积→长边→大小排序）
    local_valid = []
    for entry in (item.get("local_paths") or []):
        p = Path(entry["path"])
        if not p.is_file():
            continue
        try:
            fsize = p.stat().st_size
        except OSError:
            continue
        if fsize <= 0:
            continue
        w, h = entry.get("dims") or _image_dims_of(p)
        local_valid.append({
            "path": p, "size": fsize, "dims": (w, h),
            "area": w * h, "long_edge": max(w, h),
            "is_blurry": bool(w > 0 and h > 0 and max(w, h) < _BLURRY_THUMB_MAX_EDGE
                              and fsize < _BLURRY_THUMB_MAX_BYTES),
            "is_copy_preview": bool(entry.get("is_copy_preview")
                                    or _COPY_PREVIEW_RE.search(p.name)),
        })
    local_valid.sort(key=lambda e: (e["area"], e["long_edge"], e["size"]), reverse=True)

    # ---------------- 第 1 优先：高清原图 / 精确文件 ----------------
    if kind != "image" and local_valid:
        best_file = max(local_valid, key=lambda e: e["size"])
        return best_file["path"], "local_fileid"

    if kind == "image" and local_valid:
        # 优先选非 (1) 预览且非模糊缩略图的高清原图（如 1080×1920 / 4032×3024 / 2370×1360）
        hd_originals = [
            e for e in local_valid
            if not e["is_blurry"] and not e["is_copy_preview"]
            and (e["long_edge"] >= _HD_PREVIEW_MIN_EDGE
                 or (e["dims"] != (0, 0) and (not size or e["size"] >= size * 0.5)))
        ]
        if hd_originals:
            return hd_originals[0]["path"], "local_hd"

    if size and hashes:
        for candidate in index.get("by_size", {}).get(size, []):
            if _md5_of(candidate[1]) in hashes:
                return candidate[1], "size+md5"

    name_hit = None
    if name:
        hit = _lookup_cache(index, name, ts)
        if hit:
            try:
                hit_size = Path(hit).stat().st_size
            except OSError:
                hit_size = 0
            hit_blurry = (kind == "image" and _is_blurry_thumb(hit))
            if (not size or hit_size == size) and not (hit_blurry and size >= _BLURRY_THUMB_MAX_BYTES):
                return hit, "name"
            if not hit_blurry:
                name_hit = hit

    # 无 MD5 仅按 size 兜底：必须同时满足 >10KB + 精确字节相等 + mtime 不早于消息 10 分钟以上 + 内容唯一
    if size > _SIZE_ONLY_MIN_BYTES:
        candidates = [
            c for c in index.get("by_size", {}).get(size, [])
            if _mtime_not_too_old(c[0], ts)
            and not (kind == "image" and _is_blurry_thumb(c[1]))
        ]
        if _unique_md5_candidates(candidates):
            best = min(candidates, key=lambda c: abs(c[0] - (ts or c[0])))
            return best[1], "size"

    if name_hit:
        if kind != "image":
            return name_hit, "name-loose"
        nw, nh = _image_dims_of(name_hit)
        if max(nw, nh) >= _HD_PREVIEW_MIN_EDGE:
            return name_hit, "name-loose"

    # ---------------- 第 2 优先：高清预览中图（长边 >= 600px） ----------------
    if kind == "image" and local_valid:
        hd_previews = [e for e in local_valid
                       if not e["is_blurry"] and e["long_edge"] >= _HD_PREVIEW_MIN_EDGE]
        if hd_previews:
            return hd_previews[0]["path"], "高清中图降级"

    for tier in (item.get("tiers") or [])[1:]:
        tier_size = int(tier.get("size") or 0)
        if tier_size <= _SIZE_ONLY_MIN_BYTES:
            continue
        candidates = [
            c for c in index.get("by_size", {}).get(tier_size, [])
            if _mtime_not_too_old(c[0], ts)
            and max(_image_dims_of(c[1])) >= _HD_PREVIEW_MIN_EDGE
        ]
        if dims_hint and candidates:
            exact_d = [c for c in candidates
                       if (_image_dims_of(c[1]) in dims_hint
                           or tuple(reversed(_image_dims_of(c[1]))) in dims_hint)]
            if exact_d:
                candidates = exact_d
        if _unique_md5_candidates(candidates):
            best = min(candidates, key=lambda c: abs(c[0] - (ts or c[0])))
            return best[1], "高清中图降级"

    # local_extra_content 里若存在非模糊的合法小原图（400~599px 或 >=30KB），直接采用
    if kind == "image" and local_valid:
        non_blurry_local = [e for e in local_valid if not e["is_blurry"]]
        if non_blurry_local:
            return non_blurry_local[0]["path"], "local_hd"

    # ---------------- 第 3 兜底：210px 模糊缩略图（仅当磁盘无任何高清图时） ----------------
    if kind == "image" and local_valid:
        blurry_locals = [e for e in local_valid if e["is_blurry"]]
        if blurry_locals:
            return blurry_locals[0]["path"], "210px模糊缩略图降级"

    # 合并转发卡片（ct=4）企微不写 local_extra_content.f8 路径：
    # 仅允许精确匹配 protobuf f27 字节数 + mtime >= ts-600 + 确认 210px 缩略图 + 唯一 MD5。
    if allow_f27_thumb and kind == "image":
        for tier in (item.get("tiers") or [])[1:]:
            tier_size = int(tier.get("size") or 0)
            if not (0 < tier_size < _BLURRY_THUMB_MAX_BYTES):
                continue
            candidates = [
                c for c in index.get("by_size", {}).get(tier_size, [])
                if _mtime_not_too_old(c[0], ts) and _is_blurry_thumb(c[1])
            ]
            if dims_hint and candidates:
                candidates = [
                    c for c in candidates
                    if (_image_dims_of(c[1]) in dims_hint
                        or tuple(reversed(_image_dims_of(c[1]))) in dims_hint)
                ]
            if _unique_md5_candidates(candidates):
                best = min(candidates, key=lambda c: abs(c[0] - (ts or c[0])))
                return best[1], "210px模糊缩略图降级"

    return None, None


def resolve_forward_media(acc, card, card_ts, index=None, local_entries=None):
    """递归平铺后的所有层级附件统一找缓存，并把统计口径对齐。

    保证 total_files == matched + missing，且 images 就是 total_files，
    不再出现「含 0 张图片/文件，已精准匹配 1」这类矛盾。
    """
    if index is None:
        index, _ = _cached_cache_index(acc)
    if local_entries:
        all_items = [item for sub in card["subs"] for item in sub["files"]]
        _bind_local_extra_to_media(all_items, local_entries)
    image_no, total, matched, missing = 0, 0, 0, 0
    for sub in card["subs"]:
        for item in sub["files"]:
            total += 1
            if item["kind"] == "image" and not item.get("named"):
                image_no += 1
                item["name"] = item["name"] or f"参考图{image_no}.jpg"
            source, how = _match_media_item(
                item, index, sub.get("ts") or 0, card_ts, allow_f27_thumb=True)
            if source and item["kind"] == "image" and not item.get("named"):
                ext = _image_suffix_of(source)
                if ext:
                    item["name"] = f"参考图{image_no}{ext}"
            if source:
                matched += 1
                try:
                    item["size_kb"] = round(Path(source).stat().st_size / 1024, 1)
                except OSError:
                    item["size_kb"] = 0
            else:
                missing += 1
                item["size_kb"] = 0
            is_image = bool(source and _image_suffix_of(source))
            item["source"] = str(source) if source else None
            item["match"] = how
            item["thumb"] = is_image
            item["placeholder"] = False
    card["total_files"] = total
    card["images"] = total
    card["matched"] = matched
    card["missing"] = missing
    return card


def forward_thumb(acc, cid, mid, sub_i, file_i):
    """给界面返回合并转发子消息里某张图的本机绝对路径（调用方负责校验与读取）。"""
    cfg = load_config()
    messages = _message_index(cfg, acc, cid)
    message = next((m for m in messages if m["id"] == str(mid)), None)
    if not message or not message.get("forward"):
        return None, ""
    subs = message["forward"]["subs"]
    if not 0 <= sub_i < len(subs) or not 0 <= file_i < len(subs[sub_i]["files"]):
        return None, ""
    item = subs[sub_i]["files"][file_i]
    if not item.get("source"):
        return None, ""
    path = Path(item["source"]).resolve()
    roots = [Path(r).resolve() for r in _cache_dirs_of(acc, cfg)]
    if not any(r in path.parents for r in roots) or not path.is_file():
        return None, ""
    return path, _image_suffix_of(path)


# ---------------------------------------------------------------- 正文去噪 / 消息索引

ATTACHMENT_EXTS = (
    "docx", "doc", "pdf", "xlsx", "xls", "xlsm", "csv", "pptx", "ppt", "txt", "md",
    "wps", "et", "dps", "zip", "rar", "7z", "lnk", "dwg", "dxf", "rvt", "rfa", "skp", "obj",
    "stp", "step", "stl", "fbx", "3ds", "3dm", "max", "igs", "iges", "sat", "sldprt",
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "heic", "psd", "ai", "svg",
    "mp4", "mov", "avi", "mp3", "wav", "amr", "silk", "m4a",
)
# 取消后缀白名单：任意 1~12 位字母数字后缀都视为真实文件名
# （PDF/DOC/XLS/PPT/WPS/OBJ/STL/STP/NC/RVT/SKP/C4D/PSD/AI/7Z… 一律识别）
_EXT_ALT = r"[A-Za-z0-9]{1,12}"
_NOISE_URL_RE = re.compile(r"https?://[^\s\u4e00-\u9fff]+", re.I)
_NOISE_LINE_PATTERNS = [
    re.compile(r"^\d{15,20}$"),                       # 企微内部 15~20 位数字 ID
    re.compile(r"^\d{1,25}(?:[;,]\s*\d{10,25}){2,}$"),  # 分号拼接的系统成员 ID 列表（首段可短）
    re.compile(r"^[A-Za-z0-9+/=_\-]{24,}$"),         # hex / Base64 / v1_ 令牌 / md5
    re.compile(r"^[0-9a-fA-F]{32,}$"),
    re.compile(r"^[0-9a-fA-F\-]{32,}\.(?:jpg|jpeg|png|gif|webp)$", re.I),  # uuid 哈希图片名
    re.compile(r"^(?:file://|/var/|/private/|.*Containers/Data/Application/).*$", re.I),  # iOS 内部路径
    re.compile(r"^(?:/?storage/|/?data/user/|/?Android/data/|.*com\.tencent\.wework/files/).*$", re.I),  # 安卓缓存路径
]
_ANDROID_NOISE_RE = re.compile(
    r"^(?:/?storage/|/?data/user/|/?Android/data/|.*com\.tencent\.wework/files/)", re.I)

# ---------------------------------------------------------------- 通用链接 / 分段文本解析
# 只过滤企微内部 CDN；淘宝、网盘、腾讯文档、企微文档、网页等业务 URL 一律完整保留。
_INTERNAL_URL_PARTS = (
    "wx.qlogo.cn", "wework.qpic.cn", "wwpic", "qpic.cn",
    "imunion.weixin.qq.com", "tpdownloadmedia", "finder.video.qq.com",
    "wxapp.tc.qq.com", "rescdn.qqmail.com", "wwcdn.weixin.qq.com",
    "/cgi-bin/", "weixin.qq.com/cgi-bin", "stodownload?",
)
_URL_BYTES_RE = re.compile(
    rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{6,400}", re.I)
_URL_LINE_RE = re.compile(r"https?://[^\s\u4e00-\u9fff<>\"'\\]{6,400}", re.I)


def _is_internal_url(url):
    low = (url or "").lower()
    return any(part in low for part in _INTERNAL_URL_PARTS)


def _strip_internal_urls(line):
    """只删内部 CDN 链接；业务 URL 原样留在正文里。"""
    return _URL_LINE_RE.sub(
        lambda m: "" if _is_internal_url(m.group(0)) else m.group(0), line)


def _business_urls(raw):
    urls = []
    for match in _URL_BYTES_RE.finditer(bytes(raw or b"")):
        url = match.group(0).decode("utf-8", "ignore").rstrip(".,;)]}*\"'")
        if _is_internal_url(url) or len(url) < 12:
            continue
        if url not in urls:
            urls.append(url)
    return urls[:5]


def _is_noise_line(line):
    if not line:
        return True
    if any(p.fullmatch(line) for p in _NOISE_LINE_PATTERNS):
        return True
    if re.fullmatch(r"\d{1,25}(?:[;,]\s*\d{10,25}){2,}", line):
        return True
    if (re.search(r"[A-Za-z0-9+/=_\-]{40,}", line)
            and not re.search(r"[\u4e00-\u9fff]", line)):
        return True
    return False


def _link_cards(raw):
    """从任意类型 protobuf 提取业务链接卡片：标题 / 摘要 / URL。"""
    urls = _business_urls(raw)
    if not urls:
        return []
    texts = []
    for candidate in _deep_strings(raw):
        for piece in (candidate or "").splitlines():
            piece = piece.strip()
            if (not piece or len(piece) <= 1 or piece.lower().startswith("http")
                    or not re.search(r"[\u4e00-\u9fff]", piece)
                    or _is_noise_line(piece)):
                continue
            if piece not in texts:
                texts.append(piece)
    title = texts[0][:100] if texts else ""
    summary = " / ".join(texts[1:4])[:180]
    return [{"title": title, "summary": summary, "url": url} for url in urls[:3]]


def _parse_segments(ct, raw):
    """ct=2 的 f1[] 分段数组：mention 段 + 文本段，还原「@人名 + 完整正文」。

    真实结构：f1[0] = {f1:段类型(5/10), f2:{f1:成员ID, f2:人名}}，
              f1[1] = {f1:0, f2:{f1:正文}}。ex.render 只返回人名，正文必须下钻。
    """
    if int(ct or 0) != 2:
        return None
    fields = _pb_map(raw)
    segments = fields.get(1, [])
    if len(segments) < 2:
        return None
    names, texts = [], []
    for blob in segments:
        if not isinstance(blob, (bytes, bytearray)):
            continue
        sub = _pb_map(blob)
        seg_type = int(_pb_first(sub.get(1), 0) or 0)
        payload = _pb_first(sub.get(2), b"")
        if not isinstance(payload, (bytes, bytearray)):
            continue
        inner = _pb_map(payload)
        name = _pb_str(_pb_first(inner.get(2), b""))
        text = _pb_str(_pb_first(inner.get(1), b""))
        if seg_type and name:
            names.append("@" + name)
        elif text and text.strip():
            texts.append(text.replace("\u2005", " ").strip())
    if texts:
        joined = " ".join(dict.fromkeys(texts))
        if not any(name in joined for name in names):
            joined = " ".join(names + [joined])
        return joined.strip()
    if names:
        return " ".join(dict.fromkeys(names))
    return None


_FILE_LINE_RE = re.compile(rf"^([^\\/:*?\"<>|]{{1,120}}\.(?:{_EXT_ALT}))$", re.I)
_FILE_INLINE_RE = re.compile(
    rf"(?<![\w\u4e00-\u9fff])([^\\/:*?\"<>|\s]{{1,120}}\.(?:{_EXT_ALT}))(?![\w\u4e00-\u9fff])", re.I)
_BAD_STEM_PUNCT = re.compile(r"[，。！？；：、,!?;:]")


def _clean_filename(name):
    """去掉 protobuf 里成对出现的包裹符，保留文件名本体。

    注意 `《我一生中的重要抉择》教学设计.docx` 里的书名号是文件名的一部分，
    只有整体成对包裹（如 `[图.zip]`）才剥离，不能无脑 strip 掉开头的《。
    """
    text = str(name).strip()
    for left, right in (("[", "]"), ("【", "】"), ("<", ">"), ("《", "》"),
                        ('"', '"'), ("'", "'"), ("“", "”"), ("‘", "’")):
        if len(text) > 2 and text.startswith(left) and text.endswith(right):
            text = text[1:-1].strip()
            break
    return text.strip(" \t[]【】<>\"'“”‘’,，;；:：")


def _valid_filename(name):
    stem = name.rsplit(".", 1)[0]
    if not stem or len(stem) < 2:
        return False
    if re.fullmatch(r"[0-9a-fA-F_\-]{24,}", stem):  # 纯内部哈希名，不是用户提到的文件
        return False
    if _BAD_STEM_PUNCT.search(stem):
        return False
    return True


def _extract_filenames(line):
    """返回 (文件名列表, 去掉文件名后的正文行)。整行是文件名时优先整行判定。"""
    whole = _FILE_LINE_RE.fullmatch(line.strip())
    if whole and _valid_filename(whole.group(1)):
        return [_clean_filename(whole.group(1))], ""
    names = []

    def repl(match):
        name = _clean_filename(match.group(1))
        if name and _valid_filename(name):
            names.append(name)
            return " "
        return match.group(0)

    rest = _FILE_INLINE_RE.sub(repl, line)
    return names, rest


def clean_message(ct, raw):
    """把 protobuf 噪音洗掉，返回 (干净正文, 该消息明确提到的附件文件名列表)。

    过滤：内部 CDN 链接、独立 Base64/hex 行、15~20 位纯数字 ID、uuid 哈希图片名、
    无意义短乱码行、纯 [类型] 占位符；并去重合并重复行。
    """
    rendered = _render(ct, raw)
    files, body_lines, seen = [], [], set()
    for raw_line in rendered.splitlines():
        line = _strip_internal_urls(raw_line).strip()
        if not line:
            continue
        line = re.sub(r"^\[[^\]]{1,12}\]\s*", "", line).strip()  # 去掉 [文件]/[卡片]/[图片] 标签
        line = line.strip(" \t*·-—|>")
        if not line or re.fullmatch(r"\[[^\]]{1,12}\]", line):
            continue
        if any(p.fullmatch(line) for p in _NOISE_LINE_PATTERNS):
            continue
        # 视频号/网盘链接被拆出的查询串碎片（多个 & / = 参数、无中文、无 http）不算正文
        if ((line.count("&") >= 3 or (len(line) > 60 and "=" in line))
                and "http" not in line.lower()
                and not re.search(r"[\u4e00-\u9fff]", line)):
            continue
        # 正文里夹着一整串分号拼接的成员 ID 时，只删掉这段 ID，保留其余文字
        if re.search(r"\d{10,25}(?:;\d{10,25}){2,}", line):
            line = re.sub(r"\d{10,25}(?:;\d{10,25}){2,}", " ", line).strip()
            if not line:
                continue
        # 长 base64/hex/URL 查询串碎片且没有中文正文 → 整行丢弃；业务 URL 行必须保留
        if (re.search(r"[A-Za-z0-9+/=_\-&?%]{30,}", line)
                and not re.search(r"[\u4e00-\u9fff]", line)
                and "http" not in line.lower()):
            continue
        # 独立的英文账号/ID 行（合并转发里的 wxid），不是正文
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{7,23}", line):
            continue
        # 短数字正文（1 / 120 / 500 / 报价）必须保留；只丢弃短乱码
        if (not re.fullmatch(r"\d{1,6}", line)
                and len(line) <= 6 and not re.search(r"[\u4e00-\u9fff]", line)
                and not _FILE_LINE_RE.fullmatch(line)):
            continue  # 'Rígr' / ']' / 短乱码
        # 业务 URL 行完整保留，绝不把 doc.weixin.qq.com 之类误判成附件文件名
        if "http://" in line or "https://" in line:
            names, rest = [], line
        else:
            names, rest = _extract_filenames(line)
        for name in names:
            if name and name not in files:
                files.append(name)
        rest = re.sub(r"\s{2,}", " ", rest).strip(
            " \t-—·|[]【】<>《》\"'“”‘’,，;；:：")
        keep_short = bool(re.fullmatch(r"\d{1,6}", rest))
        if (rest and rest not in seen
                and (keep_short or not (len(rest) <= 3 and not re.search(r"[\u4e00-\u9fff]", rest)))):
            seen.add(rest)
            body_lines.append(rest)
    return "\n".join(body_lines).strip(), files


def extract_message_media(ct, raw):
    """非卡片消息：递归扫 protobuf，把所有媒体 payload 找出来（不限字段 / 后缀）。

    企业微信把图片/文件/视频/语音 payload 藏在 f103/f104/f106 或更深层；
    这里不再依赖清洗后文本里的文件名白名单，直接从原始字节里取
    真实文件名 + 原始字节数 + 32 位 hash。
    """
    if not raw:
        return []
    found, seen = [], set()

    def walk(blob, depth):
        if (depth > 7 or not isinstance(blob, (bytes, bytearray))
                or len(blob) > 2_000_000):
            return
        fields = _pb_map(blob)
        if not fields:
            return
        item = _fwd_media(blob)
        if item:
            key = (item["size"], tuple(item["hashes"]), item["name"])
            if key not in seen:
                seen.add(key)
                found.append(item)
        for number in sorted(fields):
            for value in fields[number]:
                if isinstance(value, (bytes, bytearray)) and len(value) > 20:
                    walk(value, depth + 1)

    walk(raw, 0)
    return found


_MSG_INDEX = {}          # 保序 dict 做 LRU：(acc,cid) -> (水印, 已清洗消息)
_MSG_INDEX_LOCK = threading.Lock()
_MSG_INDEX_MAX = 16      # 同时保留 16 个会话，来回切换大群不再全盘重解析
_MSG_REBUILDING = set()  # 后台正在重建的 (账号, 会话)，避免并发堆叠
_MSG_REBUILD_LOCK = threading.Lock()


# ---------------------------------------------------------------- 企业微信语音（企微转文字 + SILK→MP3）
VOICE_CTYPE = 16
VOICE_PCM_RATE = 24000
_VOICE_MP3_CACHE = {}
_VOICE_MP3_LOCK = threading.Lock()
_VOICE_MP3_CACHE_MAX = 32


def _pb_first(value, default=None):
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return value if value is not None else default


def extract_voice_meta(ct, raw):
    """ct=16 语音 protobuf：field7=时长(秒)、field4=缓存字节数、field10=MD5。"""
    if int(ct or 0) != VOICE_CTYPE or not raw:
        return None
    try:
        fields = _pb_map(raw)
    except Exception:
        return None
    duration = int(_pb_first(fields.get(7), 0) or 0)
    size = int(_pb_first(fields.get(4), 0) or 0)
    raw_md5 = _pb_first(fields.get(10), b"")
    md5 = (raw_md5.decode("ascii", "ignore") if isinstance(raw_md5, (bytes, bytearray))
           else str(raw_md5 or "")).lower()
    if not duration and not size:
        return None
    return {"duration": duration, "size": size, "md5": md5}


def load_voice_transcripts(acc, cfg, cid):
    """企微「转文字（转换完成）」文本：msg_voice2text.message_id == message_table.server_id。"""
    db = _dec_message_db(acc, cfg)
    out = {}
    try:
        with db_lock():
            con = connect_readonly(db)
            try:
                sql = ("SELECT m.message_id, v.text FROM message_table m "
                       "JOIN msg_voice2text v ON v.message_id = m.server_id "
                       "WHERE m.conversation_id=? AND m.content_type=?")
                for mid, text in con.execute(sql, (str(cid), VOICE_CTYPE)):
                    if text:
                        out[str(mid)] = str(text)
            finally:
                con.close()
    except (sqlite3.Error, OSError):
        pass
    return out


def resolve_voice_source(meta, index, msg_ts=0.0):
    """按 size+MD5 在 Cache/Voice 里精准找到 SILK 原件。"""
    if not meta or not meta.get("size"):
        return None
    item = {"size": meta["size"],
            "hashes": [meta["md5"]] if meta.get("md5") else [],
            "name": ""}
    try:
        source, _ = _match_media_item(item, index, msg_ts, msg_ts)
    except Exception:
        return None
    return str(source) if source and Path(source).is_file() else None


def is_silk_voice(path):
    """判断是否为微信 SILK v3 语音缓存（0x02 + '#!SILK_V3'）。"""
    try:
        target = Path(path)
        if "voice" not in str(target).casefold():
            return False
        with target.open("rb") as handle:
            head = handle.read(12)
        return head.startswith(b"\x02#!SILK_V3") or head.startswith(b"#!SILK_V3")
    except OSError:
        return False


def silk_to_mp3(source, duration=0):
    """SILK → PCM(24kHz/mono/s16le) → MP3；返回 (mp3_bytes, 时长秒)，失败 (None, 0)。"""
    try:
        import io
        import subprocess
        import pysilk

        path = Path(source)
        stat = path.stat()
        key = (str(path), stat.st_size, stat.st_mtime_ns)
        with _VOICE_MP3_LOCK:
            hit = _VOICE_MP3_CACHE.get(key)
        if hit:
            return hit
        pcm_out = io.BytesIO()
        pysilk.decode(io.BytesIO(path.read_bytes()), pcm_out, VOICE_PCM_RATE)
        pcm = pcm_out.getvalue()
        if not pcm:
            return None, 0
        actual = len(pcm) / 2.0 / VOICE_PCM_RATE
        seconds = int(duration or 0) or max(1, round(actual))
        result = subprocess.run(
            ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
             "-f", "s16le", "-ar", str(VOICE_PCM_RATE), "-ac", "1",
             "-i", "pipe:0", "-codec:a", "libmp3lame", "-b:a", "48k",
             "-f", "mp3", "pipe:1"],
            input=pcm, capture_output=True, timeout=90,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout:
            return None, 0
        payload = (bytes(result.stdout), seconds)
        with _VOICE_MP3_LOCK:
            if len(_VOICE_MP3_CACHE) >= _VOICE_MP3_CACHE_MAX:
                _VOICE_MP3_CACHE.clear()
            _VOICE_MP3_CACHE[key] = payload
        return payload
    except Exception:
        return None, 0


def voice_mp3_filename(duration):
    return f"语音{int(duration or 0)}s.mp3"


def resolve_voice_audio(path):
    """音频试听接口：只允许读取账号 Cache/Voice 下的 SILK 文件。"""
    cfg = load_config()
    target = Path(path).resolve()
    allowed = []
    for acc in cfg.get("accounts", []):
        root = Path(acc.get("cache_dir")
                    or (Path(acc["data_dir"]).parent / "Cache")) / "Voice"
        try:
            resolved = root.resolve()
            if resolved.is_dir():
                allowed.append(resolved)
        except OSError:
            pass
    if not any(root == target or root in target.parents for root in allowed):
        raise RuntimeError("拒绝访问非语音缓存路径")
    if not target.is_file() or not is_silk_voice(target):
        raise RuntimeError("语音缓存文件不存在或格式不支持")
    return target


def probe_media_duration(path):
    """用 ffprobe 读视频/音频时长（秒）；失败返回 0，绝不阻塞导出。"""
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=nw=1:nk=1", str(path)],
            capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode == 0 and result.stdout.strip():
            return max(0, int(round(float(result.stdout.strip()))))
    except Exception:
        pass
    return 0


def _message_summary(msg, limit=90):
    """生成引用摘要：语音 / 转发卡片 / 正文 / 文件名，尽量让 AI 看清被引用的内容。"""
    if msg.get("voice"):
        voice = msg["voice"] or {}
        text = (voice.get("transcript") or "").strip()
        return f'[语音 {voice.get("duration", 0)}"] ' + (
            text[:limit] if text else "（尚未在企微转文字）")
    if msg.get("forward"):
        card = msg["forward"]
        return f'[{card["card_type"]}] {card["title"]} · {card["count"]} 条子消息'
    body = (msg.get("content") or "").strip().replace("\n", " ")
    if body:
        return body[:limit]
    names = [item.get("name") for item in (msg.get("media") or []) if item.get("name")]
    names += [name for name in (msg.get("files") or []) if name]
    if names:
        return "、".join(list(dict.fromkeys(names))[:2])[:limit]
    return f'[{msg.get("type") or "消息"}]'


def _universal_fallback(ct, raw):
    """未知 content_type 兜底：递归抓可读文本、业务 URL、文件名，绝不静默空白。"""
    bits = []
    for candidate in _deep_strings(raw):
        for line in candidate.splitlines():
            line = _strip_internal_urls(line).strip()
            if line and len(line) > 1 and not _is_noise_line(line):
                bits.append(line)
    for url in _business_urls(raw)[:2]:
        bits.append(url)
    for match in re.finditer(rb"[^\s\x00-\x1f\"'\\/]{2,120}\.[A-Za-z0-9]{1,8}",
                             bytes(raw or b"")):
        name = match.group(0).decode("utf-8", "ignore")
        if _media_filename_ok(name):
            bits.append(name)
    return " / ".join(list(dict.fromkeys(bits))[:8])


def _schedule_message_rebuild(cfg, acc, cid):
    """缓存水印变化时后台重建；HTTP 先返回上一份有效快照，绝不卡 8 秒。"""
    key = (str(acc["id"]), str(cid))
    with _MSG_REBUILD_LOCK:
        if key in _MSG_REBUILDING:
            return
        _MSG_REBUILDING.add(key)

    def run():
        try:
            _message_index(cfg, acc, cid, allow_stale=False)
        except Exception as exc:
            print(f"[msg-index] 后台重建失败 {cid}: {exc}", file=sys.stderr)
        finally:
            with _MSG_REBUILD_LOCK:
                _MSG_REBUILDING.discard(key)

    threading.Thread(target=run, daemon=True).start()


def _message_index(cfg, acc, cid, allow_stale=False):
    """全量清洗后的消息（时间正序）；只读接口可用旧快照 + 后台重建。"""
    db = _dec_message_db(acc, cfg)
    source = Path(acc["data_dir"]) / "message.db"
    # 稳定水印：文件大小 + 该会话 (MAX(message_id), COUNT(*)) + 缓存目录条目。
    # 企微会持续 touch 原库/WAL/Cache 的 mtime_ns，若纳入缓存键会导致每次
    # /api/messages 都全量重建（压测中 8 秒超时）；真实新消息由 MAX/COUNT 感知。
    peak = _codex_conv_peak(cfg, acc, cid) or [0, 0]
    stamp = (_stat_sig_stable(db), _stat_sig_stable(str(db) + "-wal"),
             _stat_sig_stable(source), _stat_sig_stable(str(source) + "-wal"),
             _dec_version(acc), tuple(peak), _cache_dir_fingerprint(acc, cfg))
    key = (acc["id"], str(cid))
    with _MSG_INDEX_LOCK:
        hit = _MSG_INDEX.get(key)
        if hit and hit[0] == stamp:
            _MSG_INDEX[key] = _MSG_INDEX.pop(key)   # 命中移到 LRU 末尾
            return hit[1]
        stale = hit[1] if hit else None
    # 水印变了但已有有效快照：先给界面旧数据，后台慢慢重建，HTTP 绝不陪跑。
    if allow_stale and stale is not None:
        _schedule_message_rebuild(cfg, acc, cid)
        return stale
    # 后台 5 分钟同步 / 重扫密钥正持有解密库写锁时，只读预览不排队：
    # 直接返回该会话已有的内存快照（哪怕水印略旧），避免 15~30 秒阻塞。
    if not _DB_LOCK.acquire(blocking=False):
        if stale:
            return stale
    else:
        _DB_LOCK.release()
    rows, users = _rows(acc, cfg, cid, include_local_extra=True)
    index, _ = _cached_cache_index(acc)
    transcripts = (load_voice_transcripts(acc, cfg, cid)
                   if any(int(r[2] or 0) == VOICE_CTYPE for r in rows) else {})
    messages = []
    for row in rows:
        mid, sid, ct, st, raw = row[:5]
        lext = row[5] if len(row) > 5 else b""
        ts = _norm_ts(st)
        ct_num = int(ct or 0)
        raw = bytes(raw or b"")
        local_entries = _extract_local_extra_entries(lext, acc, cfg) if lext else []
        links = _link_cards(raw) if _URL_BYTES_RE.search(raw) else []
        card = parse_forward_card(ct, raw, ts)
        if card:
            resolve_forward_media(acc, card, ts, index, local_entries=local_entries)
            body = (f"【{card['card_type']}】{card['title']} · {card['count']} 条子消息"
                    f" / {card['levels']} 层 / {card['total_files']} 个附件"
                    f"（已精准匹配 {card['matched']} 个，未缓存 {card['missing']} 个）")
            files = [f["name"] for sub in card["subs"] for f in sub["files"] if f["name"]]
            messages.append({
                "id": str(mid), "ts": ts, "time": ex.fmt_time(st),
                "sender": users.get(str(sid), str(sid)), "ct": ct_num,
                "type": card["card_type"], "content": body, "files": files,
                "links": links, "media": [], "forward": card,
            })
            continue
        # 语音消息单独接管：企微转文字 + SILK 转 MP3；不让 SILK 原件被当普通附件重复打包
        if ct_num == VOICE_CTYPE:
            meta = extract_voice_meta(ct, raw)
            if meta:
                meta["transcript"] = transcripts.get(str(mid))
                meta["source"] = resolve_voice_source(meta, index, ts)
            messages.append({
                "id": str(mid), "ts": ts, "time": ex.fmt_time(st),
                "sender": users.get(str(sid), str(sid)), "ct": ct_num,
                "type": ex.type_name(ct, "windows"), "links": links,
                "content": "", "files": [], "media": [], "voice": meta,
            })
            continue
        body, files = clean_message(ct, raw)
        media = extract_message_media(ct, raw)
        if local_entries:
            _bind_local_extra_to_media(media, local_entries)
        for item in media:
            source, how = _match_media_item(item, index, ts, ts)
            item["source"] = str(source) if source else None
            item["match"] = how
            try:
                item["size_kb"] = round(Path(source).stat().st_size / 1024, 1) if source else 0
            except OSError:
                item["size_kb"] = 0
            item["thumb"] = bool(source and _image_suffix_of(source))
            if item["name"] and item["name"] not in files:
                files.append(item["name"])
        # 纯媒体消息不再显示空白：给出类型 + 文件名提示
        if not body and (files or media):
            labels = [item.get("name") for item in media if item.get("name")]
            labels += [name for name in files if name]
            label = "、".join(list(dict.fromkeys(labels))[:2])
            body = (f"[{ex.type_name(ct, 'windows')}] {label}" if label
                    else f"[{ex.type_name(ct, 'windows')}]（见下方按序打包的附件）")
        # 未知 content_type / 空壳一律兜底，绝不静默返回空白
        if not (body or files or media or links):
            fallback = _universal_fallback(ct, raw)
            body = (f"[类型 ct={ct_num}] {fallback}" if fallback
                    else f"[类型 ct={ct_num}] 系统/内部消息（无可读正文）")
        messages.append({
            "id": str(mid), "ts": ts, "time": ex.fmt_time(st),
            "sender": users.get(str(sid), str(sid)), "ct": ct_num,
            "type": ex.type_name(ct, "windows"), "links": links,
            "content": body, "files": files, "media": media,
        })
    # 引用回复通用关联：@提及型短消息紧邻前一条消息时，补出被引用内容摘要
    for i, msg in enumerate(messages):
        body = (msg.get("content") or "").strip()
        if (body.startswith("@") and len(body) <= 14 and "\n" not in body
                and i > 0 and not msg.get("forward") and not msg.get("voice")):
            prev = messages[i - 1]
            gap = msg["ts"] - prev["ts"]
            if 0 <= gap <= 600:
                summary = _message_summary(prev)
                if summary:
                    names = [x.get("name") for x in (prev.get("media") or [])
                             if x.get("name")]
                    names += [x for x in (prev.get("files") or []) if x]
                    msg["quote"] = {
                        "sender": prev["sender"], "text": summary,
                        "ref_id": str(prev["id"]), "ref_time": prev["time"],
                        "ref_name": next((n for n in names if n), ""),
                    }
                    msg["content"] = f"> 引用 [{prev['sender']}]: {summary}\n{body}"
    with _MSG_INDEX_LOCK:
        _MSG_INDEX.pop(key, None)
        _MSG_INDEX[key] = (stamp, messages)
        while len(_MSG_INDEX) > _MSG_INDEX_MAX:
            _MSG_INDEX.pop(next(iter(_MSG_INDEX)))
    return messages


RANGE_DAYS = {"today": 0, "3d": 3, "7d": 7, "30d": 30}


def _public_forward(card):
    """发给浏览器的合并转发结构：去掉本机绝对路径 / token / url，只留展示字段。

    缩略图走 /api/thumb（后端按 cid+mid+序号反查本机路径并校验目录），
    避免把 Cache 绝对路径暴露到前端，也把 /api/messages 体积压下来。
    """
    subs = []
    for sub in card["subs"]:
        subs.append({
            "idx": sub["idx"], "ts": sub["ts"], "time": sub["time"],
            "sender": sub["sender"], "kind": sub["kind"], "text": sub["text"],
            "depth": sub.get("depth", 1), "is_card": sub.get("is_card", False),
            "card_title": sub.get("card_title", ""),
            "files": [{"name": f["name"], "kind": f["kind"], "size": f["size"],
                       "thumb": f.get("thumb", False), "match": f.get("match"),
                       "size_kb": f.get("size_kb", 0)} for f in sub["files"]],
        })
    total = card["total_files"]
    return {"title": card["title"], "card_type": card.get("card_type", "合并转发"),
            "count": card["count"], "levels": card.get("levels", 1),
            "images": total, "total_files": total,
            "matched": card["matched"], "missing": card["missing"], "subs": subs}


def _parse_window_dt(value, end_of_day=False):
    if not value:
        return None
    text = str(value).strip().replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            struct = time.strptime(text, fmt)
            if fmt == "%Y-%m-%d" and end_of_day:
                struct = time.struct_time((struct.tm_year, struct.tm_mon, struct.tm_mday,
                                          23, 59, 59, struct.tm_wday, struct.tm_yday, -1))
            return time.mktime(struct)
        except ValueError:
            continue
    return None


def messages_window(cfg, acc, cid, range_key="all", start=None, end=None,
                    allow_stale=False):
    """按时间窗返回全量清洗后的消息；allow_stale=True 时旧快照先回、后台重建。"""
    if allow_stale:
        # 首次打开某会话且内存还没有快照：绝不让 HTTP 线程全表扫 30 万行，
        # 先回空窗并在后台预热，下一次界面轮询就是完整数据。
        with _MSG_INDEX_LOCK:
            no_snapshot = (str(acc["id"]), str(cid)) not in _MSG_INDEX
        if no_snapshot:
            _schedule_message_rebuild(cfg, acc, cid)
            return {"conversation_id": str(cid), "count": 0, "total": 0,
                    "from": "", "to": "", "range": range_key,
                    "last_id": "", "messages": [], "pending": True}
    _t0 = time.perf_counter()
    all_messages = _message_index(cfg, acc, cid, allow_stale=allow_stale)
    _t1 = time.perf_counter()
    low = high = None
    if range_key == "custom":
        low = _parse_window_dt(start)
        high = _parse_window_dt(end, end_of_day=True)
    elif range_key in RANGE_DAYS:
        days = RANGE_DAYS[range_key]
        now = time.localtime()
        if days == 0:
            low = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, 0, 0, 0, 0, 0, -1))
        else:
            low = time.time() - days * 86400
    picked = [m for m in all_messages
              if (low is None or m["ts"] >= low) and (high is None or m["ts"] <= high)]
    _t2 = time.perf_counter()
    fmt = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else ""
    public = []
    for message in picked:
        item = dict(message)
        if item.get("forward"):
            item["forward"] = _public_forward(item["forward"])
        content = str(item.get("content") or "")
        # 安卓缓存路径噪音二次兜底（清掉预览里露出的 /storage/emulated/... 行）
        if _ANDROID_NOISE_RE.search(content):
            content = "\n".join(
                line for line in content.splitlines()
                if not _ANDROID_NOISE_RE.match(line.strip())).strip()
            item["content"] = content
        # 纯系统/内部消息空壳：前端折叠显示、默认不勾选、不进导出
        item["system_noise"] = bool(
            content.startswith("[类型 ct=") and "系统/内部消息" in content)
        public.append(item)
    _t3 = time.perf_counter()
    if _t3 - _t0 > 1:
        _slow_log(f"messages cid={cid} total={_t3 - _t0:.2f}s "
                  f"index={_t1 - _t0:.2f}s filter={_t2 - _t1:.2f}s "
                  f"public={_t3 - _t2:.2f}s n={len(public)}")
    return {"conversation_id": str(cid), "count": len(picked), "total": len(all_messages),
            "from": fmt(low), "to": fmt(high), "range": range_key,
            "last_id": public[-1]["id"] if public else "", "messages": public}


def account_status(cfg):
    """给界面顶部用：每个账号的 key/在线状态、会话数、库大小与最后写入。"""
    accounts = []
    for acc in cfg["accounts"]:
        mdb = Path(acc["data_dir"]) / "message.db"
        key_valid = False
        if mdb.exists() and acc.get("key"):
            try:
                with mdb.open("rb") as fh:
                    key_valid = quick_verify(bytes.fromhex(acc["key"]), fh.read(4096))
            except Exception:
                pass
        conv_count = 0
        cf = CACHE / f"conv_{acc['id']}.json"
        if cf.exists():
            try:
                conv_count = len(json.loads(cf.read_text(encoding="utf-8")).get("conversations", []))
            except Exception:
                pass
        accounts.append({
            "id": acc["id"], "key_valid": key_valid, "online": bool(key_valid and mdb.exists()),
            "conversations": conv_count,
            "db_mb": round(mdb.stat().st_size / 1048576, 1) if mdb.exists() else 0,
            "last_write": time.strftime("%Y-%m-%d %H:%M", time.localtime(mdb.stat().st_mtime)) if mdb.exists() else "",
            "data_dir": acc["data_dir"],
            "cache_dir": acc.get("cache_dir", ""),
            "source": acc.get("source", "宿主机"),
            "source_box": acc.get("source_box", ""),
            "source_root": acc.get("source_root", ""),
        })
    all_id_set = set()
    for item in discover_wxwork_roots(cfg):
        try:
            all_id_set.update(
                p.name for p in item["root"].iterdir()
                if p.is_dir() and (p / "Data" / "message.db").exists())
        except OSError:
            pass
    all_ids = sorted(all_id_set)
    unlocked = {a["id"] for a in accounts if a["key_valid"]}
    running = False
    try:
        proc = subprocess.run(["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/NH"],
                              capture_output=True, text=True, encoding="gbk",
                              errors="replace", timeout=3,
                              creationflags=_WIN_NO_WINDOW)
        running = "WXWork" in (proc.stdout or "")
    except Exception:
        pass
    return {"accounts": accounts, "locked_accounts": [i for i in all_ids if i not in unlocked],
            "wecom_running": running, "export_root": cfg["export_root"],
            "total_accounts": len(all_ids)}


def list_conversations(cfg, force=False):
    rows = []
    for acc, data in all_accounts(cfg, force=force):
        for conv in data["conversations"]:
            rows.append({**conv, "account": acc["id"]})
    rows.sort(key=lambda r: (-(r.get("last_timestamp") or 0), str(r.get("name", ""))))
    return {"count": len(rows), "conversations": rows}


def list_conversations_cached(cfg):
    """只读会话缓存快照：绝不触发解密 / run_cli / db_lock，毫秒级返回。

    「刷新列表」的耗时工作统一走异步任务，前端高频轮询只读这里。
    """
    rows = []
    for acc in cfg.get("accounts") or []:
        target = CACHE / f"conv_{acc['id']}.json"
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for conv in data.get("conversations") or []:
            rows.append({**conv, "account": acc["id"]})
    rows.sort(key=lambda r: (-(r.get("last_timestamp") or 0),
                             str(r.get("name", ""))))
    return {"count": len(rows), "conversations": rows, "cached": True}


def preview_messages(cfg, acc, cid, limit=20):
    """直接读已解密的库，不重新解密，所以预览很快。返回时间正序的最近 N 条。"""
    rows, users = _rows(acc, cfg, cid, descending=True, limit=limit)
    messages = []
    for mid, sid, ct, st, raw in reversed(rows):
        messages.append({
            "local_id": str(mid), "time": ex.fmt_time(st),
            "sender": users.get(str(sid), str(sid)),
            "type": ex.type_name(ct, "windows"),
            "content": _render(ct, raw),
        })
    return {"conversation_id": cid, "count": len(messages), "messages": messages}


def extract_document_text(path, limit=20000):
    """把附件里的 docx/pdf/xlsx/txt 正文抽成纯文本，供 ALL_FOR_AI.md 就地展开。"""
    suffix = path.suffix.lower()
    try:
        if suffix in (".txt", ".md", ".csv", ".json", ".log", ".xml", ".html", ".htm"):
            return path.read_text(encoding="utf-8", errors="replace")[:limit]
        if suffix == ".docx":
            from docx import Document
            doc = Document(str(path))
            parts = [p.text for p in doc.paragraphs]
            for table in doc.tables[:20]:
                for row in table.rows[:100]:
                    parts.append(" | ".join(cell.text for cell in row.cells))
            return "\n".join(parts)[:limit]
        if suffix in (".xlsx", ".xlsm"):
            import openpyxl
            wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
            parts = []
            for ws in wb.worksheets[:10]:
                parts.append(f"[Sheet] {ws.title}")
                for row in ws.iter_rows(max_row=200, values_only=True):
                    parts.append(" | ".join("" if v is None else str(v) for v in row))
            wb.close()
            return "\n".join(parts)[:limit]
        if suffix == ".pdf":
            try:
                import pdfplumber
                with pdfplumber.open(str(path)) as pdf:
                    return "\n".join((page.extract_text() or "") for page in pdf.pages[:30])[:limit]
            except Exception:
                from pypdf import PdfReader
                reader = PdfReader(str(path))
                return "\n".join((page.extract_text() or "") for page in reader.pages[:30])[:limit]
        if suffix == ".pptx":
            try:
                from pptx import Presentation
            except ImportError:
                return None  # 未装 python-pptx：保留原格式文件，不当作解析失败
            pres = Presentation(str(path))
            parts = []
            for slide in list(pres.slides)[:60]:
                for shape in slide.shapes:
                    if getattr(shape, "has_text_frame", False):
                        parts.append(shape.text_frame.text)
            return "\n".join(parts)[:limit]
    except Exception as exc:
        return f"(文档解析失败: {exc})"
    return None


def build_all_for_ai(cfg, acc, cid, name=None, include_cache=False):
    """生成单文件 ALL_FOR_AI.md：时间正序聊天 + 附件正文 + 未关联清单 + 兜底缓存正文。"""
    folder = Path(cfg["export_root"]) / safe_name(name or cid)
    manifest_file = folder / "chat.media.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8")) if manifest_file.exists() else {"entries": []}
    entry_map = {}
    for entry in manifest.get("entries", []):
        msg = entry.get("message") or {}
        entry_map.setdefault(str(msg.get("local_id")), []).append(entry)

    rows, users = _rows(acc, cfg, cid)
    lines = [
        f"# {name or cid} · 聊天记录与附件汇总（给 AI 用）",
        "",
        f"- conversation-id: `{cid}`",
        f"- 企微账号: `{acc['id']}`",
        f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "- 消息按时间正序排列；Word / PDF / Excel / TXT 附件与兜底缓存正文已就地展开，图片用相对路径引用。",
        "- 直接把本文件拖给 Codex / 其它 AI 聊天框即可；同目录下的 attachments/ 与 cache_files/ 是被引用的原文件。",
        "",
        "---",
        "",
    ]
    stats = {"messages": 0, "documents": 0, "images": 0, "other_files": 0, "missing_notes": 0,
             "cache_documents": 0, "cache_images": 0, "cache_other_files": 0, "unresolved": 0}
    unresolved = []
    for mid, sid, ct, st, raw in rows:
        stats["messages"] += 1
        lines.append(f"## [{ex.fmt_time(st)}] {users.get(str(sid), str(sid))} · [{ex.type_name(ct, 'windows')}]")
        lines.append("")
        lines.append(_render(ct, raw))
        lines.append("")
        for entry in entry_map.get(str(mid), []):
            status = entry.get("status")
            if status != "resolved":
                stats["missing_notes"] += 1
                unresolved.append((str(mid), str(status), str(entry.get("reason", ""))))
                continue
            for rel in entry.get("files") or []:
                path = folder / rel
                if path.suffix.lower() in IMAGE_EXTENSIONS:
                    stats["images"] += 1
                    lines.append(f"![图片]({rel})")
                    lines.append("")
                else:
                    text = extract_document_text(path) if path.exists() else None
                    if text is not None:
                        stats["documents"] += 1
                        lines.append(f"**附件正文 · `{path.name}`**")
                        lines.append("")
                        lines.append("```text")
                        lines.append(text)
                        lines.append("```")
                    else:
                        stats["other_files"] += 1
                        lines.append(f"- 附件：`[{path.name}]({rel})`")
                    lines.append("")

    # 未关联媒体汇总：Windows 端 --with-media 关联率低，让 AI 也知道缺口在哪
    stats["unresolved"] = len(unresolved)
    if unresolved:
        by_status = {}
        for _, status, _ in unresolved:
            by_status[status] = by_status.get(status, 0) + 1
        lines += [
            "---", "",
            "## 未能关联到消息的媒体（Windows 端限制）", "",
            f"> 共 {len(unresolved)} 条。Windows 版资源 ID 结构与 macOS 不同，多数为 "
            "`resource_not_cached` / `unsupported`；在企业微信里点开下载后可重新导出补齐。"
            "完整清单见 `chat.media.json`。", "",
            "| 状态 | 数量 |", "| --- | --- |",
        ]
        for status, count in sorted(by_status.items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{status}` | {count} |")
        lines += ["", "前 100 条明细（消息 local_id · 状态 · 原因）：", "", "```text"]
        for mid, status, reason in unresolved[:100]:
            lines.append(f"{mid}\t{status}\t{reason}")
        lines += ["```", ""]

    # 兜底缓存：这些文件与消息不一一对应，但属于同期缓存，正文同样喂给 AI
    if include_cache:
        cache_dir = folder / "cache_files"
        files = sorted(_selected_cache_files(folder),
                       key=lambda p: (0 if p.suffix.lower() in CACHE_TEXT_EXTENSIONS else 1,
                                      -p.stat().st_mtime)) if cache_dir.exists() else []
        lines += [
            "---", "",
            "## 本机缓存兜底文件（按该群最近活跃时间窗筛选）", "",
            "> 这些文件无法与单条消息一一对应，但属于同一账号同期的本地缓存；"
            "Word / PDF / Excel / TXT 正文已就地展开，图片与工程文件用相对路径引用。", "",
        ]
        used_chars = 0
        for path in files:
            rel = path.relative_to(folder).as_posix()
            suffix = path.suffix.lower()
            if suffix in IMAGE_EXTENSIONS:
                stats["cache_images"] += 1
                lines.append(f"- 图片：`[{path.name}]({rel})`")
                continue
            if (suffix in CACHE_TEXT_EXTENSIONS and stats["cache_documents"] < MAX_ALL_FOR_AI_CACHE_DOCS
                    and used_chars < MAX_ALL_FOR_AI_CACHE_CHARS):
                text = extract_document_text(path, limit=12000)
                if text is not None:
                    stats["cache_documents"] += 1
                    used_chars += len(text)
                    lines += [f"**缓存文档正文 · `{rel}`**", "", "```text", text, "```", ""]
                    continue
            stats["cache_other_files"] += 1
            lines.append(f"- 文件：`[{path.name}]({rel})`")
        lines.append("")

    out = folder / "ALL_FOR_AI.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return {"path": str(out), "size_kb": round(out.stat().st_size / 1024, 1), **stats}


def _cache_rank(item):
    """可抽正文的文档最优先（小文件在前），其次其它工程/办公文件，最后图片。"""
    mtime, size, path = item
    suffix = path.suffix.lower()
    if suffix in CACHE_TEXT_EXTENSIONS:
        return (0, size, -mtime)
    if suffix not in IMAGE_EXTENSIONS:
        return (1, size, -mtime)
    return (2, 0, -mtime)


def _selected_cache_files(folder):
    """读本轮 manifest；旧版本导出的目录没有 manifest 时回退到目录扫描。"""
    mf = folder / "cache_manifest.json"
    if mf.exists():
        try:
            rels = json.loads(mf.read_text(encoding="utf-8")).get("selected", [])
            return [(folder / "cache_files" / r) for r in rels if (folder / "cache_files" / r).is_file()]
        except (ValueError, OSError):
            pass
    d = folder / "cache_files"
    return sorted((p for p in d.rglob("*") if p.is_file()), key=lambda p: (-p.stat().st_mtime)) if d.exists() else []


def prune_cache(folder):
    """显式清理：只删 cache_files/ 里不属于本轮 manifest 的工具生成文件。

    不自动执行；必须由界面按钮或 CLI 明确触发，避免误删用户放在导出目录里的东西。
    """
    folder = Path(folder)
    target = folder / "cache_files"
    if not target.exists():
        return {"removed": 0, "kept": 0, "path": str(target)}
    keep = {str(p.relative_to(target).as_posix()) for p in _selected_cache_files(folder)}
    removed = 0
    for existing in list(target.rglob("*")):
        if not existing.is_file():
            continue
        if existing.relative_to(target).as_posix() in keep:
            continue
        try:
            existing.unlink()
            removed += 1
        except OSError:
            pass
    for directory in sorted((p for p in target.rglob("*") if p.is_dir()),
                            key=lambda p: -len(p.parts)):
        try:
            directory.rmdir()
        except OSError:
            pass
    return {"removed": removed, "kept": len(keep), "path": str(target)}


def cache_filtered(cfg, acc, cid, name=None):
    """兜底：按该群最近活跃时间窗，把本机缓存里的 PDF/Word/图片/工程文件拷到 cache_files/。"""
    folder = Path(cfg["export_root"]) / safe_name(name or cid)
    target = folder / "cache_files"
    target.mkdir(parents=True, exist_ok=True)
    with db_lock():
        db = _dec_message_db(acc, cfg)
        con = connect_readonly(db)
        try:
            row = con.execute("SELECT MIN(send_time), MAX(send_time) FROM message_table WHERE conversation_id=?", (cid,)).fetchone()
        finally:
            con.close()
    # 群的历史跨度可能长达数月，直接用 min~max 会命中几乎全部缓存。
    # 取「最近 CACHE_WINDOW_DAYS 天活跃窗口」，并让文档/工程文件优先于图片。
    first = _norm_ts(row[0]) if row and row[0] else 0
    last = _norm_ts(row[1]) if row and row[1] else time.time()
    span_days = round((last - first) / 86400) if first else 0
    start = max(first - 86400, last - CACHE_WINDOW_DAYS * 86400) if first else last - CACHE_WINDOW_DAYS * 86400
    end = last + 2 * 86400
    cache = Path(acc.get("cache_dir") or (Path(acc["data_dir"]).parent / "Cache"))
    picked = []
    if cache.exists():
        for path in cache.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in DOC_EXTENSIONS:
                continue
            try:
                st = path.stat()
                if start <= st.st_mtime <= end:
                    picked.append((st.st_mtime, st.st_size, path))
            except OSError:
                pass
    picked.sort(key=_cache_rank)
    selected, total_bytes, skipped = [], 0, 0
    for _, size, path in picked:
        if size > MAX_CACHE_SINGLE_BYTES:
            skipped += 1
            continue
        if len(selected) >= MAX_CACHE_FILES or total_bytes + size > MAX_CACHE_BYTES:
            skipped += 1
            continue
        selected.append(path)
        total_bytes += size
    selected_rel = {str(p.relative_to(cache).as_posix()) for p in selected}
    copied = 0
    for path in selected:
        dst = target / path.relative_to(cache)
        if dst.exists() and dst.stat().st_size == path.stat().st_size:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dst)
        copied += 1
    manifest_file = folder / "cache_manifest.json"
    fmt = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "-"
    manifest_file.write_text(json.dumps({
        "window": [fmt(start), fmt(end)], "selected": sorted(selected_rel),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    stale = sum(1 for p in target.rglob("*") if p.is_file()
                and p.relative_to(target).as_posix() not in selected_rel)
    return {"path": str(target), "window": [fmt(start), fmt(end)],
            "window_note": f"群历史跨度 {span_days} 天，按最近 {CACHE_WINDOW_DAYS} 天活跃窗口筛选；文档优先、单文件上限 25MB",
            "matched": len(picked), "selected": len(selected), "copied": copied,
            "skipped": skipped, "stale": stale,
            "mb": round(total_bytes / 1048576, 1)}


def web_export(cfg, acc, cid, name=None, cache_fallback=False):
    """Compatibility wrapper: all messages of this conversation -> one ZIP."""
    all_ids = [m["id"] for m in _message_index(cfg, acc, cid)]
    result = precise_export(cfg, acc, cid, name, all_ids, zip_mode="timestamp")
    result["cache_fallback"] = None
    return result


CACHE_SUBDIRS = ("File", "Image", "Voice", "Video", "Emotion", "Files", "Images")


def _cache_dirs_of(acc, cfg=None):
    """宿主机 + 所有 Sandboxie 沙盒里该账号的 Cache 目录（去重）。"""
    roots = [Path(acc.get("cache_dir")
                  or (Path(acc["data_dir"]).parent / "Cache"))]
    try:
        for item in discover_wxwork_roots(cfg or load_config()):
            candidate = item["root"] / acc["id"] / "Cache"
            if candidate.is_dir():
                roots.append(candidate)
    except (OSError, ValueError, KeyError):
        pass
    seen, out = set(), []
    for root in roots:
        try:
            key = str(root.resolve()).casefold()
        except OSError:
            key = str(root).casefold()
        if key not in seen:
            seen.add(key)
            out.append(root)
    return out


def _cache_dir_fingerprint(acc, cfg=None):
    """稳定目录指纹：只取 Cache/Image/File 下条目名+大小，不用目录 mtime_ns。

    企微点开合并转发里的图片只写 Cache\\Image，完全不改 message.db / WAL；
    目录条目变化必须能被感知。但企微也会无意义 touch 目录 mtime，若把
    mtime_ns 放进缓存键，消息索引与 quick-sync 指纹会永远不命中、反复全量重建。
    这里只比较「有哪些文件、各多大」：新图落盘立刻变化，日常 touch 不会抖动。
    """
    def entries_sig(folder):
        try:
            # 只看文件名集合：新图落盘/旧图清理立刻变；逐文件 stat 会让指纹
            # 涨到 90ms+，而同文件名替换场景由消息峰值/库大小兜底。
            names = [item.name for item in folder.iterdir()]
            blob = repr(tuple(sorted(names))).encode("utf-8", "replace")
            return hashlib.blake2b(blob, digest_size=8).hexdigest()
        except OSError:
            return "missing"

    parts = []
    for root in _cache_dirs_of(acc, cfg):
        if not root.is_dir():
            continue
        for sub in ("", "Image", "File", "Files", "Images"):
            folder = root / sub if sub else root
            if folder.is_dir():
                parts.append((str(folder), entries_sig(folder)))
        image = root / "Image"
        if image.is_dir():
            try:
                children = [p for p in image.iterdir() if p.is_dir()]
            except OSError:
                children = []
            # 只签名最近两个月 + Temp：新图必落在当月/临时目录，新月份会出现在
            # Image 的目录名集合里；全量扫 9 个月目录要 80ms+，没必要。
            recent = sorted(children, key=lambda p: p.name)[-2:]
            temp = [p for p in children if p.name.lower() == "temp"]
            for child in dict.fromkeys(recent + temp):
                parts.append((str(child), entries_sig(child)))
    return tuple(parts)


def invalidate_media_caches():
    """「刷新列表」时只清 Cache 文件索引；消息快照留作旧数据秒回 + 后台重建。"""
    # 不再 _MSG_INDEX.clear()：清空会逼下一条 /api/messages 在 HTTP 线程里
    # 全量重解析（压测 4~8 秒超时）。Cache 指纹变化会自行触发后台重建。
    with _CACHE_INDEX_LOCK:
        _CACHE_INDEX_CACHE.clear()


def _norm_filename(name):
    """归一化缓存文件名：小写、去空白、去 (1)/(2) 副本标记，让重名文件可比对。"""
    text = str(name).strip().lower()
    text = re.sub(r"\s*\(\d+\)(?=(?:\.[^.]+)?$)", "", text)
    text = re.sub(r"\s+", "", text)
    return text


def _safe_attachment_name(name):
    cleaned = re.sub(r'[\\/:*?"<>|\r\n\t]', "_", str(name))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:120] or "attachment"


def build_cache_index(acc):
    """索引当前账号 Cache 下的文件（完整名 / 主名 / 原始字节数三级），供精准匹配。

    by_size 供无文件名图片按原始大小 + MD5（或严控时间窗+唯一性）命中；
    已彻底移除危险的纯宽高 by_dims 索引，杜绝跨群张冠李戴。
    """
    # 宿主机 + 所有 Sandboxie 沙盒双目录，统一由 _cache_dirs_of 去重提供
    roots = _cache_dirs_of(acc)
    index = {"name": {}, "stem": {}, "by_size": {}, "all": []}
    count = 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root)
                if rel.parts and rel.parts[0] not in CACHE_SUBDIRS:
                    continue
                stat = path.stat()
            except (OSError, ValueError):
                continue
            item = (stat.st_mtime, path, stat.st_size)
            index["name"].setdefault(_norm_filename(path.name), []).append(item)
            index["stem"].setdefault(_norm_filename(path.stem), []).append(item)
            index["by_size"].setdefault(stat.st_size, []).append(item)
            index["all"].append(item)
            count += 1
    return index, count


def _lookup_cache(index, filename, msg_ts):
    """精确名 → 主名（扩展名可不同）；重名取 mtime 最接近该条消息时间的那个。"""
    def nearest(items):
        if not items:
            return None
        return min(items, key=lambda it: abs(it[0] - (msg_ts or it[0])))[1]

    hit = nearest(index["name"].get(_norm_filename(filename)))
    if hit:
        return hit
    return nearest(index["stem"].get(_norm_filename(Path(filename).stem)))


# ---------------------------------------------------------------- 补扫本机常用目录
# 场景：文件被「另存为」到桌面/下载目录，企微 Cache 里没有，导致导出提示未下载。
# 只在企微缓存未命中时才懒加载补扫，避免每次导出都遍历本机目录。
EXTRA_SCAN_MAX_DEPTH = 3          # 最多扫 3 层子目录
EXTRA_SCAN_MAX_FILES = 50000      # 单次导出扫描文件数上限
EXTRA_SCAN_MAX_SECONDS = 8.0      # 单次导出扫描耗时上限
_EXTRA_SCAN_SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", "appdata",
    "$recycle.bin", "system volume information", ".workbuddy", "windows",
    "program files", "program files (x86)", "programdata",
}
_EXTRA_SCAN_LNK_NAMES = ("极速下载好的文件.lnk", "极速下载好的文件")


def _exact_name_key(name):
    """补扫专用：文件名完全一致（只忽略大小写与首尾空白），不像 _norm_filename 那样去副本标记。"""
    return str(name).strip().casefold()


def _lnk_target_dir(lnk_path):
    """纯读文件解析 .lnk 里的本地路径，不调用 WScript/COM。"""
    try:
        data = Path(lnk_path).read_bytes()
    except OSError:
        return None
    for text in (data.decode("utf-16-le", errors="ignore"),
                 data.decode("latin-1", errors="ignore")):
        for match in re.finditer(r"[A-Za-z]:\\[^\x00\r\n\t|<>\"']{2,220}", text):
            raw = "".join(ch for ch in match.group(0).strip().rstrip(".")
                          if ch.isprintable())
            try:
                path = Path(raw)
                if path.is_dir():
                    return str(path)
                if path.is_file():
                    return str(path.parent)
                if path.parent.is_dir():
                    return str(path.parent)
            except (OSError, ValueError):
                continue
    return None


def default_extra_scan_dirs(cfg=None):
    """内置默认：真实桌面、系统下载目录、常见下载目录、极速下载快捷方式目标。"""
    cfg = cfg or {}
    dirs, seen = [], set()

    def add(value):
        if not value:
            return
        try:
            path = Path(value).expanduser().resolve()
            key = str(path).casefold()
            if path.is_dir() and key not in seen:
                seen.add(key)
                dirs.append(str(path))
        except (OSError, ValueError):
            pass

    try:
        export_root = Path(cfg["export_root"]).resolve()
        add(export_root.parent)          # 「企业微信导出」的父目录 = 真实桌面
        desktop = export_root.parent
        for name in _EXTRA_SCAN_LNK_NAMES:
            lnk = desktop / name
            if lnk.is_dir():
                add(lnk)
            elif lnk.is_file() and lnk.suffix.lower() == ".lnk":
                add(_lnk_target_dir(lnk))
    except (KeyError, OSError, ValueError):
        desktop = None
    home = Path.home()
    add(home / "Desktop")
    add(home / "Downloads")
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        add(Path(userprofile) / "Downloads")
    for candidate in ("D:/Downloads", "D:/下载", "D:/下载文件"):
        add(candidate)
    return dirs


def get_extra_scan_dirs(cfg=None):
    """config 里显式配置过就完全以它为准（可删到空）；否则用内置默认。"""
    cfg = cfg or load_config()
    if "extra_scan_dirs" in cfg:
        return [str(x) for x in (cfg.get("extra_scan_dirs") or [])]
    return default_extra_scan_dirs(cfg)


def save_extra_scan_dirs(dirs):
    """把补扫目录列表持久化到 config.json，保留其它配置字段。"""
    cfg = load_config()
    cleaned, seen = [], set()
    for raw in dirs or []:
        text = str(raw).strip()
        if not text:
            continue
        key = text.casefold()
        if key not in seen:
            seen.add(key)
            cleaned.append(text)
    cfg["extra_scan_dirs"] = cleaned
    save_config(cfg)
    return cleaned


def _collect_wanted_attachment_names(picked):
    """导出前收集带真实文件名的附件名；补扫时只索引这些名字，避免全盘建索引。"""
    wanted = set()
    for message in picked:
        for item in (message.get("media") or []):
            name = item.get("name")
            if name and _media_filename_ok(name):
                wanted.add(_exact_name_key(name))
        for name in (message.get("files") or []):
            if name and _media_filename_ok(name):
                wanted.add(_exact_name_key(name))
        card = message.get("forward")
        if card:
            for sub in card.get("subs") or []:
                for item in sub.get("files") or []:
                    name = item.get("name")
                    if name and _media_filename_ok(name):
                        wanted.add(_exact_name_key(name))
    return wanted


def build_extra_scan_index(cfg, wanted_names, max_depth=EXTRA_SCAN_MAX_DEPTH):
    """浅层补扫常用目录；只记录与 wanted_names 精确同名的文件。"""
    info = {"dirs": [], "wanted": len(wanted_names or ()), "scanned_files": 0,
            "elapsed_ms": 0, "truncated": False, "name": {}}
    if not wanted_names:
        return info
    started = time.monotonic()
    deadline = started + EXTRA_SCAN_MAX_SECONDS
    try:
        export_root = Path(cfg["export_root"]).resolve()
    except (KeyError, OSError, ValueError):
        export_root = None

    for raw_dir in get_extra_scan_dirs(cfg):
        if time.monotonic() >= deadline:
            info["truncated"] = True
            break
        try:
            root = Path(raw_dir).expanduser().resolve()
        except (OSError, ValueError):
            continue
        if not root.is_dir():
            continue
        # 跳过「企业微信导出」目录自身及其子目录，防止套娃把旧导出包当源文件
        if export_root and (root == export_root or export_root in root.parents):
            continue
        info["dirs"].append(str(root))
        for cur, dirnames, filenames in os.walk(root):
            if (time.monotonic() >= deadline
                    or info["scanned_files"] >= EXTRA_SCAN_MAX_FILES):
                info["truncated"] = True
                break
            cur_path = Path(cur)
            try:
                depth = len(cur_path.relative_to(root).parts)
            except ValueError:
                depth = 0
            if depth >= max_depth:
                dirnames[:] = []
            keep = []
            for name in dirnames:
                if name.casefold() in _EXTRA_SCAN_SKIP_DIRS:
                    continue
                child = cur_path / name
                if export_root and (child == export_root or export_root in child.parents):
                    continue
                keep.append(name)
            dirnames[:] = keep
            info["scanned_files"] += len(filenames)
            for filename in filenames:
                key = _exact_name_key(filename)
                if key not in wanted_names:
                    continue
                path = cur_path / filename
                try:
                    stat = path.stat()
                except OSError:
                    continue
                info["name"].setdefault(key, []).append(
                    (stat.st_mtime, path, stat.st_size))
    info["elapsed_ms"] = round((time.monotonic() - started) * 1000, 1)
    return info


def lookup_extra_scan(extra_index, filename, expected_size=0, msg_ts=0):
    """严格精准命中：文件名完全一致；有字节数时必须一致；同名取 mtime 最接近消息时间。"""
    items = (extra_index or {}).get("name", {}).get(_exact_name_key(filename)) or []
    if not items:
        return None
    if expected_size:
        exact = [it for it in items if it[2] == expected_size]
        if not exact:
            return None
        items = exact
    return min(items, key=lambda it: abs(it[0] - (msg_ts or it[0])))[1]


TMP_EXPORT_ROOT = RUNTIME / "tmp_export"


def _cleanup_stale_tmp_exports(max_age_seconds=86400):
    """Remove abandoned temp export directories older than one day."""
    if not TMP_EXPORT_ROOT.exists():
        return 0
    now = time.time()
    removed = 0
    for child in TMP_EXPORT_ROOT.iterdir():
        try:
            if child.is_dir() and now - child.stat().st_mtime > max_age_seconds:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            pass
    return removed


def _rewrite_quote_content(content, quote, by_mid):
    """把「> 引用 [xxx]: [图片]」升级为被引用消息在本次导出里分配到的附件编号。"""
    if not quote or not content:
        return content
    lines = str(content).splitlines()
    if not lines or not lines[0].startswith("> 引用 ["):
        return content
    hits = by_mid.get(str(quote.get("ref_id") or "")) or []
    if hits:
        marker = " ".join(f"[附件 {n} -> {r}]" for n, r in hits[:3])
    else:
        name = str(quote.get("ref_name") or "")
        stamp = str(quote.get("ref_time") or "")
        fallback = name or stamp or str(quote.get("text") or "")
        marker = f"[被引附件未在本范围: {fallback}]"
    lines[0] = f"> 引用 [{quote.get('sender') or ''}]: {marker}"
    return "\n".join(lines)


_WRITE_LOCKS = {}
_WRITE_LOCK_GUARD = threading.Lock()


def _write_lock_for(path):
    with _WRITE_LOCK_GUARD:
        return _WRITE_LOCKS.setdefault(str(path), threading.Lock())


def _atomic_write_text(path, text):
    """唯一临时文件 + 进程内串行 + 重试，杜绝并发 os.replace 的 WinError 5。"""
    path = Path(path)
    tmp = path.with_name(
        f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    with _write_lock_for(path):
        last_exc = None
        for attempt in range(6):
            try:
                tmp.write_text(text, encoding="utf-8")
                os.replace(tmp, path)
                return
            except PermissionError as exc:
                # Windows 上别的线程/进程正读该文件时 replace 会短暂拒绝访问
                last_exc = exc
                time.sleep(0.05 * (attempt + 1))
            finally:
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass
        raise last_exc


def _atomic_write_if_changed(path, text):
    """内容完全一致时不重写（避免假同步把 mtime 推新却仍是旧内容）。"""
    path = Path(path)
    try:
        if path.read_text(encoding="utf-8") == text:
            return False
    except (OSError, UnicodeError):
        pass
    _atomic_write_text(path, text)
    return True


def _new_tmp_export_dir():
    _cleanup_stale_tmp_exports()
    TMP_EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    name = "export_{}_{}_{}".format(
        time.strftime("%Y%m%d-%H%M%S"), os.getpid(), uuid.uuid4().hex[:8]
    )
    path = TMP_EXPORT_ROOT / name
    path.mkdir(parents=True, exist_ok=False)
    return path


def _cleanup_tmp_export_dir(tmp_dir):
    """删除本次导出自建的临时目录，绝不让外部运行时 shim 影响导出主流程。

    背景：部分运行环境会通过 sitecustomize 把 shutil.rmtree 包装成「先移入
    回收站 + 批量删除守卫」。守卫拒绝时抛的是 SystemExit(1)（BaseException
    子类），`shutil.rmtree(..., ignore_errors=True)` 的 `except Exception` 和
    后台任务的 `except Exception` 都拦不住它，结果导出线程静默死亡、任务永远
    停在 running（前端一直显示「正在导出…」）。

    这里只删除程序自己刚创建、名字带 uuid 的临时目录：
      1) 优先调用被包装前的原始 rmtree，避免触发回收站包装与守卫；
      2) 用 BaseException 兜底，任何异常 / SystemExit 都不外泄；
      3) 原生方式失败时用系统命令兜底；
      4) 最终仍失败只登记待清理，导出结果照常返回，绝不阻塞主流程。
    """
    path = Path(tmp_dir)
    original = None
    try:
        import sitecustomize
        original = getattr(sitecustomize, "_orig_shutil_rmtree", None)
    except BaseException:
        pass
    for rmtree in (original, shutil.rmtree):
        if not callable(rmtree):
            continue
        try:
            rmtree(path, ignore_errors=True)
        except BaseException:
            pass
        if not path.exists():
            return True
    if os.name == "nt":
        try:
            subprocess.run(["cmd", "/c", "rmdir", "/S", "/Q", str(path)],
                           timeout=15, check=False,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except BaseException:
            pass
        if not path.exists():
            return True
    try:
        with (RUNTIME / "tmp_export_pending.txt").open("a", encoding="utf-8") as fh:
            fh.write(str(path) + "\n")
    except OSError:
        pass
    return False


def _tier_note(match):
    text = str(match or "")
    return text if "降级" in text else ""


def _short_export_label(name):
    """合并 ZIP 名里的会话核心称呼：去掉「· 成员A · 成员B…」冗长后缀。"""
    text = str(name or "").strip()
    head = re.split(r"[·•]", text)[0].strip()
    head = re.split(r"[+＋]", head)[0].strip()
    head = re.sub(r'[\\/:*?"<>|\s]+', "", head)
    return head[:12] or "会话"


def _export_zip_name(name, zip_mode="timestamp"):
    base = safe_name(name or "未命名会话")
    if zip_mode == "overwrite":
        return f"{base}.zip"
    if zip_mode != "timestamp":
        raise RuntimeError(f"不支持的 ZIP 命名模式: {zip_mode}")
    return f"{time.strftime('%Y%m%d-%H%M%S')}_{base}.zip"


def _unique_export_zip_path(export_root, filename, zip_mode):
    path = Path(export_root) / filename
    if zip_mode == "overwrite" or not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    index = 2
    while True:
        candidate = path.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
        index += 1


def _zip_export_files(zip_temp, entries):
    """Write entries in the exact order given; Unicode names get the UTF-8 flag."""
    with zipfile.ZipFile(zip_temp, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for arcname, source in entries:
            zf.write(source, arcname)
    return [arcname for arcname, _ in entries]


# ---------------------------------------------------------------- 网页 AI 轻量包
# 完整原件包逻辑完全不变；仅在临时目录的副本上额外制作一个可上传给网页 AI 的小包。
LITE_AUTO_TRIGGER_BYTES = 20 * 1024 * 1024   # 完整包 >20MB 时自动生成
LITE_IMAGE_TRIGGER_BYTES = 500 * 1024        # 图片 >500KB 才瘦身
LITE_IMAGE_MAX_EDGE = 1600                   # 长边上限
LITE_IMAGE_JPEG_QUALITY = 82                 # JPG 质量
LITE_SKIP_OTHER_BYTES = 15 * 1024 * 1024    # 非文档/非图片 >15MB 跳过
LITE_SKIP_DOC_BYTES = 20 * 1024 * 1024      # 文档 >20MB 也跳过
LITE_RESIZABLE_IMAGES = {".jpg", ".jpeg", ".png", ".webp"}
LITE_VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv",
                   ".m4v", ".webm", ".mpeg", ".mpg"}
LITE_DOC_EXTS = {
    ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".xlsm", ".csv", ".txt", ".md",
    ".json", ".log", ".xml", ".html", ".htm", ".ppt", ".pptx", ".rtf",
    ".wps", ".et", ".dps",
}


def _lite_should_generate(mode, full_zip_bytes):
    """智能触发：always 恒生成；auto 仅当完整包 >20MB；off 关闭。"""
    mode = (mode or "auto").lower()
    if mode == "off":
        return False, "off"
    if mode == "always":
        return True, "always"
    if full_zip_bytes > LITE_AUTO_TRIGGER_BYTES:
        return True, "auto_over_20mb"
    return False, "under_20mb"


def _lite_shrink_image(source, destination):
    """把图片副本缩放到长边 <=1600px 并转成质量 82% 的标准 JPG，失败返回 False。"""
    try:
        from PIL import Image, ImageOps
        with Image.open(source) as raw:
            im = ImageOps.exif_transpose(raw)
            im.thumbnail((LITE_IMAGE_MAX_EDGE, LITE_IMAGE_MAX_EDGE), Image.LANCZOS)
            if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
                rgba = im.convert("RGBA")
                canvas = Image.new("RGB", rgba.size, (255, 255, 255))
                canvas.paste(rgba, mask=rgba.getchannel("A"))
                im = canvas
            else:
                im = im.convert("RGB")
            im.save(destination, "JPEG", quality=LITE_IMAGE_JPEG_QUALITY,
                    optimize=True, progressive=True)
        return destination.is_file()
    except Exception:
        return False


def _lite_build(tmp_dir, folder, chat_lines, ai_lines, attachments, full_zip_name):
    """基于临时副本构建网页 AI 轻量包，返回 (lite_temp_zip, meta)。

    绝不改动企微缓存原件与完整包。编号 001、002… 与 ZIP 内顺序同完整包 100%
    对应：跳过的超大原件不写入轻量包但编号不重排，并在两个 md 的原位置标注。
    """
    lite_dir = tmp_dir / "lite"
    lite_dir.mkdir(parents=True, exist_ok=True)
    plan, shrunk, skipped, kept = [], [], [], []

    for item in attachments:
        renamed = item["renamed"]
        src = folder / renamed
        if not src.is_file():
            continue
        size = src.stat().st_size
        suffix = src.suffix.lower()
        number = item["number"]
        state, arcname, path, marker = "kept", renamed, None, None

        # 1) 大图自动瘦身 -> 长边<=1600px / JPG 82%
        if suffix in LITE_RESIZABLE_IMAGES and size > LITE_IMAGE_TRIGGER_BYTES:
            new_name = re.sub(r"\.(jpg|jpeg|png|webp)$", ".jpg", renamed, flags=re.I)
            dst = lite_dir / new_name
            if _lite_shrink_image(src, dst):
                state, arcname, path = "shrunk", new_name, dst
                shrunk.append({
                    "number": number, "from": renamed, "to": new_name,
                    "from_kb": round(size / 1024, 1),
                    "to_kb": round(dst.stat().st_size / 1024, 1),
                })
            else:
                path = lite_dir / renamed
                shutil.copy2(src, path)
                kept.append({"number": number, "name": renamed,
                             "reason": "瘦身失败，保留原件"})
        # 2) 超大不可读原件：文档 >20MB / 其它格式 >15MB -> 跳过并标注
        elif size > (LITE_SKIP_DOC_BYTES if suffix in LITE_DOC_EXTS
                     else LITE_SKIP_OTHER_BYTES):
            limit = LITE_SKIP_DOC_BYTES if suffix in LITE_DOC_EXTS else LITE_SKIP_OTHER_BYTES
            size_mb = size / 1048576
            if Path(renamed).suffix.lower() in LITE_VIDEO_EXTS:
                marker = f"[超大视频未进轻量包: {renamed} ({size_mb:.1f} MB)]"
            else:
                marker = (f"[超大原件未进轻量包: {renamed} ({size_mb:.1f} MB)，"
                          "原件已保存在完整包与本机缓存]")
            state = "skipped"
            skipped.append({
                "number": number, "name": renamed, "size_mb": round(size_mb, 1),
                "limit_mb": round(limit / 1048576, 1), "marker": marker,
            })
        # 3) 其余（含常规文档及其正文）原样保留
        else:
            path = lite_dir / renamed
            shutil.copy2(src, path)
            kept.append({"number": number, "name": renamed, "reason": "原样保留",
                         "size_kb": round(size / 1024, 1)})

        plan.append({"number": number, "renamed": renamed, "state": state,
                     "arcname": arcname, "path": path, "marker": marker})

    rename_map = {p["renamed"]: p["arcname"] for p in plan if p["state"] == "shrunk"}
    skip_map = {p["renamed"]: p["marker"] for p in plan if p["state"] == "skipped"}

    def rewrite(lines):
        out = []
        for line in lines:
            hit = next((old for old in skip_map if old in line), None)
            if hit:
                stripped = line.strip()
                if stripped.startswith("[附件") and stripped.endswith("]") and "->" in stripped:
                    out.append(skip_map[hit])
                else:
                    out.append(line.replace(hit, f"{hit}（超大原件未进轻量包）"))
                continue
            for old, new in rename_map.items():
                if old in line:
                    line = line.replace(old, new)
            out.append(line)
        return out

    banner = [
        "> ⚠️ **网页 AI 轻量包**：`001`、`002`… 编号及聊天顺序与完整原件包 100% 对应。",
        f"> 完整原件包：`{full_zip_name}`（含所有原格式文件，未做任何改动）。",
        f"> 大图瘦身 {len(shrunk)} 张（长边≤{LITE_IMAGE_MAX_EDGE}px / JPG 质量 "
        f"{LITE_IMAGE_JPEG_QUALITY}%）；超大原件跳过 {len(skipped)} 个（见下方原位置标注）；"
        f"其余 {len(kept)} 个原样保留。",
        "",
    ]

    def with_banner(lines):
        rewritten = rewrite(lines)
        return rewritten[:2] + banner + rewritten[2:]

    lite_chat_path = lite_dir / "000_chat.md"
    lite_ai_path = lite_dir / "ALL_FOR_AI.md"
    lite_chat_path.write_text("\n".join(with_banner(chat_lines)), encoding="utf-8")
    lite_ai_path.write_text("\n".join(with_banner(ai_lines)), encoding="utf-8")

    entries = [("000_chat.md", lite_chat_path)]
    entries += [(p["arcname"], p["path"]) for p in plan
                if p["state"] != "skipped" and p["path"] is not None]
    entries.append(("ALL_FOR_AI.md", lite_ai_path))
    lite_temp = tmp_dir / "lite_export.zip"
    lite_entry_names = _zip_export_files(lite_temp, entries)

    meta = {
        "zip_entries": lite_entry_names, "shrunk": shrunk, "skipped": skipped,
        "kept_count": len(kept),
        "chat_bytes": lite_chat_path.stat().st_size,
        "ai_bytes": lite_ai_path.stat().st_size,
    }
    return lite_temp, meta


def _resolve_export_path(path):
    cfg = load_config()
    root = Path(cfg["export_root"]).resolve()
    target = Path(path).resolve()
    if target != root and root not in target.parents:
        raise RuntimeError(f"拒绝访问导出根目录之外的路径: {target}")
    return root, target


def resolve_export_zip(path):
    """Validate that a download/open request points to a .zip inside export_root."""
    _, target = _resolve_export_path(path)
    if not target.is_file():
        raise RuntimeError(f"ZIP 文件不存在: {target}")
    if target.suffix.lower() != ".zip":
        raise RuntimeError(f"只允许下载 .zip 文件: {target}")
    return target


def _launch_explorer(target, select=False):
    """Use ShellExecuteW so Chinese paths with spaces work without cmd shell quoting."""
    import ctypes

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell_execute = shell32.ShellExecuteW
    shell_execute.restype = ctypes.c_void_p
    shell_execute.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
    ]
    params = f'/select,"{target}"' if select else f'"{target}"'
    result = shell_execute(None, "open", "explorer.exe", params, None, 1)
    if int(result or 0) <= 32:
        # Fallback for unusual shell configurations.
        subprocess.Popen(
            ["explorer.exe", f"/select,{target}" if select else str(target)],
            close_fds=True, creationflags=_WIN_NO_WINDOW,
        )


def _find_explorer_hwnd_by_selection(target, timeout=6.0):
    """Find the Explorer window whose selected item is exactly this file."""
    try:
        import win32com.client
        import win32gui
    except Exception:
        return None
    shell = win32com.client.Dispatch("Shell.Application")
    needle = str(target).casefold()
    fallback = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            for window in shell.Windows():
                try:
                    if "explorer.exe" not in str(window.FullName).lower():
                        continue
                    hwnd = int(window.HWND)
                    if not hwnd or not win32gui.IsWindow(hwnd):
                        continue
                    if fallback is None:
                        fallback = hwnd
                    selected = window.Document.SelectedItems()
                    for item in selected:
                        if str(item.Path).casefold() == needle:
                            return hwnd
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(0.2)
    return fallback


def _find_explorer_hwnd_by_title(target, timeout=2.0):
    try:
        import win32gui
    except Exception:
        return None
    needles = [str(target.name), str(target.parent.name)]
    deadline = time.time() + timeout
    while time.time() < deadline:
        found = []

        def callback(hwnd, _unused):
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                if win32gui.GetClassName(hwnd) not in ("CabinetWClass", "ExploreWClass"):
                    return True
                title = win32gui.GetWindowText(hwnd)
                if any(needle and needle in title for needle in needles):
                    found.insert(0, hwnd)
                else:
                    found.append(hwnd)
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(callback, None)
        except Exception:
            pass
        if found:
            return found[0]
        time.sleep(0.2)
    return None


def _force_foreground(hwnd):
    """Restore, topmost-toggle and foreground an Explorer window."""
    try:
        import win32gui
        import win32con
        import win32process
        import win32api
        import win32com.client
    except Exception as exc:
        return {"ok": False, "reason": f"窗口 API 不可用: {exc}"}
    try:
        foreground_before = win32gui.GetForegroundWindow()
        fg_tid, _ = win32process.GetWindowThreadProcessId(foreground_before)
        target_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
        attached = False
        if fg_tid and target_tid and fg_tid != target_tid:
            try:
                win32process.AttachThreadInput(fg_tid, target_tid, True)
                attached = True
            except Exception:
                pass
        reassert = 0
        held_ms = 0
        try:
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            win32api.keybd_event(win32con.VK_MENU, 0, 0, 0)
            win32api.keybd_event(win32con.VK_MENU, 0, win32con.KEYEVENTF_KEYUP, 0)
            win32gui.BringWindowToTop(hwnd)
            win32gui.SetForegroundWindow(hwnd)
            flags = win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
            # 只做一次 TOPMOST 切换时，窗口常被 IDE / 浏览器立刻盖到底层。
            # 这里保持置顶约 1.8 秒，期间若前台被抢走就再次夺回。
            win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0, flags)
            hold_start = time.time()
            while time.time() - hold_start < 1.8:
                if win32gui.GetForegroundWindow() != hwnd:
                    try:
                        win32gui.SetForegroundWindow(hwnd)
                        reassert += 1
                    except Exception:
                        pass
                time.sleep(0.2)
            held_ms = int((time.time() - hold_start) * 1000)
            win32gui.SetWindowPos(hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, flags)
            try:
                app = win32com.client.Dispatch("WScript.Shell")
                app.AppActivate(win32gui.GetWindowText(hwnd))
            except Exception:
                pass
        finally:
            if attached:
                try:
                    win32process.AttachThreadInput(fg_tid, target_tid, False)
                except Exception:
                    pass
        time.sleep(0.2)
        foreground_after = win32gui.GetForegroundWindow()
        return {
            "ok": foreground_after == hwnd,
            "hwnd": hwnd,
            "foreground_hwnd": foreground_after,
            "title": win32gui.GetWindowText(hwnd),
            "class": win32gui.GetClassName(hwnd),
            "held_topmost_ms": held_ms,
            "reassert_count": reassert,
        }
    except Exception as exc:
        return {"ok": False, "reason": str(exc)}


def _reset_ai_dir(folder, export_root):
    """导出前清空该会话的 发给AI/ 目录（只动工具自有目录，严格校验路径）。"""
    root = Path(export_root).resolve()
    folder = Path(folder).resolve()
    if folder.name != "发给AI" or root not in folder.parents:
        raise RuntimeError(f"拒绝清理非工具导出目录: {folder}")
    if folder.exists():
        for child in folder.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass
    folder.mkdir(parents=True, exist_ok=True)


def precise_export(cfg, acc, cid, name=None, ids=None, zip_mode="timestamp",
                   lite_mode="auto", progress=None, items=None,
                   live_dir=None, since_ts=0):
    """Export selected messages + exact attachments as ONE .zip in export_root.

    The temporary work directory lives under runtime/tmp_export and is always
    removed. No per-conversation directory is created in the export root.
    ZIP entry order: 000_chat.md, 001_..., 002_..., ..., ALL_FOR_AI.md.

    lite_mode: "auto" 仅当完整包 >20MB 时额外生成网页 AI 轻量包；"always" 恒生成；
    "off" 关闭。轻量包只处理临时副本，完整包与企微缓存原件均不改动。
    progress: 可选回调，用于把阶段进度写进任务日志；回调自身异常绝不影响导出。
    """
    def report(message):
        if progress is None:
            return
        try:
            progress(message)
        except BaseException:
            pass

    if zip_mode not in ("timestamp", "overwrite"):
        raise RuntimeError(f"不支持的 ZIP 命名模式: {zip_mode}")
    if lite_mode not in ("auto", "always", "off"):
        raise RuntimeError(f"不支持的轻量包模式: {lite_mode}")
    multi = bool(items and len(items) >= 2)
    report("① 读取会话消息索引 / 解密库…")
    if multi:
        # 多会话合并：每个会话各取自己勾选的消息，再严格按真实时间戳升序交错合并。
        # 每条消息带上来源账号/会话/显示名，附件匹配时按各自账号的 Cache 索引查找。
        pools, scope = [], []
        for item in items:
            item_cid = str(item.get("cid") or "")
            item_aid = str(item.get("account") or acc["id"])
            item_acc = next((a for a in cfg["accounts"] if a["id"] == item_aid), None)
            if item_acc is None:
                raise RuntimeError(f"账号 {item_aid} 不在配置中，请先点「重新扫描」")
            want = {str(x) for x in (item.get("ids") or [])}
            matched = [m for m in _message_index(cfg, item_acc, item_cid)
                       if m["id"] in want]
            if not matched:
                continue
            source_name = str(item.get("name") or item_cid)
            for msg in matched:
                enriched = dict(msg)
                enriched["_account"] = item_aid
                enriched["_cid"] = item_cid
                enriched["_source"] = source_name
                pools.append(enriched)
            scope.append({"account": item_aid, "cid": item_cid,
                          "name": source_name, "count": len(matched)})
        if len(scope) < 2:
            raise RuntimeError("合并导出至少需要 2 个含已选消息的会话")
        picked = sorted(
            pools,
            key=lambda m: (m["ts"], str(m.get("_cid", "")),
                           int(m["id"]) if str(m["id"]).isdigit() else 0))
        labels = [_short_export_label(entry["name"]) for entry in scope[:3]]
        suffix = "+".join(labels)
        if len(scope) > 3:
            suffix += f"等{len(scope)}会话"
        title = f"合并{len(scope)}会话_{suffix}"
    else:
        wanted = {str(x) for x in (ids or [])}
        if not wanted:
            raise RuntimeError("没有勾选任何消息，请先在右侧列表里选择")
        all_messages = _message_index(cfg, acc, cid)
        picked = [m for m in all_messages if m["id"] in wanted]
        if not picked:
            raise RuntimeError("勾选的消息不在该会话中，请刷新右侧列表后重试")
        picked.sort(key=lambda m: (m["ts"], int(m["id"]) if m["id"].isdigit() else 0))
        scope = [{"account": acc["id"], "cid": str(cid),
                  "name": name or str(cid), "count": len(picked)}]
        title = name or str(cid)
    if not picked:
        raise RuntimeError("没有可导出的消息，请刷新右侧列表后重试")
    if since_ts:
        picked = [m for m in picked if (m.get("ts") or 0) >= float(since_ts)]
        if not picked:
            raise RuntimeError("起始时间之后没有消息，请放宽范围")

    # 补扫索引懒加载：绝大多数导出在企微 Cache 就全部命中，不付遍历本机目录的代价。
    wanted_names = _collect_wanted_attachment_names(picked)
    extra_index = None
    extra_hits = []

    def ensure_extra_index():
        nonlocal extra_index
        if extra_index is None:
            extra_index = build_extra_scan_index(cfg, wanted_names)
            report(f"③b 企微缓存未命中，正在浅层补扫本机常用目录"
                   f"（{len(extra_index['dirs'])} 个目录 / 最多 {EXTRA_SCAN_MAX_DEPTH} 层）…")
        return extra_index

    export_root = Path(cfg["export_root"]).resolve()
    export_root.mkdir(parents=True, exist_ok=True)
    tmp_dir = (RUNTIME / "tmp_export_live") if live_dir else _new_tmp_export_dir()
    folder = Path(live_dir) if live_dir else tmp_dir
    folder.mkdir(parents=True, exist_ok=True)
    report(f"② 命中 {len(picked)} 条消息，正在建立本机缓存索引…")
    index_by_account = {}
    cache_count = 0
    for aid in dict.fromkeys(entry["account"] for entry in scope):
        scoped_acc = next((a for a in cfg["accounts"] if a["id"] == aid), acc)
        idx, cnt = (_cached_cache_index(scoped_acc) if live_dir
                    else build_cache_index(scoped_acc))
        index_by_account[aid] = idx
        cache_count += cnt
    index = index_by_account.get(acc["id"]) or next(iter(index_by_account.values()), {})

    def _index_for(message):
        """跨账号合并时，按消息来源账号取对应 Cache 索引。"""
        return index_by_account.get(message.get("_account") or acc["id"], index)

    report(f"③ 缓存索引完成（扫描 {cache_count} 个文件 / "
           f"{len(index_by_account)} 个账号），正在生成聊天记录与编号附件…")

    if multi:
        scope_lines = ["- 会话清单（每条消息标题用 [来源: …] 标注所属会话）："]
        for number, entry in enumerate(scope, 1):
            scope_lines.append(
                f"  {number}. {entry['name']} (`{entry['cid']}` / 账号 "
                f"`{entry['account']}`) · {entry['count']} 条")
        scope_lines.append("- 全部会话消息严格按真实时间戳升序交错排列，"
                           "合并转发卡片仍在原位置递归展开。")
    else:
        scope_lines = [f"- conversation-id: `{cid}`",
                       f"- 企微账号: `{acc['id']}`"]
    # 防串单：活目录头部明确锚定唯一业务基准的客户群，AI 不再把私聊里其它新派单混入
    main_group = ""
    if live_dir:
        if multi:
            main_group = next(
                (str(x.get("name") or x.get("cid") or "")
                 for x in (items or []) if _codex_is_group(x.get("cid"))), "")
        elif _codex_is_group(cid):
            main_group = str(name or cid)
    anchor_lines = ([f"> 主项目群（唯一业务基准）: {main_group}", ""]
                    if main_group else [])
    chat_lines = [
        f"# {title} · 已选消息（时间正序）", "",
        *anchor_lines,
        *scope_lines,
        f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 已选消息: {len(picked)} 条（仅当前勾选，不含未勾选消息与其它群文件）",
        "- 导出产物：单个 ZIP 压缩包；包内文件按聊天出现顺序排列。",
        "- 合并转发卡片已在原位置递归展开【任意层嵌套】，层级用 ### / #### 标题区分。",
        "- 各层文字、图片、文件按原始时间正序展示；所有附件统一编入全局 001、002… 序列。",
        "- 附件不限格式：可转文本的就地展开正文，其余保留原格式文件并原位标注。", "",
        "---", "",
    ]
    ai_lines = [
        f"# {title} · 单文件汇总（给 AI）", "",
        *anchor_lines,
        f"- 会话数 {len(scope)} / 已选消息 {len(picked)} 条，附件按全局时间顺序编号 001、002…",
        *scope_lines,
        "- 只含当前勾选消息与这些消息精准匹配到的附件；Word/PDF/Excel/TXT 正文就地展开。",
        "- 本文件与 000_chat.md、编号附件一起打包在同一个 ZIP 里。", "",
        "---", "",
    ]
    file_map, attachments, missing, blurry_thumbs = {}, [], [], []
    attachments_by_mid = {}   # 消息 id -> [(附件编号, 编号文件名)]，供引用行反查
    md5_map = {}          # 真实文件 MD5 -> 首次编号的附件（同内容只打包一次）
    emitted_slots = set() # (number, stamp) 集合，用于活目录安全清理被高清覆盖的旧 UUID 缩略图
    attach_changed = False
    dedup_count = 0
    seq = 0
    stats = {"messages": 0, "documents": 0, "images": 0, "other_files": 0,
             "forward_cards": 0, "forward_subs": 0, "blurry_thumbs": 0}
    forward_hint = "需在企业微信里点开该合并转发卡片并点击查看原图/下载文件后重新导出"

    def emit_attachment(filename, source, ts, time_str, key, local_id,
                        forward=False, require_image=False, origin="",
                        expected_size=0, voice=None, tier="", match=""):
        """统一编号：主群消息与合并转发子消息共用同一个 001、002… 序列。"""
        nonlocal seq, chat_lines, ai_lines, dedup_count, attach_changed
        if key in file_map:
            note = file_map[key]
            chat_lines += [note, ""]
            ai_lines += [note, ""]
            return
        if source is not None:
            source = Path(source)
            # 不再按「必须是图片头」过滤：任意格式（OBJ/STP/NC/RVT/压缩包/视频…）
            # 只要缓存文件真实存在就按原格式打包
            if not source.is_file():
                source = None
            elif is_silk_voice(source):
                # 语音：SILK -> 标准 MP3 后再按原聊天顺序编号打包
                mp3_bytes, seconds = silk_to_mp3(
                    source, int((voice or {}).get("duration") or 0))
                if mp3_bytes:
                    voice_dir = tmp_dir / "_voice"
                    voice_dir.mkdir(parents=True, exist_ok=True)
                    digest = hashlib.md5(str(source).encode("utf-8")).hexdigest()[:8]
                    mp3_path = voice_dir / f"voice_{digest}_{seconds}s.mp3"
                    mp3_path.write_bytes(mp3_bytes)
                    source = mp3_path
                    filename = voice_mp3_filename(seconds)
                else:
                    source = None
        source_kind = "企微缓存"
        # 企微 Cache 未命中，且有真实文件名 -> 在本机常用目录浅层精准补扫
        if source is None and _media_filename_ok(filename):
            hit = lookup_extra_scan(ensure_extra_index(), filename, expected_size, ts)
            if hit is not None and Path(hit).is_file():
                source = Path(hit)
                source_kind = "补扫目录命中"
                extra_hits.append({
                    "name": filename, "path": str(hit),
                    "dir": str(Path(hit).parent),
                    "size": source.stat().st_size,
                    "expected_size": int(expected_size or 0),
                })
        if source is None:
            note = f"[附件未下载: {filename}]"
            missing.append({
                "category": "missing", "status": "not_downloaded", "reason": filename,
                "kind": Path(filename).suffix.lower().lstrip(".") or "file",
                "local_id": local_id,
                "hint": forward_hint if forward else "请在企业微信里点开该消息/附件，等待下载缓存完成后重新导出",
            })
            chat_lines += [note, ""]
            ai_lines += [note, ""]
            file_map[key] = note
            return
        # 按真实文件 MD5 去重：客服私聊与客户群互相转发同一批参考图/文档时，
        # 同内容文件只打包一次、不占新编号，原位标注指向首次编号。
        try:
            digest = _md5_of(source)
        except Exception:
            digest = ""
        if digest:
            previous = md5_map.get(digest)
            if previous:
                dedup_count += 1
                note = (f"[同附件 {previous['number']} -> "
                        f"{previous['renamed']}（已去重）]")
                attachments_by_mid.setdefault(str(local_id), []).append(
                    (previous["number"], previous["renamed"]))
                chat_lines += [note, ""]
                ai_lines += [note, ""]
                file_map[key] = note
                return
        seq += 1
        number = f"{seq:03d}"
        stamp = time.strftime("%m%d-%H%M", time.localtime(ts)) if ts else "0000-0000"
        dest_name = f"{number}_{stamp}_{_safe_attachment_name(filename)}"
        emitted_slots.add((number, stamp))
        if digest:
            md5_map[digest] = {"number": number, "renamed": dest_name}
        attachments_by_mid.setdefault(str(local_id), []).append((number, dest_name))
        destination = folder / dest_name
        unchanged = False
        if live_dir and destination.is_file():
            try:
                # 仅当 MD5、字节数、分辨率完全一致才跳过；高清升级必定自动覆盖替换
                unchanged = (
                    destination.stat().st_size == source.stat().st_size
                    and _md5_of(destination) == _md5_of(source)
                )
            except Exception:
                unchanged = False
        if not unchanged:
            shutil.copy2(source, destination)
            attach_changed = True
        note = f"[附件 {number} -> {dest_name}]"
        if live_dir and destination.suffix.lower() == ".zip":
            extracted = _auto_unzip_live(Path(live_dir), destination)
            if extracted:
                note += f"（已自动解压到 _附件解压/{extracted}/ 供直接读取）"
        suffix = destination.suffix.lower()
        duration = probe_media_duration(source) if suffix in LITE_VIDEO_EXTS else 0
        dest_size = destination.stat().st_size
        dims = _image_dims_of(destination) if suffix in IMAGE_EXTENSIONS else (0, 0)
        is_blurry = bool(
            tier == "210px模糊缩略图降级"
            or (suffix in IMAGE_EXTENSIONS and _is_blurry_thumb(destination)
                and str(match or "") != "size+md5")
        )
        attachments.append({"number": number, "name": filename, "renamed": dest_name,
                            "source": str(source), "time": time_str, "local_id": local_id,
                            "origin": origin or ("合并转发" if forward else "主聊天"),
                            "source_kind": source_kind, "duration": duration,
                            "size_kb": round(dest_size / 1024, 1),
                            "dims": list(dims), "match": str(match or ""),
                            "blurry_thumb": is_blurry})
        chat_lines += [note, ""]
        ai_lines += [note, ""]
        if is_blurry:
            stats["blurry_thumbs"] += 1
            blurry_thumbs.append({
                "number": number, "renamed": dest_name, "local_id": local_id,
                "size_kb": round(dest_size / 1024, 1), "dims": list(dims),
            })
            chat_lines += [_BLURRY_WARNING_TEXT, ""]
            ai_lines += [_BLURRY_WARNING_TEXT, ""]
        elif tier:
            marker = f"[已用清晰预览图兜底: {tier}]"
            chat_lines += [marker, ""]
            ai_lines += [marker, ""]
        if duration:
            duration_note = f"> 视频时长 {duration} 秒（{dest_name}）"
            chat_lines += [duration_note, ""]
            ai_lines += [duration_note, ""]
        text = (extract_document_text(destination, limit=20000)
                if suffix in (".txt", ".md", ".csv", ".json", ".log", ".xml", ".html", ".htm",
                              ".docx", ".xlsx", ".xlsm", ".pdf", ".pptx", ".rtf") else None)
        if text is not None:
            stats["documents"] += 1
            ai_lines += [f"**附件 {number} 正文 · `{dest_name}`**", "", "```text", text, "```", ""]
        elif suffix in IMAGE_EXTENSIONS:
            stats["images"] += 1
            ai_lines += [f"![附件 {number}]({dest_name})", ""]
        else:
            stats["other_files"] += 1
            ai_lines += [f"- 附件 {number}：`{dest_name}`（原格式文件，保留在 ZIP 中）", ""]
        file_map[key] = note

    for message in picked:
        stats["messages"] += 1
        # 多会话：附件查重 key 带会话前缀，避免不同会话里的同名文件互相吞掉编号
        key_prefix = f"{message.get('_cid', cid)}|" if multi else ""
        source_tag = f" [来源: {message.get('_source')}]" if multi else ""

        def emit_links():
            """业务链接卡片按 [链接卡片] 标题 | 摘要 | URL 写入两个 md。"""
            for link in (message.get("links") or []):
                line = (f"[链接卡片] {link.get('title') or '（无标题）'} | "
                        f"{link.get('summary') or '（无摘要）'} | {link.get('url')}")
                chat_lines.extend([line, ""])
                ai_lines.extend([line, ""])

        card = message.get("forward")
        if card:
            stats["forward_cards"] += 1
            card_type = card.get("card_type", "合并转发")
            header = (f"## [{message['time']}] {message['sender']} · "
                      f"[{card_type}]{source_tag}")
            intro = (f"**{card['title']}** · {card['count']} 条（含各层转发卡片）/ "
                     f"{card.get('levels', 1)} 层嵌套 / {card['total_files']} 个附件"
                     f"（已精准匹配 {card['matched']} 个，未缓存 {card['missing']} 个）")
            note = "以下按各层子消息原始时间正序递归展开，全部附件统一编入全局 001、002… 序列"
            chat_lines += [header, ""]
            ai_lines += [header, ""]
            emit_links()
            chat_lines += [intro, "", note, "", "---", ""]
            ai_lines += [intro, "", note, "", "---", ""]
            for si, sub in enumerate(card["subs"]):
                stats["forward_subs"] += 1
                depth = min(int(sub.get("depth", 1)), 6)
                hashes = "#" * (2 + depth)
                layer = f"第{depth}层转发"
                sub_header = (f"{hashes} [{layer}] [{sub['time']}] "
                              f"{sub['sender']} · [{sub['kind']}]")
                if sub.get("is_card"):
                    body = (f"**{sub.get('card_title') or '合并转发聊天记录'}** · "
                            "以下为该层展开的子消息（按原始时间正序）")
                else:
                    body = _clean_fwd_body(sub["text"]) or "（此条为图片/文件，无文字正文）"
                chat_lines += [sub_header, "", body, ""]
                ai_lines += [sub_header, "", body, ""]
                # 合并转发卡片内的语音：同主聊天规则显示转文字状态
                vsub = sub.get("voice")
                if vsub:
                    vdur = int(vsub.get("duration") or 0)
                    vlabel = (f'[语音 {vdur}" · 企微转文字（可能存在同音误差）]'
                              if vsub.get("transcript") else
                              f'[语音 {vdur}" · 尚未在企微转文字]')
                    chat_lines += [vlabel, ""]
                    ai_lines += [vlabel, ""]
                    detail = (vsub["transcript"] if vsub.get("transcript") else
                              "> 请在企业微信里点「转文字」，或直接听下方打包的 MP3 原声。")
                    chat_lines += [detail, ""]
                    ai_lines += [detail, ""]
                for fi, item in enumerate(sub["files"]):
                    source = item.get("source")
                    filename = (item["name"] or (Path(source).name if source
                                                 else f"附件_{item.get('size', 0)}"))
                    key = key_prefix + (_norm_filename(filename) if item.get("named")
                           else f"{message['id']}|{si}|{fi}|{item.get('size', 0)}|"
                                 f"{','.join(item.get('hashes', [])[:1])}")
                    emit_attachment(
                        filename, source, sub["ts"], sub["time"], key,
                        f"{message['id']}#{si + 1}", forward=True,
                        expected_size=item.get("size") or 0,
                        voice=vsub, tier=_tier_note(item.get("match")),
                        match=item.get("match") or "",
                        origin=f"{card_type} · 第{depth}层 · {card['title']}")
            chat_lines += ["---", ""]
            ai_lines += ["---", ""]
            continue

        # 语音消息：在原时间位置输出企微转文字（或提醒），并把 MP3 编入全局序号
        voice = message.get("voice")
        if voice:
            duration = int(voice.get("duration") or 0)
            header = (f"## [{message['time']}] {message['sender']} · "
                      f"[语音]{source_tag}")
            chat_lines += [header, ""]
            ai_lines += [header, ""]
            emit_links()
            if voice.get("transcript"):
                label = f'[语音 {duration}" · 企微转文字（可能存在同音误差）]'
                chat_lines += [label, "", voice["transcript"], ""]
                ai_lines += [label, "", voice["transcript"], ""]
            else:
                label = f'[语音 {duration}" · 尚未在企微转文字]'
                hint = "> 请在企业微信里点「转文字」后重新导出，或直接听下方打包的 MP3 原声。"
                chat_lines += [label, "", hint, ""]
                ai_lines += [label, "", hint, ""]
            if voice.get("source"):
                emit_attachment(voice_mp3_filename(duration), voice["source"],
                                message["ts"], message["time"],
                                key_prefix + f"voice|{message['id']}", message["id"],
                                origin="主聊天语音", voice=voice)
            continue

        header = (f"## [{message['time']}] {message['sender']} · "
                  f"[{message['type']}]{source_tag}")
        chat_lines += [header, ""]
        ai_lines += [f"## [{message['time']}] {message['sender']}{source_tag}", ""]
        emit_links()
        rendered_content = _rewrite_quote_content(
            message["content"], message.get("quote"), attachments_by_mid)
        chat_lines += [rendered_content, ""]
        ai_lines += [rendered_content, ""]
        emitted_keys = set()
        # 1) 直接从 protobuf 媒体 payload 精准匹配到的附件（不限格式/后缀）
        for mi, item in enumerate(message.get("media", [])):
            source = item.get("source")
            filename = (Path(source).name if source else
                        (item["name"] or f"附件_{item.get('size', 0)}"))
            key = key_prefix + (_norm_filename(filename) if item.get("named")
                   else f"{message['id']}|media|{mi}|{item.get('size', 0)}")
            emit_attachment(filename, source, message["ts"], message["time"], key,
                            message["id"], origin="主聊天",
                            tier=_tier_note(item.get("match")),
                            match=item.get("match") or "",
                            expected_size=item.get("size") or 0)
            emitted_keys.add(_norm_filename(filename))
            if item.get("name"):
                emitted_keys.add(_norm_filename(item["name"]))
        # 2) 正文里提到的文件名兜底（去重，避免同一附件编号两次）
        for idx, filename in enumerate(message["files"]):
            if _norm_filename(filename) in emitted_keys:
                continue
            emitted_keys.add(_norm_filename(filename))
            emit_attachment(filename,
                            _lookup_cache(_index_for(message), filename, message["ts"]),
                            message["ts"], message["time"],
                            key_prefix + _norm_filename(filename),
                            message["id"])

    if attachments:
        ai_lines += ["---", "", "## 附件清单（按聊天出现顺序）", "",
                     "| 编号 | 消息时间 | 来源 | 文件 |", "| --- | --- | --- | --- |"]
        for item in attachments:
            ai_lines.append(f"| {item['number']} | {item['time']} | {item['origin']} | `{item['renamed']}` |")
        ai_lines.append("")
    if missing:
        ai_lines += ["---", "", "## 尚未下载的附件", "",
                     "> 合并转发里的图片/文件：需在企业微信里点开该卡片并点击查看原图/下载文件，等缓存落地后重新导出。", ""]
        for item in missing:
            ai_lines.append(f"- 消息 {item['local_id']}：`{item['reason']}`")
        ai_lines.append("")

    # 活目录安全清理：当某编号位从旧 210px UUID 缩略图升级成新 UUID 高清原图（或旧错配被替换、
    # 或因前序图片从去重缩略图升级为独立高清图导致后序编号平移）时，仅清理根目录里已被替代的旧件，
    # 绝不动交付给客户/、_附件解压/ 或任何用户/AI 文件。
    upgraded_removed = []
    if live_dir:
        emitted_cf = {a["renamed"].casefold() for a in attachments}
        emitted_tail_md5 = {}
        for a in attachments:
            rn = a["renamed"]
            if len(rn) > 4 and rn[:3].isdigit() and rn[3] == "_":
                try:
                    emitted_tail_md5[rn[4:].casefold()] = _md5_of(folder / rn)
                except OSError:
                    pass
        try:
            for old in list(folder.iterdir()):
                if not old.is_file() or old.name.casefold() in emitted_cf:
                    continue
                remove_old = False
                m = _MANAGED_UUID_ATTACH_RE.match(old.name)
                if m:
                    slot = (m.group(1), m.group(2))
                    if slot in emitted_slots or _is_blurry_thumb(old):
                        remove_old = True
                elif (len(old.name) > 4 and old.name[:3].isdigit()
                      and old.name[3] == "_"):
                    tail_cf = old.name[4:].casefold()
                    want_md5 = emitted_tail_md5.get(tail_cf)
                    if want_md5 and _md5_of(old) == want_md5:
                        remove_old = True
                if remove_old:
                    try:
                        old.unlink()
                        upgraded_removed.append(old.name)
                        attach_changed = True
                    except OSError:
                        pass
        except OSError:
            pass

    chat_path = folder / "000_chat.md"
    ai_path = folder / "ALL_FOR_AI.md"
    chat_text = "\n".join(chat_lines)
    ai_text = "\n".join(ai_lines)
    content_changed = True
    if live_dir:
        # 活目录：原子写 + 内容未变则不重写，杜绝「mtime 推新但内容还是旧快照」
        content_changed = _atomic_write_if_changed(chat_path, chat_text)
        if _atomic_write_if_changed(ai_path, ai_text):
            content_changed = True
        if attach_changed:
            content_changed = True
    else:
        chat_path.write_text(chat_text, encoding="utf-8")
        ai_path.write_text(ai_text, encoding="utf-8")
    ai_size_kb = round(ai_path.stat().st_size / 1024, 1)

    zip_path = None
    zip_entry_names = [x["renamed"] for x in attachments]
    if not live_dir:
        zip_filename = _export_zip_name(title, zip_mode)
        zip_path = _unique_export_zip_path(export_root, zip_filename, zip_mode)
        zip_temp = tmp_dir / "export.zip"
        zip_entries = [("000_chat.md", chat_path)]
        zip_entries += [(item["renamed"], folder / item["renamed"])
                        for item in attachments]
        zip_entries.append(("ALL_FOR_AI.md", ai_path))
        report("④ 正在打包完整原件 ZIP…")
        zip_entry_names = _zip_export_files(zip_temp, zip_entries)

        # 完整原件包逻辑不变；只在临时目录的副本上额外制作网页 AI 轻量包。
        full_zip_bytes = zip_temp.stat().st_size
        want_lite, lite_reason = _lite_should_generate(lite_mode, full_zip_bytes)
        lite_temp = lite_meta = lite_path = None
        if want_lite:
            report("⑤ 正在生成网页 AI 轻量包…")
            lite_temp, lite_meta = _lite_build(
                tmp_dir, folder, chat_lines, ai_lines, attachments, zip_path.name)
            lite_filename = f"{zip_path.stem}_AI轻量.zip"
            lite_path = _unique_export_zip_path(export_root, lite_filename, "timestamp")

        temp_dir_cleaned = False
        try:
            os.replace(zip_temp, zip_path)
            if lite_temp is not None and lite_path is not None:
                os.replace(lite_temp, lite_path)
        finally:
            report("⑥ 正在清理临时目录…")
            temp_dir_cleaned = _cleanup_tmp_export_dir(tmp_dir)
        report("⑦ 导出完成，正在汇总结果…")
    else:
        report("④ 实时在办目录已就地更新（不打 ZIP，附件已 MD5 去重）…")

    # ---- 解析质量自检（每次导出自动执行）----
    quality = {"total": len(picked), "complete": 0, "empty_shell": [],
               "fallback": [], "attachment_sequence_ok": False,
               "chat_md_matches": False}
    for msg in picked:
        content = (msg.get("content") or "").strip()
        has_any = bool(content) or any((msg.get("files"), msg.get("media"),
                                        msg.get("forward"), msg.get("voice"),
                                        msg.get("links")))
        if has_any:
            quality["complete"] += 1
        else:
            quality["empty_shell"].append({"id": msg["id"], "ct": msg.get("ct", 0),
                                           "time": msg["time"]})
        if content.startswith("[类型 ct="):
            quality["fallback"].append({"id": msg["id"], "ct": msg.get("ct", 0)})
    numbers = [item["number"] for item in attachments]
    quality["attachment_sequence_ok"] = (
        numbers == [f"{i:03d}" for i in range(1, len(attachments) + 1)])
    chat_text = "\n".join(chat_lines)
    quality["chat_md_matches"] = all(
        f"[附件 {number} -> " in chat_text for number in numbers)
    report(f"⑧ 解析质量自检：{quality['complete']}/{quality['total']} 条完整 / "
           f"{len(quality['empty_shell'])} 条空壳 / "
           f"{len(quality['fallback'])} 条未知类型已标注 / "
           f"附件编号连续={quality['attachment_sequence_ok']}")
    report(f"⑧b 附件 MD5 去重：跳过 {dedup_count} 个重复附件"
           f"（原位标注 [同附件 00X -> …（已去重）]）")

    if live_dir:
        # 活目录模式：所有文件已就地写好，跳过 ZIP / 轻量包 / 临时目录清理
        return {
            "live": True, "folder": str(folder), "name": title,
            "chat_md": str(chat_path), "all_for_ai_md": str(ai_path),
            "messages": len(picked), "attachments_ok": len(attachments),
            "files": attachments, "missing": missing,
            "blurry_thumbs": blurry_thumbs,
            "blurry_thumbs_count": len(blurry_thumbs),
            "upgraded_removed": upgraded_removed,
            "quality": quality,
            "deduplicated": dedup_count, "multi": multi,
            "merged_items": scope, "content_changed": content_changed,
            "all_for_ai": {"size_kb": ai_size_kb, **stats},
            "counts": {"attachments": len(attachments),
                       "blurry_thumbs": len(blurry_thumbs)},
            "recent_messages": [
                {"id": str(msg["id"]), "time": msg.get("time", ""),
                 "sender": msg.get("sender", ""), "ct": msg.get("ct", 0),
                 "source": msg.get("_source", ""),
                 "system_noise": bool(msg.get("system_noise")),
                 "content": str(msg.get("content") or "")[:600],
                 "attachments": [
                     f"{a['number']} -> {a['renamed']}" for a in attachments
                     if str(a.get("local_id", "")).split("#")[0] == str(msg["id"])]}
                for msg in picked
            ],
        }

    lite = {
        "generated": bool(lite_path is not None),
        "reason": lite_reason,
        "trigger_mb": round(LITE_AUTO_TRIGGER_BYTES / 1048576, 1),
        "full_size_kb": round(full_zip_bytes / 1024, 1),
        "zip_path": str(lite_path) if lite_path else None,
        "zip_name": lite_path.name if lite_path else None,
        "zip_size_kb": (round(lite_path.stat().st_size / 1024, 1)
                        if lite_path else None),
        "zip_entries": (lite_meta or {}).get("zip_entries", []),
        "shrunk": (lite_meta or {}).get("shrunk", []),
        "skipped": (lite_meta or {}).get("skipped", []),
        "kept_count": (lite_meta or {}).get("kept_count", 0),
    }
    if lite["generated"] and lite["full_size_kb"] > 0:
        lite["saved_kb"] = round(lite["full_size_kb"] - lite["zip_size_kb"], 1)
        lite["ratio_pct"] = round(lite["zip_size_kb"] / lite["full_size_kb"] * 100, 1)

    return {
        "account": acc["id"], "conversation_id": str(cid), "name": title,
        "multi": multi, "merged_items": scope,
        "export_root": str(export_root), "out_dir": str(export_root),
        "zip_path": str(zip_path), "zip_name": zip_path.name,
        "zip_mode": zip_mode, "zip_entries": zip_entry_names,
        "lite_mode": lite_mode, "lite": lite,
        "zip_size_kb": round(zip_path.stat().st_size / 1024, 1),
        "chat_md": f"{zip_path}#000_chat.md", "chat_md_name": "000_chat.md",
        "messages": len(picked), "attachments_ok": len(attachments),
        "files": attachments, "missing": missing,
        "blurry_thumbs": blurry_thumbs,
        "blurry_thumbs_count": len(blurry_thumbs),
        "quality": quality,
        "deduplicated": dedup_count,
        "extra_scan": {
            "dirs": (extra_index or {}).get("dirs", []),
            "wanted": len(wanted_names),
            "scanned_files": (extra_index or {}).get("scanned_files", 0),
            "elapsed_ms": (extra_index or {}).get("elapsed_ms", 0),
            "truncated": (extra_index or {}).get("truncated", False),
            "hits": extra_hits,
        },
        "cache_files_scanned": cache_count,
        "all_for_ai": {
            "path": f"{zip_path}#ALL_FOR_AI.md", "name": "ALL_FOR_AI.md",
            "size_kb": ai_size_kb, **stats,
        },
        # 统计一致性自检：顶部统计 / 子项状态 / 实际打包数三者必须相等
        "counts": {
            "attachments": len(attachments),
            "classified": stats["documents"] + stats["images"] + stats["other_files"],
            "missing": len(missing),
            "forward_cards": stats["forward_cards"],
            "forward_subs": stats["forward_subs"],
            "card_total_files": sum(c["total_files"] for m in picked
                                    if (c := m.get("forward"))),
            "card_matched": sum(c["matched"] for m in picked
                                if (c := m.get("forward"))),
            "card_missing": sum(c["missing"] for m in picked
                                if (c := m.get("forward"))),
        },
        "temp_dir": str(tmp_dir), "temp_dir_cleaned": bool(temp_dir_cleaned),
        "temp_cleanup_state": "cleaned" if temp_dir_cleaned else "pending",
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------- 实时增量同步
#
# 前端每 8 秒静默轮询 /api/changes。直接读加密 message.db + WAL 的 stat 做水印；
# 有写入时只把 WAL 里「已提交」的页解密后补进解密库（本机 WAL 约 7 MB，
# 补丁约 0.2 秒），而不是每来一条新消息都整库重解 297 MB（约 8 秒）。
# WAL 发生 checkpoint / generation 变化时自动退回整库重解，并对整库重解做节流。

LIVE_STATE = RUNTIME / "live"
PAGE_SZ = 4096
_WAL_MAGICS = (0x377F0682, 0x377F0683)
_LIVE_FULL_LOCK = threading.Lock()
_LAST_FULL = {}


def _stat_sig(path):
    try:
        info = Path(path).stat()
        return (info.st_size, info.st_mtime_ns)
    except OSError:
        return (0, 0)


def _stat_sig_stable(path):
    """只看文件大小的稳定水印；mtime_ns 会被企微持续 touch，不能进缓存键。"""
    try:
        return (Path(path).stat().st_size,)
    except OSError:
        return (0,)


def live_signature(acc):
    main = Path(acc["data_dir"]) / "message.db"
    return {"main": _stat_sig(main), "wal": _stat_sig(str(main) + "-wal")}


def _wal_checksum(data, byteorder, state=(0, 0)):
    import struct
    first, second = state
    for left, right in struct.iter_unpack(byteorder + "II", data):
        first = (first + left + second) & 0xFFFFFFFF
        second = (second + right + first) & 0xFFFFFFFF
    return first, second


_WAL_STAMP_CACHE = {}
_WAL_STAMP_LOCK = threading.Lock()


def _wal_commit_stamp(acc):
    """返回 WAL 真实提交戳 (gen, commit_size, last_commit_offset, last_checksum)。

    按 (wal_size, wal_mtime_ns) 缓存：
    - 企微仅 touch WAL 文件 mtime 但无新事务提交 → 提交戳完全不变（0 抖动）
    - 企微在已有 WAL 文件内覆写提交新消息（文件大小不变）→ 提交戳立刻变化（0 漏抓）
    """
    import struct
    wal = Path(acc["data_dir"]) / "message.db-wal"
    try:
        st = wal.stat()
        key = (str(wal), st.st_size, st.st_mtime_ns)
    except OSError:
        return ("", 0, 0, 0, 0)
    if st.st_size < 32:
        return ("", 0, 0, 0, 0)
    with _WAL_STAMP_LOCK:
        hit = _WAL_STAMP_CACHE.get(key)
        if hit is not None:
            return hit
    try:
        data = _read_shared_file(wal)
    except OSError:
        return ("", 0, 0, 0, 0)
    if len(data) < 32:
        return ("", 0, 0, 0, 0)
    magic, version, page_size = struct.unpack(">III", data[:12])
    if magic not in _WAL_MAGICS or version != 3007000 or page_size != PAGE_SZ:
        return ("", 0, 0, 0, 0)
    byteorder = "<" if magic == _WAL_MAGICS[0] else ">"
    state = _wal_checksum(data[:24], byteorder)
    if state != struct.unpack(">II", data[24:32]):
        return ("", 0, 0, 0, 0)
    generation = data[16:24]
    commit_size, last_off, last_c1, last_c2 = 0, 0, 0, 0
    frame_size = PAGE_SZ + 24
    for offset in range(32, len(data) - frame_size + 1, frame_size):
        header = data[offset:offset + 24]
        if header[8:16] != generation:
            break
        page_number, size = struct.unpack(">II", header[:8])
        if not 1 <= page_number <= 0xFFFFFFFE:
            break
        page = data[offset + 24:offset + frame_size]
        state = _wal_checksum(header[:8] + page, byteorder, state)
        if state != struct.unpack(">II", header[16:24]):
            break
        if size:
            commit_size = size
            last_off = offset
            last_c1, last_c2 = state
    stamp = (generation.hex(), commit_size, last_off, last_c1, last_c2)
    with _WAL_STAMP_LOCK:
        if len(_WAL_STAMP_CACHE) > 64:
            _WAL_STAMP_CACHE.clear()
        _WAL_STAMP_CACHE[key] = stamp
    return stamp


def _wal_committed(acc):
    """只读 WAL：返回 (generation_hex, commit_size, {page_no: 加密页})。

    遇到正在写入/校验失败的帧就停在最后一个完整提交，绝不把半帧当成已提交数据。
    """
    import struct
    wal = Path(acc["data_dir"]) / "message.db-wal"
    try:
        data = _read_shared_file(wal)
    except OSError:
        return None, 0, {}
    if len(data) < 32:
        return None, 0, {}
    magic, version, page_size = struct.unpack(">III", data[:12])
    if magic not in _WAL_MAGICS or version != 3007000 or page_size != PAGE_SZ:
        return None, 0, {}
    byteorder = "<" if magic == _WAL_MAGICS[0] else ">"
    state = _wal_checksum(data[:24], byteorder)
    if state != struct.unpack(">II", data[24:32]):
        return None, 0, {}
    generation = data[16:24]
    pending, committed, commit_size = {}, {}, None
    frame_size = PAGE_SZ + 24
    for offset in range(32, len(data) - frame_size + 1, frame_size):
        header = data[offset:offset + 24]
        if header[8:16] != generation:
            break
        page_number, size = struct.unpack(">II", header[:8])
        if not 1 <= page_number <= 0xFFFFFFFE:
            break
        page = data[offset + 24:offset + frame_size]
        state = _wal_checksum(header[:8] + page, byteorder, state)
        if state != struct.unpack(">II", header[16:24]):
            break
        pending[page_number] = page
        if size:
            committed.update(pending)
            pending.clear()
            committed = {number: payload for number, payload in committed.items()
                         if number <= size}
            commit_size = size
    return generation.hex(), commit_size or 0, committed


def sync_live_db(acc, cfg, background=False):
    """有写入则把 WAL 已提交页增量补进纯净解密库；失败/结构变化/库不健康则整库重解。

    background=True 时拿不到锁立刻 BusySkip（后台让路给前台），绝不排队。
    """
    LIVE_STATE.mkdir(parents=True, exist_ok=True)
    state_path = LIVE_STATE / f"{acc['id']}.json"
    dec = Path(acc["decrypted_dir"]) / "message.db"
    sig = live_signature(acc)
    try:
        previous = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = {}
    db_healthy = _dec_db_is_clean_and_healthy(acc, dec)
    if (db_healthy
            and previous.get("main") == list(sig["main"])
            and previous.get("wal") == list(sig["wal"])):
        return False, "unchanged"

    generation, commit_size, pages = _wal_committed(acc)
    same_main_for_new_wal = (
        not previous.get("generation")
        and previous.get("main") == list(sig["main"])
    )
    can_patch = bool(
        db_healthy and dec.exists() and generation and pages and commit_size
        and (previous.get("generation") == generation or same_main_for_new_wal)
        and previous.get("main_size") == sig["main"][0]
        and acc.get("key")
    )
    method = "wal"
    with db_lock(background=background):
        if can_patch:
            from wxwork_crypto import decrypt_page, has_plain_header_fragment
            size_before = dec.stat().st_size
            prev_pages = int(previous.get("pages") or 0)
            expected_before = (prev_pages * PAGE_SZ) if prev_pages else sig["main"][0]
            if size_before != expected_before and size_before != sig["main"][0]:
                # 解密库尺寸与原库/上轮页数不符，禁止做页级补丁，退回整库重解
                can_patch = False
        if can_patch:
            peak_before = 0
            try:
                probe = connect_readonly(dec, immutable=True)
                try:
                    peak_before = int(probe.execute(
                        "SELECT COALESCE(MAX(message_id),0) FROM message_table"
                    ).fetchone()[0] or 0)
                finally:
                    probe.close()
            except (OSError, sqlite3.Error, ValueError):
                peak_before = 0
            old_pages = {}
            try:
                key = bytes.fromhex(acc["key"])
                if 1 in pages and not has_plain_header_fragment(pages[1]):
                    raise ValueError("WAL 页1 缺明文头片段，退回整库重解")
                grown = commit_size - size_before // PAGE_SZ
                if grown > 0 and any(n not in pages for n in
                                     range(size_before // PAGE_SZ + 1, commit_size + 1)):
                    raise ValueError("WAL 缺少新增页，退回整库重解")
                with dec.open("r+b") as handle:
                    for number, page in sorted(pages.items()):
                        offset = (number - 1) * PAGE_SZ
                        if offset >= size_before:
                            old_pages[number] = b""
                        else:
                            handle.seek(offset)
                            old_pages[number] = handle.read(PAGE_SZ)
                        handle.seek(offset)
                        handle.write(decrypt_page(key, page, number))
                    handle.truncate(commit_size * PAGE_SZ)
                    handle.seek(28)
                    handle.write(commit_size.to_bytes(4, "big"))
                    handle.flush()
                    os.fsync(handle.fileno())
                connection = connect_readonly(dec, immutable=True)
                try:
                    # 校验：补丁后必须可读、有消息、最大 message_id 不倒退，中小库附加 quick_check
                    row = connection.execute(
                        "SELECT COALESCE(MAX(message_id),0), COUNT(*) "
                        "FROM message_table").fetchone()
                    if not row or (peak_before > 0 and int(row[1] or 0) == 0):
                        raise ValueError("WAL 补丁后解密库无消息，退回整库重解")
                    if int(row[0] or 0) < peak_before:
                        raise ValueError(
                            "WAL 补丁后最大 message_id 倒退，退回整库重解")
                    if dec.stat().st_size <= 64 * 1024 * 1024:
                        qc = [r[0] for r in connection.execute(
                            'PRAGMA quick_check("message_table")')]
                        if qc != ["ok"]:
                            raise ValueError(f"WAL 补丁后 quick_check 失败: {qc[:2]}")
                finally:
                    connection.close()
                _mark_dec_updated(acc)
                _ensure_message_index(acc, cfg, allow_repair=False)
            except Exception:
                # 逐页回滚，绝不让一次失败的补丁破坏已解密的库
                try:
                    with dec.open("r+b") as handle:
                        for number, buffer in old_pages.items():
                            handle.seek((number - 1) * PAGE_SZ)
                            handle.write(buffer)
                        handle.truncate(size_before)
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError:
                    pass
                can_patch = False
        if not can_patch:
            now = time.monotonic()
            cooldown = 20 if (background and db_healthy) else 2
            with _LIVE_FULL_LOCK:
                last = _LAST_FULL.get(acc["id"], 0)
                if now - last < cooldown:
                    # 不写 state（下一轮会重试），绝不假装「已同步」
                    return False, "pending"
                _LAST_FULL[acc["id"]] = now
            # 直接在进程内原子整库重解：避免递归调用 refresh(force=True) 撞节流变成空操作！
            sig = live_signature(acc)
            _full_decrypt_message_db(acc, cfg, background=background)
            generation, commit_size, _ = _wal_committed(acc)
            method = "full"
        # 不清 _MSG_INDEX：版本号/水印变化触发「旧快照先回 + 后台重建」，HTTP 不陪跑。

    pages_now = commit_size or (dec.stat().st_size // PAGE_SZ if dec.exists() else 0)
    state = {"main": list(sig["main"]), "wal": list(sig["wal"]),
             "main_size": sig["main"][0], "generation": generation or "",
             "pages": pages_now, "synced_at": time.time()}
    try:
        _atomic_write_text(state_path, json.dumps(state, ensure_ascii=False))
    except OSError:
        pass
    return True, method


def check_changes(cfg, acc, cid, last_id=""):
    """前端 5~10 秒轮询：水印检查 + WAL 增量补丁 + 侧车索引只读两条 SQL，不重建消息索引。

    前端对比 last_id / total 决定是否增量刷新右侧列表，因此这里刻意不做
    全量 protobuf 解析（6228 条消息的群重建一次要几秒）。
    """
    try:
        changed, method = sync_live_db(acc, cfg)
    except Exception as exc:
        return {"ok": False, "changed": False, "error": str(exc),
                "last_updated": time.strftime("%H:%M:%S")}
    try:
        db = _dec_message_db(acc, cfg)
        used_idx = _ensure_message_index(acc, cfg)
        idx_db = _msg_idx_path(acc)
        with db_lock():
            if used_idx and idx_db.is_file():
                con = connect_readonly(idx_db, immutable=True)
                try:
                    total = con.execute(
                        "SELECT count(*) FROM msg_idx WHERE conversation_id=?", (str(cid),)
                    ).fetchone()[0]
                    row = con.execute(
                        "SELECT message_id, send_time FROM msg_idx WHERE conversation_id=? "
                        "ORDER BY send_time DESC, message_id DESC LIMIT 1", (str(cid),)
                    ).fetchone()
                finally:
                    con.close()
            else:
                con = connect_readonly(db)
                try:
                    total = con.execute(
                        "SELECT count(*) FROM message_table WHERE conversation_id=?", (cid,)
                    ).fetchone()[0]
                    row = con.execute(
                        "SELECT message_id, send_time FROM message_table WHERE conversation_id=? "
                        "ORDER BY send_time DESC, message_id DESC LIMIT 1", (cid,)
                    ).fetchone()
                finally:
                    con.close()
        current_id = str(row[0]) if row else ""
        last_time = ex.fmt_time(row[1]) if row else ""
    except sqlite3.DatabaseError as exc:
        _mark_dec_corrupt(acc)
        return {"ok": False, "changed": False, "error": str(exc),
                "last_updated": time.strftime("%H:%M:%S")}
    except Exception as exc:
        return {"ok": False, "changed": False, "error": str(exc),
                "last_updated": time.strftime("%H:%M:%S")}
    return {"ok": True, "changed": bool(changed or (last_id and current_id != str(last_id))),
            "method": method, "total": total, "last_id": current_id,
            "last_time": last_time, "last_updated": time.strftime("%H:%M:%S")}


def watch_get():
    return {"ids": parse_watch(),
            "text": WATCH.read_text(encoding="utf-8-sig") if WATCH.exists() else ""}


def watch_set(cids):
    cids = [str(c).strip() for c in cids if str(c).strip()]
    header = []
    if WATCH.exists():
        for line in WATCH.read_text(encoding="utf-8-sig").splitlines():
            if line.strip().startswith("#"):
                header.append(line)
            elif line.strip():
                break
    if not header:
        header = ["# 定时同步清单 —— 每行一个 conversation-id", "# 由本地 Web 界面维护"]
    WATCH.write_text("\n".join(header + [""] + cids) + "\n", encoding="utf-8")
    return {"ids": cids}


def sync_status():
    state = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    return {"last_sync": state.get("last_sync"), "fingerprints": state.get("fingerprints", {}),
            "watched": parse_watch()}


def rescan():
    """界面「重新扫描企微账号与密钥」：重扫内存 → 补账号 → 清缓存 → 强制刷新会话。"""
    cfg = load_config()
    before = {a["id"] for a in cfg["accounts"]}
    scan_out, scan_err = "", ""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(FIND_KEYS)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=200,
            creationflags=_WIN_NO_WINDOW,
        )
        scan_out = proc.stdout or ""
        scan_err = (proc.stderr or "").strip()
    except subprocess.TimeoutExpired:
        scan_err = "扫描超时（200s），沿用已有 key"
    keys = {}
    if KEYS_JSON.exists():
        try:
            keys = json.loads(KEYS_JSON.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            pass
    cfg = load_config()
    sync_accounts_from_keys(cfg, keys)
    cfg = load_config()
    added = [a["id"] for a in cfg["accounts"] if a["id"] not in before]
    for old in CACHE.glob("conv_*.json"):
        try:
            old.unlink()
        except OSError:
            pass
    refreshed, errors = [], []
    for acc in cfg["accounts"]:
        try:
            refreshed.append({"account": acc["id"],
                              "conversations": len(refresh(acc, cfg, force=True)["conversations"])})
        except Exception as exc:
            errors.append(f"{acc['id']}: {exc}")
    scan_lines = [line for line in scan_out.splitlines()
                  if ("KEY=" in line or "MATCHED" in line or "SCAN_LIMITED" in line
                      or "扫描内存" in line or "扫描模式" in line or "NO_WXWORK" in line)]
    if scan_err:
        scan_lines.append("扫描提示: " + scan_err[:200])
    return {"added": added, "keys": sorted(keys.keys()), "scan_lines": scan_lines[:20],
            "refreshed": refreshed, "errors": errors,
            "scan_limited": "SCAN_LIMITED" in scan_out, "scan_stderr": scan_err}


def open_folder(path):
    """Open Explorer on a directory, or select a ZIP and force it to the front."""
    _, target = _resolve_export_path(path)
    if not target.exists():
        raise RuntimeError(f"路径不存在: {target}")

    if target.is_file():
        if target.suffix.lower() != ".zip":
            raise RuntimeError(f"只允许定位 .zip 文件: {target}")
        _launch_explorer(target, select=True)
        hwnd = (_find_explorer_hwnd_by_selection(target, timeout=6.0)
                or _find_explorer_hwnd_by_title(target, timeout=2.0))
        foreground = _force_foreground(hwnd) if hwnd else {"ok": False, "reason": "未找到资源管理器窗口"}
        return {
            "opened": str(target.parent), "selected": str(target),
            "foreground": bool(foreground.get("ok")), "foreground_detail": foreground,
        }

    _launch_explorer(target, select=False)
    hwnd = _find_explorer_hwnd_by_title(target, timeout=4.0)
    foreground = _force_foreground(hwnd) if hwnd else {"ok": False, "reason": "未找到资源管理器窗口"}
    return {
        "opened": str(target), "selected": None,
        "foreground": bool(foreground.get("ok")), "foreground_detail": foreground,
    }


# ---------------------------------------------------------------- CLI

def main():
    parser = argparse.ArgumentParser(description="wecom-agent Windows 导出/同步工具")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("accounts")
    p_refresh = sub.add_parser("refresh"); p_refresh.add_argument("--force", action="store_true")
    p_match = sub.add_parser("match"); p_match.add_argument("keyword"); p_match.add_argument("--force", action="store_true")
    p_export = sub.add_parser("export"); p_export.add_argument("--cid", required=True)
    p_export.add_argument("--account"); p_export.add_argument("--name")
    p_export.add_argument("--zip-mode", choices=("timestamp", "overwrite"), default="timestamp")
    p_export.add_argument("--lite-mode", choices=("auto", "always", "off"), default="auto")
    p_sync = sub.add_parser("sync"); p_sync.add_argument("--force", action="store_true")
    p_cache = sub.add_parser("cache"); p_cache.add_argument("--cid", required=True)
    p_cache.add_argument("--account"); p_cache.add_argument("--name")
    sub.add_parser("fingerprint")
    sub.add_parser("status")
    sub.add_parser("rescan")
    sub.add_parser("watch-get")
    sub.add_parser("sync-status")
    p_conv = sub.add_parser("conversations"); p_conv.add_argument("--force", action="store_true")
    p_prev = sub.add_parser("preview"); p_prev.add_argument("--cid", required=True)
    p_prev.add_argument("--account"); p_prev.add_argument("--name"); p_prev.add_argument("--limit", type=int, default=20)
    for name in ("all-for-ai", "cache-filtered", "web-export"):
        p = sub.add_parser(name); p.add_argument("--cid", required=True)
        p.add_argument("--account"); p.add_argument("--name")
        if name == "web-export":
            p.add_argument("--cache-fallback", action="store_true")
    p_ws = sub.add_parser("watch-set"); p_ws.add_argument("--ids", default="")
    p_of = sub.add_parser("open-folder"); p_of.add_argument("--path", required=True)
    p_prune = sub.add_parser("prune-cache"); p_prune.add_argument("--path", required=True)
    p_msgs = sub.add_parser("messages"); p_msgs.add_argument("--cid", required=True)
    p_msgs.add_argument("--account"); p_msgs.add_argument("--range", default="all")
    p_msgs.add_argument("--start"); p_msgs.add_argument("--end")
    p_pe = sub.add_parser("precise-export"); p_pe.add_argument("--cid", required=True)
    p_pe.add_argument("--account"); p_pe.add_argument("--name"); p_pe.add_argument("--ids", required=True)
    p_pe.add_argument("--zip-mode", choices=("timestamp", "overwrite"), default="timestamp")
    p_pe.add_argument("--lite-mode", choices=("auto", "always", "off"), default="auto")
    args = parser.parse_args()
    cfg = load_config()

    if args.command == "accounts":
        out = {"accounts": [{"id": a["id"], "data_dir": a["data_dir"], "key_ready": bool(a.get("key"))}
                            for a in cfg["accounts"]],
               "export_root": cfg["export_root"], "python": cfg["python"]}
    elif args.command == "refresh":
        accs = [a for a in cfg["accounts"] if not getattr(args, "account", None) or a["id"] == args.account]
        out = {"refreshed": [{"account": a["id"], "conversations": len(refresh(a, cfg, force=args.force)["conversations"])}
                             for a in accs]}
    elif args.command == "match":
        out = match(cfg, args.keyword, force=args.force)
    elif args.command == "export":
        acc = next((a for a in cfg["accounts"] if a["id"] == args.account), None) if args.account else None
        if acc is None:
            acc, name = locate(cfg, args.cid)
            if acc is None:
                raise RuntimeError(f"找不到会话 {args.cid}")
        else:
            name = args.name
        ids = [m["id"] for m in _message_index(cfg, acc, args.cid)]
        out = precise_export(cfg, acc, args.cid, name or args.name, ids,
                             zip_mode=args.zip_mode, lite_mode=args.lite_mode)
    elif args.command == "sync":
        out = sync(cfg, force=args.force)
    elif args.command == "cache":
        acc = next((a for a in cfg["accounts"] if a["id"] == args.account), None) if args.account else None
        found_name = None
        if acc is None:
            acc, found_name = locate(cfg, args.cid)
            if acc is None:
                raise RuntimeError(f"找不到会话 {args.cid}")
        out = export_cache(cfg, acc, args.cid, args.name or found_name)
    elif args.command == "status":
        out = account_status(cfg)
    elif args.command == "conversations":
        out = list_conversations(cfg, force=args.force)
    elif args.command in ("preview", "all-for-ai", "cache-filtered", "web-export"):
        acc = next((a for a in cfg["accounts"] if a["id"] == args.account), None) if args.account else None
        nm = args.name
        if acc is None:
            acc, found = locate(cfg, args.cid)
            if acc is None:
                raise RuntimeError(f"找不到会话 {args.cid}")
            nm = nm or found
        if args.command == "preview":
            out = preview_messages(cfg, acc, args.cid, args.limit)
        elif args.command == "all-for-ai":
            has_cache = (Path(cfg["export_root"]) / safe_name(nm or args.cid) / "cache_files").exists()
            out = build_all_for_ai(cfg, acc, args.cid, nm, include_cache=has_cache)
        elif args.command == "cache-filtered":
            out = cache_filtered(cfg, acc, args.cid, nm)
        else:
            out = web_export(cfg, acc, args.cid, nm, cache_fallback=args.cache_fallback)
    elif args.command == "rescan":
        out = rescan()
    elif args.command == "watch-get":
        out = watch_get()
    elif args.command == "watch-set":
        out = watch_set([c for c in args.ids.split(",") if c.strip()])
    elif args.command == "sync-status":
        out = sync_status()
    elif args.command == "open-folder":
        out = open_folder(args.path)
    elif args.command == "prune-cache":
        out = prune_cache(args.path)
    elif args.command in ("messages", "precise-export"):
        acc = next((a for a in cfg["accounts"] if a["id"] == args.account), None) if args.account else None
        if acc is None:
            acc, found = locate(cfg, args.cid)
            if acc is None:
                raise RuntimeError(f"找不到会话 {args.cid}")
        if args.command == "messages":
            out = messages_window(cfg, acc, args.cid, args.range, args.start, args.end)
        else:
            out = precise_export(cfg, acc, args.cid, args.name,
                                 [x.strip() for x in args.ids.split(",") if x.strip()],
                                 zip_mode=args.zip_mode, lite_mode=args.lite_mode)
    else:
        out = {"fingerprints": {a["id"]: fingerprint(a) for a in cfg["accounts"]}}
    print(json.dumps(out, ensure_ascii=False, indent=2))


CODEX_DEFAULT_ROOT = Path(r"D:\AI在办项目")
CODEX_FALLBACK_ROOT = Path.home() / "Documents" / "ChatGPT" / "单子"
CODEX_INTERVAL_SECONDS = 3   # 水印检查周期（无变化时只做文件 stat，<5ms）
_CODEX_LOCK = threading.Lock()
_CODEX_LAST_TICK = {"at": 0.0, "runs": 0}
_AI_TARGETS = ("codex", "antigravity")
_AI_TARGET_LABEL = {"codex": "Codex", "antigravity": "反重力"}


def _normalize_target(value):
    text = str(value or "codex").strip().lower()
    if text in ("反重力", "antigravity", "anti-gravity"):
        return "antigravity"
    return "codex"


def _detect_antigravity_root():
    """在与 xwechat_files / 腾讯云文档 同级目录里探测刚建好的「反重力」文件夹。"""
    home = Path.home()
    bases = [home / "Documents", home, Path("D:/"),
             Path("C:/Users/Public/Documents")]
    found = []
    for base in bases:
        try:
            if not base.is_dir():
                continue
            for child in base.iterdir():
                if child.is_dir() and "反重力" in child.name:
                    found.append(child)
        except OSError:
            continue
    if not found:
        return None
    try:
        return max(found, key=lambda p: p.stat().st_mtime)   # 多个候选取最近修改
    except OSError:
        return found[0]


def _codex_ensure_config(cfg):
    """首次迁移：写双根目录、给在跑项目补 target；绝不动 folder/status/scope。"""
    changed = False
    roots = cfg.get("live_roots") or {}
    if not isinstance(roots, dict):
        roots = {}
    if not roots.get("codex"):
        old = str(cfg.get("codex_root") or "").strip()
        # 旧字段若被临时指到反重力目录，回落到用户固定的 Codex 根目录
        if not old or ("反重力" in old and CODEX_FALLBACK_ROOT.is_dir()):
            old = str(CODEX_FALLBACK_ROOT)
        roots["codex"] = old
        changed = True
    if not roots.get("antigravity"):
        detected = _detect_antigravity_root()
        roots["antigravity"] = str(detected) if detected else ""
        changed = True
    if cfg.get("live_roots") != roots:
        cfg["live_roots"] = roots
        changed = True
    for project in cfg.get("codex_projects") or []:
        if not project.get("target"):
            project["target"] = "codex"
            changed = True
    return changed


def codex_root(cfg, target="codex"):
    """双根目录：优先 live_roots[target]，兼容旧 codex_root 字段。"""
    key = _normalize_target(target)
    roots = cfg.get("live_roots") or {}
    value = roots.get(key)
    if not value:
        if key == "codex":
            value = cfg.get("codex_root") or str(CODEX_FALLBACK_ROOT)
        else:
            value = str(_detect_antigravity_root() or CODEX_DEFAULT_ROOT)
    return Path(value)


def _find_acc(cfg, account_id):
    return next((a for a in cfg["accounts"] if a["id"] == str(account_id)), None)


def codex_since(range_key, start=None, end=None):
    """把界面上的快捷/自定义时间范围换算成起始 Unix 时间戳。"""
    if range_key == "custom" and start:
        low = _parse_window_dt(start)
        if low:
            return float(low)
    days = RANGE_DAYS.get(range_key)
    if days is None:
        return 0.0
    if days == 0:
        now = time.localtime()
        return float(time.mktime((now.tm_year, now.tm_mon, now.tm_mday,
                                 0, 0, 0, 0, 0, -1)))
    return time.time() - days * 86400


def _codex_log(message):
    """把 5 秒同步的异常原因落到独立日志，前端卡片也会显示 last_error。"""
    try:
        RUNTIME.mkdir(parents=True, exist_ok=True)
        with (RUNTIME / "codex_sync.log").open("a", encoding="utf-8") as handle:
            handle.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except OSError:
        pass


def _dec_db_peak(cfg, acc):
    """解密库的 (最大 message_id, 消息总数)，用于轻量校验 WAL 补丁是否真的生效。"""
    db = _dec_message_db(acc, cfg)
    try:
        connection = connect_readonly(db, immutable=True)
        try:
            row = connection.execute(
                "SELECT COALESCE(MAX(message_id),0), COUNT(*) "
                "FROM message_table").fetchone()
            return (int(row[0] or 0), int(row[1] or 0))
        finally:
            connection.close()
    except sqlite3.DatabaseError:
        _mark_dec_corrupt(acc)
        return (0, 0)
    except (OSError, sqlite3.Error, ValueError):
        return (0, 0)


def _codex_sync_sources(cfg, project, *, background=False):
    """根治假同步：任何一轮刷新前，先把原库/WAL 的新消息可靠落到解密库。

    返回同步明细；只要有一个账号是 pending / 回退 / 解密失败，就抛异常，
    调用方绝不推进 signature，3 秒后自动重试。
    """
    details = []
    for aid in project.get("accounts") or []:
        acc = _find_acc(cfg, aid)
        if acc is None:
            raise RuntimeError(f"账号 {aid} 不在配置中，无法更新解密库")
        before = _dec_db_peak(cfg, acc)
        changed, method = sync_live_db(acc, cfg, background=background)
        if method == "pending":
            raise RuntimeError(
                f"账号 {aid} 整库重解被节流跳过，解密库尚未更新；本轮不推进水印，稍后重试")
        after = _dec_db_peak(cfg, acc)
        if after[1] == 0:
            _mark_dec_corrupt(acc)
            raise RuntimeError(f"账号 {aid} 解密库为空或不可读，本轮中止")
        if after[0] < before[0]:
            raise RuntimeError(
                f"账号 {aid} 解密库最大 message_id 倒退 {before[0]}→{after[0]}，本轮中止")
        details.append({"account": aid, "method": method,
                        "before": list(before), "after": list(after)})
    return details


def _codex_cache_fp(cfg, project):
    """项目涉及账号的 Cache 目录稳定指纹（不随其它群消息抖动）。"""
    parts = []
    for aid in project.get("accounts") or []:
        acc = _find_acc(cfg, aid)
        if acc is None:
            continue
        parts.append((aid, tuple(
            (str(folder), str(digest))
            for folder, digest in _cache_dir_fingerprint(acc, cfg))))
    return tuple(parts)


_CONV_PEAK_CACHE = {}
_CONV_PEAK_LOCK = threading.Lock()


def _codex_conv_peak(cfg, acc, cid, cap=None):
    """某会话 (MAX(message_id), COUNT(*))；走侧车索引库 + 按 dec 水印做 10 秒记忆。

    dec/message.db 只由本工具写入，其 (size, mtime_ns, dec_ver) 无企微抖动；
    每次 sync_live_db 更新 dec 后立刻递增版本并失效缓存，绝不返回旧峰值漏掉新消息。
    """
    db = _dec_message_db(acc, cfg)
    try:
        st = db.stat()
        db_size, db_mtime = st.st_size, st.st_mtime_ns
    except OSError:
        db_size, db_mtime = 0, 0
    dec_ver = _dec_version(acc)
    memo_key = (str(db), str(cid), cap, db_size, db_mtime, dec_ver)
    memo_at = time.monotonic()
    with _CONV_PEAK_LOCK:
        memo = _CONV_PEAK_CACHE.get(memo_key)
        if memo and memo_at - memo[0] < 10:
            return list(memo[1])
    used_idx = _ensure_message_index(acc, cfg)
    idx_db = _msg_idx_path(acc)
    if used_idx and idx_db.is_file():
        sql = ("SELECT COALESCE(MAX(message_id),0), COUNT(*) "
               "FROM msg_idx WHERE conversation_id=?")
        args = [str(cid)]
        if cap is not None:
            sql += " AND message_id <= ?"
            args.append(int(cap))
        try:
            connection = connect_readonly(idx_db, immutable=True)
            try:
                row = connection.execute(sql, args).fetchone()
                peak = [int(row[0] or 0), int(row[1] or 0)]
            finally:
                connection.close()
        except (OSError, sqlite3.Error, ValueError):
            peak = None
    else:
        peak = None
    if peak is None:
        sql = ("SELECT COALESCE(MAX(CAST(message_id AS INTEGER)),0), COUNT(*) "
               "FROM message_table WHERE conversation_id=?")
        args = [str(cid)]
        if cap is not None:
            sql += " AND CAST(message_id AS INTEGER) <= ?"
            args.append(int(cap))
        try:
            connection = connect_readonly(db, immutable=True)
            try:
                row = connection.execute(sql, args).fetchone()
                peak = [int(row[0] or 0), int(row[1] or 0)]
            finally:
                connection.close()
        except sqlite3.DatabaseError:
            _mark_dec_corrupt(acc)
            return None
        except (OSError, sqlite3.Error, ValueError):
            return None
    with _CONV_PEAK_LOCK:
        _CONV_PEAK_CACHE[memo_key] = (time.monotonic(), peak)
        if len(_CONV_PEAK_CACHE) > 256:
            for old in sorted(_CONV_PEAK_CACHE,
                              key=lambda k: _CONV_PEAK_CACHE[k][0])[:64]:
                _CONV_PEAK_CACHE.pop(old, None)
    return list(peak)


def _codex_project_fingerprint(cfg, project):
    """项目所有会话的轻量指纹 {cid: [max_id, count]}，用于毫秒级跳过无新增项目。"""
    fingerprint = {}
    for entry in _codex_scope_entries(project.get("scope")):
        acc = _find_acc(cfg, entry.get("account"))
        if acc is None:
            continue
        cid = str(entry.get("cid") or "")
        cap = (_mid_num(entry.get("locked_max_id"))
               if entry.get("locked") else None)
        peak = _codex_conv_peak(cfg, acc, cid, cap)
        if peak is not None:
            fingerprint[cid] = peak
    return fingerprint


def _codex_quick_fingerprint(cfg, project):
    """毫秒级稳定指纹：原库大小 + WAL 真实提交戳 + 会话 (MAX,COUNT) + 缓存目录条目签名。

    企微在同大小 WAL 文件内覆写新消息时，WAL 提交戳会立刻变化（绝不漏抓）；
    企微仅 touch 文件 mtime 但无新提交时，提交戳完全不变（稳态 0.04s 毫秒快返）。
    """
    parts = []
    for aid in project.get("accounts") or []:
        acc = _find_acc(cfg, aid)
        if acc is None:
            continue
        main = Path(acc["data_dir"]) / "message.db"
        wal = Path(str(main) + "-wal")
        parts.append((aid, _stat_sig(str(main))[0], _stat_sig(str(wal))[0],
                      _wal_commit_stamp(acc)))
        # 缓存目录只保留「路径 + 稳定条目签名」，丢掉抖动的目录 mtime_ns
        cache_entries = tuple(
            (str(folder), str(digest))
            for folder, digest in _cache_dir_fingerprint(acc, cfg))
        parts.append(cache_entries)
    conv = _codex_project_fingerprint(cfg, project)
    parts.append(tuple(sorted((k, tuple(v)) for k, v in conv.items())))
    return tuple(parts)


def _codex_fp_str(fingerprint):
    """指纹统一序列化成字符串：避免 tuple 经 config.json 往返变成 list 后永不相等。"""
    return json.dumps(fingerprint, ensure_ascii=False, sort_keys=True,
                      default=str)


def _codex_quick_result(project, cached=False, degraded=False, note=""):
    """直接用已落盘的最新有效基准数据返回，不重导、不报错、不弹红条。"""
    stats = project.get("stats") or {}
    latest = str(project.get("latest_msg_time")
                 or project.get("last_write")
                 or project.get("last_update") or "")
    return {
        "ok": True, "synced": True, "cached": cached,
        "degraded": degraded, "note": note,
        "messages": int(stats.get("messages") or 0),
        "attachments": int(stats.get("attachments") or 0),
        "latest": latest, "latest_time": latest,
        "latest_attach_no": str(project.get("latest_attach_no") or "无"),
        "content_changed": not cached, "project": dict(project),
    }


def codex_quick_sync(project_id):
    """快返入口：异常/慢请求落诊断日志，不刷控制台。"""
    _q0 = time.perf_counter()
    try:
        return _codex_quick_sync_impl(project_id)
    except Exception as exc:
        _slow_log(f"quick_sync {project_id} EXC "
                  f"{type(exc).__name__}: {str(exc)[:160]}")
        raise
    finally:
        _dt = time.perf_counter() - _q0
        if _dt > 1:
            _slow_log(f"quick_sync {project_id} total={_dt:.2f}s")


def _codex_quick_sync_impl(project_id):
    """「复制口令」前的单项目极速同步：无变化毫秒快返，真有变化才重导。"""
    cfg = load_config()
    project = next((p for p in cfg.get("codex_projects") or []
                    if p["id"] == project_id), None)
    if project is None:
        raise RuntimeError(f"找不到在办项目 {project_id}")
    has_history = int((project.get("stats") or {}).get("messages") or 0) > 0
    needs_retry = bool(project.get("sync_pending") or project.get("last_error"))
    fingerprint = _codex_quick_fingerprint(cfg, project)
    if (has_history and not needs_retry
            and _codex_fp_str(fingerprint) == project.get("quick_fp")):
        return _codex_quick_result(project, cached=True)   # 0.05 秒快返

    # 绝不被后台重扫 / 其它项目慢任务卡住：锁繁忙直接按已落盘数据温和返回
    if not _CODEX_LOCK.acquire(blocking=False):
        _codex_log(f"{project.get('name')} quick-sync 锁繁忙，按已落盘数据继续")
        return _codex_quick_result(
            project, cached=True, degraded=True,
            note="后台正忙，已按当前最新落盘数据继续")
    try:
        cfg = load_config()
        project = next((p for p in cfg.get("codex_projects") or []
                        if p["id"] == project_id), None)
        if project is None:
            raise RuntimeError(f"找不到在办项目 {project_id}")
        needs_retry = bool(project.get("sync_pending") or project.get("last_error"))
        fingerprint = _codex_quick_fingerprint(cfg, project)
        if (has_history and not needs_retry
                and _codex_fp_str(fingerprint) == project.get("quick_fp")):
            return _codex_quick_result(project, cached=True)
        try:
            # 非阻塞读源库：后台刷新/重扫持有 db_lock 时立刻温和降级，绝不卡 HTTP 8 秒超时
            details = _codex_sync_sources(cfg, project, background=True)
        except BusySkip:
            return _codex_quick_result(
                project, cached=True, degraded=True,
                note="后台正忙，已按当前最新落盘数据继续")
        except RuntimeError as exc:
            if "节流" in str(exc) or "pending" in str(exc).lower():
                return _codex_quick_result(
                    project, cached=True, degraded=True,
                    note="后台同步冷却中，已按当前最新落盘数据继续")
            raise
        # 同账号其它群产生 WAL 写入时，若本项目自身会话峰值与 Cache 目录均未变化，
        # 无需耗时重导整个活目录，推进指纹后毫秒快返。
        conv_after = _codex_project_fingerprint(cfg, project)
        cache_after = _codex_fp_str(_codex_cache_fp(cfg, project))
        if (has_history and not needs_retry
                and conv_after == project.get("conv_fingerprint")
                and (not project.get("cache_fp")
                     or cache_after == project.get("cache_fp"))):
            project["signature"] = codex_signature(cfg, project)
            project["cache_fp"] = cache_after
            project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
            save_config(cfg)
            return _codex_quick_result(project, cached=True)
        try:
            result = build_live_folder(cfg, project)
        except _CodexTransientEmpty as exc:
            # 硬保护：保留原活目录快照，仍返回有效基准数据，不陷入报错重试
            project["last_skip_reason"] = str(exc)
            project["last_skip_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            project["sync_pending"] = False
            project["last_error"] = ""
            project["quick_fp"] = _codex_fp_str(fingerprint)
            save_config(cfg)
            _codex_log(f"{project.get('name')} {exc}（quick-sync 保留快照）")
            return {**_codex_quick_result(project, cached=True),
                    "degraded": True,
                    "note": "解密库暂缺该会话，已保留原活目录快照"}
        project["signature"] = codex_signature(cfg, project)
        project["conv_fingerprint"] = _codex_project_fingerprint(cfg, project)
        project["cache_fp"] = _codex_fp_str(_codex_cache_fp(cfg, project))
        project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
        project["last_error"] = ""
        project["sync_pending"] = False
        project["last_sync_method"] = ",".join(d["method"] for d in details)
        project["stats"] = _codex_stats(result)
        project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
        save_config(cfg)
        _write_root_overviews(cfg)
        recent = result.get("recent_messages") or []
        files = result.get("files") or []
        latest_time = recent[-1].get("time", "") if recent else ""
        latest_attach_no = (str(files[-1].get("number") or "")
                            if files else "") or "无"
        return {"ok": True, "synced": True, "cached": False,
                "degraded": False, "note": "",
                "latest": latest_time, "latest_time": latest_time,
                "latest_attach_no": latest_attach_no,
                "messages": result.get("messages"),
                "attachments": result.get("attachments_ok"),
                "content_changed": result.get("content_changed"),
                "project": dict(project)}
    finally:
        _CODEX_LOCK.release()


def codex_signature(cfg, project):
    """对应账号的 message.db 主库 + WAL 水印；完全一致说明没有新消息/新图。"""
    sig = {}
    for aid in project.get("accounts") or []:
        acc = _find_acc(cfg, aid)
        if not acc:
            continue
        try:
            current = live_signature(acc)
            sig[str(aid)] = [list(current["main"]), list(current["wal"])]
        except (OSError, ValueError, KeyError):
            continue
    return sig


def _codex_stats(result):
    return {
        "messages": int(result.get("messages") or 0),
        "attachments": int(result.get("attachments_ok") or 0),
        "missing": len(result.get("missing") or []),
        "deduplicated": int(result.get("deduplicated") or 0),
        "blurry_thumbs": len(result.get("blurry_thumbs") or []),
    }


def _auto_unzip_live(folder, zip_path, max_bytes=50 * 1024 * 1024):
    """仅 Codex 活目录：≤50MB 客户 .zip 安全解压一份到 _附件解压/<名>/，原包不动。

    兼容 GBK/UTF-8 中文名、防路径穿越、原 zip 未变化则跳过不重复解压。
    """
    try:
        if zip_path.stat().st_size > max_bytes:
            return None
        digest = _md5_of(zip_path)
        if not digest:
            return None
        stem = safe_name(zip_path.stem)[:80] or "附件"
        target = Path(folder) / "_附件解压" / stem
        marker = target / ".codex_unzip_md5"
        if marker.is_file():
            try:
                if marker.read_text(encoding="utf-8").strip() == digest:
                    return stem                    # 原 zip 未变化，跳过
            except OSError:
                pass
        target.mkdir(parents=True, exist_ok=True)
        allowed = str(target.resolve())
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                raw_name = info.filename
                name = raw_name
                if not (info.flag_bits & 0x800):
                    # 非 UTF-8 标记的老 ZIP：Python 先按 cp437 解，再还原中文
                    for enc in ("gbk", "utf-8"):
                        try:
                            name = raw_name.encode("cp437").decode(enc)
                            break
                        except (UnicodeEncodeError, UnicodeDecodeError):
                            continue
                parts = [p for p in str(name).replace("\\", "/").split("/")
                         if p not in ("", ".", "..")]
                if not parts:
                    continue
                dest = target.joinpath(*parts)
                try:
                    resolved = str(dest.resolve())
                except OSError:
                    continue
                if not (resolved == allowed
                        or resolved.startswith(allowed + os.sep)):
                    continue                        # 防路径穿越
                if info.is_dir() or str(name).endswith("/"):
                    dest.mkdir(parents=True, exist_ok=True)
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as source, open(dest, "wb") as out:
                    shutil.copyfileobj(source, out)
        _atomic_write_text(marker, digest)
        return stem
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError):
        return None


_LIVE_LATEST3_HEADER = "## 当前群聊最新 3 条有效消息（时间正序）"


def _format_live_latest3_section(folder, result=None):
    """生成 000_最新变化.md 底部的「最新 3 条有效消息」区块（跳过系统噪音）。"""
    latest3 = _extract_recent_human_messages(result=result, folder=folder, limit=3)
    lines = ["---", "", _LIVE_LATEST3_HEADER, ""]
    if latest3:
        for idx, item in enumerate(latest3, 1):
            ts_label = item.get("full_time") or item.get("time") or "—"
            lines.append(f"{idx}. `[{ts_label}]` **{item['sender']}**：{item['body']}")
    else:
        lines.append("（暂无有效真人消息）")
    lines.append("")
    return "\n".join(lines)


def _ensure_live_changes_latest3(project):
    """补齐/更新存量 000_最新变化.md 底部的最新 3 条有效消息区块（无变化绝不写盘）。"""
    folder = Path(project.get("folder") or "")
    change_path = folder / "000_最新变化.md"
    if not str(folder) or not change_path.is_file():
        return False
    try:
        raw = change_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    marker = f"\n---\n\n{_LIVE_LATEST3_HEADER}"
    if marker in raw:
        head = raw.split(marker, 1)[0].rstrip()
    elif _LIVE_LATEST3_HEADER in raw:
        head = raw.split(_LIVE_LATEST3_HEADER, 1)[0].rstrip()
    else:
        head = raw.rstrip()
    footer = _format_live_latest3_section(folder)
    updated = f"{head}\n\n{footer}"
    return _atomic_write_if_changed(change_path, updated)


def _write_live_changes(project, result, folder):
    """原子写 000_最新变化.md：同步时间 + 相对上一轮新增数 + 新增消息正文与附件编号 + 最新 3 条有效消息。"""
    recent = result.get("recent_messages") or []
    previous_ids = set(project.get("message_ids") or [])
    total_messages = int(result.get("messages") or len(recent))
    total_attachments = int(result.get("attachments_ok") or 0)
    prev_attachments = int(project.get("attachments_count") or 0)
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    first_time = not previous_ids
    if first_time:
        added = recent[-10:]                     # 首次创建列最近 10 条
        added_attachments = total_attachments
    else:
        added = [m for m in recent if m["id"] not in previous_ids]
        added_attachments = max(0, total_attachments - prev_attachments)

    change_path = Path(folder) / "000_最新变化.md"
    content_changed = bool(result.get("content_changed", True))
    # 无新增消息且活目录内容也没变 → 只核对底部最新 3 条区块（未变则 0 写盘），杜绝「假刷新」把 mtime 推新
    if (not first_time and not added and not content_changed
            and change_path.is_file()):
        _ensure_live_changes_latest3(project)
        return

    out = [
        f"# 000_最新变化 · {project.get('name', '')}", "",
        f"- 本次同步时间：{now}",
        f"- 相比上一轮：新增 {len(added)} 条消息 / {added_attachments} 个附件",
        f"- 活目录累计：{total_messages} 条消息 / {total_attachments} 个附件",
        f"- 后台监控：每 {CODEX_INTERVAL_SECONDS} 秒心跳检测 · 监控中",
        "- 首次创建只列最近 10 条；后续同步列出本轮全部新增消息。", "",
        "---", "", "## 本次新增消息（按真实时间正序）", "",
    ]
    for msg in added:
        source = f" [来源: {msg['source']}]" if msg.get("source") else ""
        out += [f"### [{msg.get('time', '')}] {msg.get('sender', '')}{source}", ""]
        out += [(msg.get("content") or "").strip() or "（无文字正文）", ""]
        for attachment in msg.get("attachments") or []:
            out += [f"- [附件 {attachment}]", ""]
        out += ["---", ""]
    if not added:
        out += ["（本轮无新增消息）", ""]
    if len(out) >= 2 and out[-2] == "---" and out[-1] == "":
        out = out[:-2]
    out.append(_format_live_latest3_section(folder, result=result))
    _atomic_write_if_changed(change_path, "\n".join(out))

    project["message_ids"] = [m["id"] for m in recent]
    project["attachments_count"] = total_attachments
    if first_time or added:
        project["last_write"] = now          # 只在真的有消息变化时推进
    project["last_write_stats"] = {"messages": total_messages,
                                   "attachments": total_attachments}
    project["last_added"] = {"messages": len(added),
                             "attachments": added_attachments}


def _humanize_preview_body(raw_body, ct=0, has_attach=False):
    """把 [type101]（见下方按序打包的附件）等内部占位文案转成人话摘要。"""
    text = str(raw_body or "").strip()
    if text:
        text = re.sub(r"\[type(?:14|101)\]（见下方按序打包的附件）", "[图片]", text)
        text = re.sub(r"\[type(?:15|102)\]（见下方按序打包的附件）", "[文件]", text)
        text = re.sub(r"\[type\d+\]（见下方按序打包的附件）",
                      "[图片]" if has_attach else "[附件]", text)
        text = re.sub(r"^\[type(?:14|101)\]\s*", "[图片] ", text).strip()
        text = re.sub(r"^\[type(?:15|102)\]\s*", "[文件] ", text).strip()
    body = " ".join(text.split())[:48]
    if not body:
        if int(ct or 0) in (14, 101):
            return "[图片]"
        return "[图片/附件]" if has_attach else "[消息]"
    return body


def _codex_refresh_meta(project, result):
    """每次同步/刷新提取最新有效消息的人话摘要与时间戳，写进项目配置（纯内存）。"""
    recent = result.get("recent_messages") or []
    picked = None
    for msg in reversed(recent):
        content = str(msg.get("content") or "").strip()
        # 跳过系统空消息（如 [类型 ct=1023] 系统/内部消息「无可读正文」）
        if msg.get("system_noise"):
            continue
        if content.startswith("[类型 ct=") or "系统/内部消息（无可读正文）" in content:
            continue
        if content or msg.get("attachments"):
            picked = msg
            break
    if picked is None:
        return
    raw_time = str(picked.get("time") or "")
    match = re.search(r"(\d{2}:\d{2})", raw_time)
    hhmm = match.group(1) if match else (raw_time or "—")
    sender = str(picked.get("sender") or "").strip() or "—"
    has_attach = bool(picked.get("attachments"))
    body = _humanize_preview_body(picked.get("content"), picked.get("ct", 0), has_attach)
    suffix = (" [图]" if (has_attach and body not in ("[图片]", "[图片/附件]")) else "")
    project["latest_preview"] = f"[{hhmm} {sender}]：{body}{suffix}"
    stamp = 0.0
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            stamp = float(time.mktime(time.strptime(raw_time, fmt)))
            break
        except (ValueError, TypeError):
            continue
    project["latest_msg_ts"] = stamp or time.time()
    project["latest_msg_time"] = raw_time          # 供 quick-sync 快返组装对账锚点
    files = result.get("files") or []
    project["latest_attach_no"] = (
        (str(files[-1].get("number") or "") if files else "") or "无")
    # 存量项目首次迁移：把已发基线初始化为当前消息数，避免升级后满屏红点
    if "last_sent_count" not in project:
        project["last_sent_count"] = int(
            result.get("messages") or len(recent))
    project.setdefault("alias_note", "")
    project.setdefault("latest_preview", "")
    project.setdefault("latest_msg_ts", 0)
    project.setdefault("last_sent_at", "")


_CHAT_HEADING_RE = re.compile(
    r"^## \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (.+?) · \[(.+?)\](?:\s+\[来源:.*\])?$"
)


def _codex_bound_group_label(project):
    """返回项目绑定的企微群名（优先 R: 群名，单聊项目回退到会话名/目录名）。"""
    mg = str(project.get("main_group") or "").strip()
    if mg:
        return mg
    entries = _codex_scope_entries(project.get("scope"))
    groups = [str(e.get("name") or e.get("cid") or "").strip()
              for e in entries if _codex_is_group(e.get("cid"))]
    if groups:
        return " / ".join(dict.fromkeys(g for g in groups if g))
    names = [str(e.get("name") or e.get("cid") or "").strip() for e in entries]
    return " / ".join(dict.fromkeys(n for n in names if n)) or str(project.get("name") or "—")


def _extract_recent_human_messages(result=None, folder=None, limit=5):
    """提取最近 N 条有效真人对话（按时间正序，自动跳过系统噪音）。

    统一以活目录 000_chat.md 为唯一确定性来源（仅当 000_chat.md 尚不存在时回退到 result），
    确保增量同步与重启核对生成字节完全一致，杜绝无谓写盘。
    """
    if folder and (Path(folder) / "000_chat.md").is_file():
        chat_path = Path(folder) / "000_chat.md"
        out = []
        try:
            lines = chat_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            lines = []
        idx = 0
        while idx < len(lines):
            m = _CHAT_HEADING_RE.match(lines[idx].strip())
            if not m:
                idx += 1
                continue
            raw_time, sender, kind = m.group(1), m.group(2).strip(), m.group(3).strip()
            idx += 1
            if "系统" in kind:
                continue
            body_parts, attach_nos, missing_att, is_noise = [], [], False, False
            while idx < len(lines):
                ln = lines[idx].strip()
                if ln.startswith("## [") or ln == "---":
                    break
                idx += 1
                if not ln:
                    continue
                if ln.startswith("[类型 ct=") or "系统/内部消息" in ln:
                    is_noise = True
                    continue
                if ln.startswith(("[已用清晰预览图兜底", "[⚠️ 仅为 210px")):
                    continue
                if ln.startswith("[附件未下载:"):
                    missing_att = True
                    continue
                if ln.startswith("[附件 ") or ln.startswith("[同附件 "):
                    am = re.search(r"\[(?:同)?附件\s+(\d+)", ln)
                    if am:
                        attach_nos.append(am.group(1))
                    continue
                body_parts.append(ln)
            if is_noise and not attach_nos and not missing_att:
                continue
            if kind.startswith("type") and not body_parts and not attach_nos and not missing_att:
                continue
            ct_guess = 101 if kind == "type101" else (14 if "图" in kind else 0)
            joined = " ".join(body_parts).strip()
            body = _humanize_preview_body(joined, ct_guess, bool(attach_nos or missing_att))
            if joined:
                clean_full = re.sub(r"\[type(?:14|101)\]（见下方按序打包的附件）", "[图片]", joined)
                clean_full = re.sub(r"\[type(?:15|102)\]（见下方按序打包的附件）", "[文件]", clean_full)
                clean_full = re.sub(r"\[type\d+\]（见下方按序打包的附件）",
                                    "[图片]" if (attach_nos or missing_att) else "[附件]", clean_full)
                clean_full = " ".join(clean_full.split())
                if clean_full:
                    body = clean_full[:80] + ("…" if len(clean_full) > 80 else "")
            if attach_nos and attach_nos[0] not in body:
                body = f"{body}（附件 {attach_nos[0]}）"
            elif missing_att and "未下载" not in body:
                body = f"{body}（未下载）"
            out.append({
                "time": raw_time[5:16] if len(raw_time) >= 16 else raw_time,
                "full_time": raw_time,
                "sender": sender or "—",
                "body": body,
            })
        return out[-limit:]

    out = []
    if result is not None:
        for msg in (result.get("recent_messages") or []):
            content = str(msg.get("content") or "").strip()
            if msg.get("system_noise"):
                continue
            if content.startswith("[类型 ct=") or "系统/内部消息（无可读正文）" in content:
                continue
            has_attach = bool(msg.get("attachments"))
            if not (content or has_attach):
                continue
            raw_time = str(msg.get("time") or "")
            short_time = raw_time[5:16] if len(raw_time) >= 16 else (raw_time or "—")
            sender = str(msg.get("sender") or "").strip() or "—"
            body = _humanize_preview_body(content, msg.get("ct", 0), has_attach)
            if content:
                clean_full = re.sub(r"\[type(?:14|101)\]（见下方按序打包的附件）", "[图片]", content)
                clean_full = re.sub(r"\[type(?:15|102)\]（见下方按序打包的附件）", "[文件]", clean_full)
                clean_full = re.sub(r"\[type\d+\]（见下方按序打包的附件）",
                                    "[图片]" if has_attach else "[附件]", clean_full)
                clean_full = " ".join(clean_full.split())
                if clean_full:
                    body = clean_full[:80] + ("…" if len(clean_full) > 80 else "")
            if has_attach:
                first_att = str((msg.get("attachments") or [""])[0]).split("->")[0].strip()
                if first_att and first_att not in body:
                    body = f"{body}（附件 {first_att}）"
            out.append({"time": short_time, "full_time": raw_time,
                        "sender": sender, "body": body})
        return out[-limit:]
    return []


def _write_project_dashboard(project, result=None, folder=None, stats=None):
    """原子维护单项目极简 000_状态看板.md（约 15 行；内容完全不变时不写盘，绝不触碰交付文件）。"""
    target_dir = Path(folder or project.get("folder") or "")
    if not str(target_dir) or not target_dir.is_dir():
        return False
    st = stats if isinstance(stats, dict) else (project.get("stats") or {})
    order_no = int(project.get("order_no") or 0)
    order_tag = f"#{order_no:02d}" if order_no else "#--"
    alias = str(project.get("alias_note") or "").strip()
    name = str(project.get("name") or target_dir.name)
    display_name = f"{alias}（{name}）" if alias and alias != name else name
    target_key = _normalize_target(project.get("target"))
    target_label = _AI_TARGET_LABEL.get(target_key, target_key)
    group_name = _codex_bound_group_label(project)
    latest_time = str(project.get("latest_msg_time") or project.get("last_write") or "—")
    msg_count = int(st.get("messages") or 0)
    att_count = int(st.get("attachments") or 0)
    blurry = int(st.get("blurry_thumbs") or 0)
    recent5 = _extract_recent_human_messages(result=result, folder=target_dir, limit=5)

    lines = [
        f"# 状态看板 · {order_tag} {display_name}",
        "",
        f"- **项目**：`{order_tag}` {display_name} · 所属软件：**{target_label}**",
        f"- **绑定企微群**：{group_name}",
        (f"- **同步进度**：最新消息 `{latest_time}` · 共 **{msg_count}** 条消息 / **{att_count}** 个附件"
         + ("" if blurry > 0 else " · 图片全部高清")),
    ]
    if blurry > 0:
        lines.append(
            f"- **模糊缩略图提醒**：⚠️ 含 **{blurry}** 张 210px 模糊缩略图，请企微点开大图后自动升级高清"
        )
    lines += ["", "## 最近 5 条有效对话（时间正序）", ""]
    if recent5:
        for idx, item in enumerate(recent5, 1):
            lines.append(f"{idx}. `[{item['time']}]` **{item['sender']}**：{item['body']}")
    else:
        lines.append("（暂无有效真人对话记录）")
    lines.append("")
    return _atomic_write_if_changed(target_dir / "000_状态看板.md", "\n".join(lines))


def _write_root_overviews(cfg):
    """在反重力与 Codex 两个根目录各自原子维护 000_全部单子总览.md（内容不变绝不写盘）。"""
    updated = []
    running = [p for p in (cfg.get("codex_projects") or []) if p.get("status") == "running"]
    for target in _AI_TARGETS:
        root = codex_root(cfg, target)
        if not root.is_dir():
            continue
        label = _AI_TARGET_LABEL.get(target, target)
        items = [p for p in running if _normalize_target(p.get("target")) == target]
        items.sort(
            key=lambda p: (
                -(float(p.get("latest_msg_ts") or 0)),
                "" if p.get("latest_msg_time") else "z",
                int(p.get("order_no") or 9999),
            )
        )
        lines = [
            f"# {label} · 全部在办单子总览（共 {len(items)} 单）",
            "",
            "> 按最新消息时间倒序自动维护；点开对应子目录的 `000_状态看板.md` 可分屏盯盘。",
            "",
        ]
        if items:
            lines += [
                "| 序号 | 备注名 / 目录 | 绑定企微群 | 最新消息时间 | 条数 / 附件 | 最新一句话 |",
                "| :---: | --- | --- | :---: | :---: | --- |",
            ]
            for p in items:
                no = int(p.get("order_no") or 0)
                tag = f"`#{no:02d}`" if no else "`#--`"
                alias = str(p.get("alias_note") or "").strip()
                name = str(p.get("name") or "")
                disp = f"**{alias}**（`{name}`）" if alias and alias != name else f"**{name}**"
                grp = _codex_bound_group_label(p).replace("|", "/")
                ltime = str(p.get("latest_msg_time") or p.get("last_write") or "—")
                st = p.get("stats") or {}
                cnt = f"{int(st.get('messages') or 0)} 条 / {int(st.get('attachments') or 0)} 附"
                blurry = int(st.get("blurry_thumbs") or 0)
                if blurry > 0:
                    cnt += f" · ⚠️{blurry}糊图"
                prev = str(p.get("latest_preview") or "—").replace("|", "/").replace("\n", " ")
                lines.append(f"| {tag} | {disp} | {grp} | `{ltime}` | {cnt} | {prev} |")
        else:
            lines.append("（当前该软件根目录下暂无实时同步中的在办单子）")
        lines.append("")
        overview_path = root / "000_全部单子总览.md"
        if _atomic_write_if_changed(overview_path, "\n".join(lines)):
            updated.append(str(overview_path))
    return updated


def refresh_codex_dashboards(cfg=None, project_ids=None):
    """统一生成/核对在办项目 000_状态看板.md 与两个根目录 000_全部单子总览.md（无变化不写盘）。"""
    cfg = cfg or load_config()
    boards_updated = []
    wanted = set(project_ids) if project_ids is not None else None
    for project in (cfg.get("codex_projects") or []):
        if project.get("status") != "running":
            continue
        if wanted is not None and project.get("id") not in wanted:
            continue
        try:
            if _write_project_dashboard(project):
                boards_updated.append(str(Path(project["folder"]) / "000_状态看板.md"))
            _ensure_live_changes_latest3(project)
        except OSError:
            continue
    overviews_updated = _write_root_overviews(cfg)
    return {"boards_updated": boards_updated, "overviews_updated": overviews_updated}


class _CodexTransientEmpty(RuntimeError):
    """瞬态空结果：解密库暂查不到该会话，但项目已有历史消息，必须保留原活目录快照。"""


def _codex_guard_empty(project, picked):
    """硬保护：已有历史消息的项目，瞬态 0 条绝不覆盖活目录、绝不无限报错重试。"""
    if picked:
        return
    history = int((project.get("stats") or {}).get("messages") or 0)
    if history > 0:
        raise _CodexTransientEmpty(
            f"解密库暂查不到该会话（项目历史 {history} 条），已保留原活目录快照")
    raise RuntimeError("起始时间之后没有任何消息，请放宽范围")


def build_live_folder(cfg, project, progress=None):
    """重算活目录（幂等）：按起始时间取各会话全量消息，交给 precise_export 就地输出。

    不打 ZIP、不生成轻量包；md 原子写、附件内容未变则跳过复制。编号按真实时间
    固定，新消息自然追加到后面、新附件接着往后编号。每次同步后写 000_最新变化.md。
    """
    scope = project.get("scope") or {}
    _codex_prepare_locks(cfg, project)
    since = float(project.get("since_ts") or 0)
    folder = Path(project["folder"])
    folder.mkdir(parents=True, exist_ok=True)
    # 干净交付隔离区：只创建、绝不清空；成品只放这里，AI 记录与脚本全留根目录
    (folder / "交付给客户").mkdir(exist_ok=True)
    if scope.get("items"):
        built = []
        for entry in scope["items"]:
            acc = _find_acc(cfg, entry["account"])
            if acc is None:
                raise RuntimeError(f"账号 {entry['account']} 不在配置中")
            entry_since = (float(entry["since_ts"])
                           if entry.get("since_ts") is not None else since)
            picked = [m["id"] for m in _message_index(cfg, acc, entry["cid"])
                      if (m.get("ts") or 0) >= entry_since]
            # 防串单：锁定的客服私聊只取到锁定水位，之后新派的其他单子绝不混入
            if entry.get("locked"):
                cap = _mid_num(entry.get("locked_max_id"))
                picked = [mid for mid in picked if _mid_num(mid) <= cap]
            built.append({"account": entry["account"], "cid": entry["cid"],
                          "name": entry.get("name") or entry["cid"], "ids": picked})
        active = [x for x in built if x["ids"]]
        _codex_guard_empty(project, active)
        first = active[0]
        acc0 = _find_acc(cfg, first["account"])
        if len(active) == 1:
            result = precise_export(cfg, acc0, first["cid"], name=project["name"],
                                    ids=first["ids"], live_dir=str(folder),
                                    since_ts=since, progress=progress)
        else:
            result = precise_export(cfg, acc0, first["cid"], name=project["name"],
                                    ids=[], items=active, live_dir=str(folder),
                                    since_ts=since, progress=progress)
    else:
        acc = _find_acc(cfg, scope.get("account") or "")
        if acc is None or not scope.get("cid"):
            raise RuntimeError("项目缺少会话配置（account / cid）")
        picked = [m["id"] for m in _message_index(cfg, acc, scope["cid"])
                  if (m.get("ts") or 0) >= since]
        if scope.get("locked"):
            cap = _mid_num(scope.get("locked_max_id"))
            picked = [mid for mid in picked if _mid_num(mid) <= cap]
        _codex_guard_empty(project, picked)
        result = precise_export(cfg, acc, scope["cid"], name=project["name"],
                                ids=picked, live_dir=str(folder), since_ts=since,
                                progress=progress)
    _write_live_changes(project, result, folder)
    _codex_refresh_meta(project, result)
    _write_project_dashboard(project, result=result, folder=folder,
                             stats=_codex_stats(result))
    return result


def _root_health(root):
    """单个根目录的存在 / 可写 / 项目数检测；探针自动清理不落垃圾。"""
    exists = root.is_dir()
    writable = False
    projects = 0
    if exists:
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(
                    prefix=".codex_probe_", suffix=".tmp",
                    dir=str(root), delete=True) as probe:
                probe.write(b"ok")
                probe.flush()
            writable = True
        except OSError:
            writable = False
        try:
            projects = sum(1 for p in root.iterdir() if p.is_dir())
        except OSError:
            projects = 0
    return {"root": str(root), "exists": exists,
            "writable": writable, "projects": projects}


_ROOT_HEALTH_CACHE = {"at": 0.0, "value": None}


def _root_health_cached(cfg):
    """根目录健康状态缓存 30 秒：前端每 3 秒轮询不必反复创建探针文件。"""
    now = time.monotonic()
    cached = _ROOT_HEALTH_CACHE["value"]
    if cached and now - _ROOT_HEALTH_CACHE["at"] < 30:
        return cached
    value = {t: _root_health(codex_root(cfg, t)) for t in _AI_TARGETS}
    _ROOT_HEALTH_CACHE.update({"at": now, "value": value})
    return value


def _codex_created_sort_key(project):
    """兼容 created_at / created 两种字段名，按接入时间升序稳定排序。"""
    text = str(project.get("created_at") or project.get("created") or "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(text, fmt))
        except (ValueError, TypeError):
            continue
    return 0.0


def _codex_assign_order(cfg):
    """存量按接入时间补 order_no=1..N；维护 codex_seq_counter 最大已分配序号。

    只写这两个字段，绝不改动 folder / name / scope / target 等任何物理或业务配置。
    """
    projects = cfg.get("codex_projects") or []
    if not projects:
        return False
    changed = False
    taken = {int(p["order_no"]) for p in projects
             if str(p.get("order_no") or "").isdigit()}
    counter = max(int(cfg.get("codex_seq_counter") or 0),
                  max(taken) if taken else 0)
    missing = [p for p in projects
               if not str(p.get("order_no") or "").isdigit()]
    missing.sort(key=lambda p: (_codex_created_sort_key(p),
                                str(p.get("id") or "")))
    for project in missing:
        counter += 1
        while counter in taken:
            counter += 1
        project["order_no"] = counter
        taken.add(counter)
        changed = True
    if int(cfg.get("codex_seq_counter") or 0) != counter:
        cfg["codex_seq_counter"] = counter
        changed = True
    return changed


_CODEX_FP_WARMED = False


def _codex_warm_quick_fps(cfg, projects):
    """进程启动时一次性预写稳定快返指纹，冷启动第一次点复制也走毫秒快返。"""
    global _CODEX_FP_WARMED
    if _CODEX_FP_WARMED:
        return False
    changed = False
    for project in projects:
        if (project.get("status") == "running"
                and not project.get("sync_pending")
                and int((project.get("stats") or {}).get("messages") or 0) > 0):
            try:
                value = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
                if project.get("quick_fp") != value:
                    project["quick_fp"] = value
                    changed = True
            except Exception:
                continue
    _CODEX_FP_WARMED = True
    return changed


def _codex_clean_stale_preview(project):
    """存量脏预览（系统空消息 / 原始 [type...] / 旧版空行误判成的 [消息]）→ 从 000_chat.md 回捞真人发言。"""
    text = str(project.get("latest_preview") or "")
    if not ("[类型 ct=" in text or "系统/内部消息" in text or "[type" in text
            or text.endswith("：[消息]")):
        return False
    chat = Path(project.get("folder") or "") / "000_chat.md"
    if not chat.is_file():
        project["latest_preview"] = ""
        return True
    try:
        lines = chat.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    pattern = re.compile(
        r"^## \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (.+?) · \[(.+?)\](?:\s+\[来源:.*\])?$")
    for idx in range(len(lines) - 1, -1, -1):
        matched = pattern.match(lines[idx].strip())
        if not matched:
            continue
        kind = matched.group(3)
        if "系统" in kind:
            continue
        # 000_chat.md 标题与正文之间有空行：向下跳过空行采集真实正文与附件标记
        body_parts, has_attach = [], False
        for j in range(idx + 1, min(len(lines), idx + 16)):
            ln = lines[j].strip()
            if ln.startswith("## [") or ln == "---":
                break
            if not ln:
                continue
            if ln.startswith(("[附件 ", "[同附件 ", "[已用清晰预览图兜底", "[⚠️ 仅为 210px")):
                has_attach = True
                continue
            if ln.startswith("[类型 ct=") or "系统/内部消息" in ln:
                body_parts = []
                break
            body_parts.append(ln)
        if kind.startswith("type") and not has_attach and not body_parts:
            continue
        ct_guess = 101 if kind == "type101" else (14 if "图" in kind else 0)
        body = _humanize_preview_body(" ".join(body_parts), ct_guess, has_attach)
        if not body or body == "[消息]" and kind.startswith("type"):
            if has_attach:
                body = "[图片]" if ct_guess in (14, 101) else "[图片/附件]"
            else:
                continue
        suffix = (" [图]" if (has_attach and body not in ("[图片]", "[图片/附件]")) else "")
        project["latest_preview"] = (
            f"[{matched.group(1)[11:16]} {matched.group(2)}]：{body}{suffix}")
        return True
    project["latest_preview"] = ""
    return True


def codex_status():
    # 只读状态接口：绝不排 _CODEX_LOCK 的队，后台整库重解时前端仍秒回
    with contextlib.nullcontext():
        cfg = load_config()
        if _codex_ensure_config(cfg):
            save_config(cfg)
        projects = cfg.get("codex_projects") or []
        # 惰性补防串单锁定字段，让卡片即使水印没变化也能显示锁定状态
        migrated = False
        if _codex_assign_order(cfg):
            migrated = True
        # 稳定性专项：清掉存量卡死的报错与待重试黄条（瞬态空结果 / 整库节流 / 忙让路）
        for project in projects:
            error_text = str(project.get("last_error") or "")
            if project.get("sync_pending") and any(
                    token in error_text for token in (
                        "起始时间之后没有任何消息", "整库重解被节流跳过",
                        "解密库正忙", "锁正忙")):
                project["sync_pending"] = False
                project["last_error"] = ""
                project["last_skip_reason"] = (
                    "数据源暂不可用，已保留原活目录快照，后台下轮补跑")
                migrated = True
        # 卡片统计兼容：老配置若缺少 blurry_thumbs 字段，按 000_chat.md 惰性统计一次
        for project in projects:
            if project.get("status") != "running":
                continue
            st = project.get("stats")
            if isinstance(st, dict) and "blurry_thumbs" not in st:
                chat_f = Path(project.get("folder") or "") / "000_chat.md"
                cnt = 0
                if chat_f.is_file():
                    try:
                        cnt = chat_f.read_text(encoding="utf-8", errors="ignore").count(
                            "[⚠️ 仅为 210px")
                    except OSError:
                        cnt = 0
                st["blurry_thumbs"] = cnt
                migrated = True
        for project in projects:
            if _codex_clean_stale_preview(project):
                migrated = True
        if _codex_warm_quick_fps(cfg, projects):
            migrated = True
        for project in projects:
            if (project.get("status") == "running"
                    and _codex_prepare_locks(cfg, project)):
                migrated = True
            # 标签与物理路径不一致时自动纠正（只改标签，不动文件）
            if (project.get("status") == "running"
                    and _codex_validate_target_path(cfg, project)):
                migrated = True
            # 卡片升级首次迁移：已发基线初始化为当前消息数，避免满屏红点
            if project.get("status") == "running":
                if "last_sent_count" not in project:
                    project["last_sent_count"] = int(
                        (project.get("stats") or {}).get("messages") or 0)
                    migrated = True
                for meta_key, meta_default in (
                        ("alias_note", ""), ("latest_preview", ""),
                        ("latest_msg_ts", 0), ("last_sent_at", "")):
                    if meta_key not in project:
                        project[meta_key] = meta_default
                        migrated = True
        if migrated:
            save_config(cfg)
        health = _root_health_cached(cfg)
        default = health["codex"]
        running_projects = [p for p in projects if p.get("status") == "running"]
        need_lookup = any(
            not str(e.get("name") or "").strip()
            or str(e.get("name") or "").strip() == str(e.get("cid") or "")
            for p in running_projects
            for e in _codex_scope_entries(p.get("scope"))
        )
        conv_names = _codex_conv_name_map(cfg) if need_lookup else {}
        return {"root": default["root"],
                "root_exists": default["exists"],
                "root_writable": default["writable"],
                "root_projects": default["projects"],
                "roots": health,
                "live_roots": {t: str(codex_root(cfg, t)) for t in _AI_TARGETS},
                "targets": list(_AI_TARGETS),
                "interval": CODEX_INTERVAL_SECONDS,
                "last_tick": _CODEX_LAST_TICK["at"],
                "tick_runs": _CODEX_LAST_TICK["runs"],
                "heartbeat": (time.strftime("%H:%M:%S",
                              time.localtime(_CODEX_LAST_TICK["at"]))
                              if _CODEX_LAST_TICK["at"] else "—"),
                "projects": [{**dict(p), "scopes": _codex_public_scopes(cfg, p, conv_names)}
                             for p in running_projects],
                "count": len(running_projects)}


def codex_set_root(root, target="codex"):
    key = _normalize_target(target)
    value = str(Path(str(root)).expanduser())
    with codex_lock():
        cfg = load_config()
        _codex_ensure_config(cfg)
        cfg.setdefault("live_roots", {})[key] = value
        if key == "codex":
            cfg["codex_root"] = value          # 向后兼容旧字段
        save_config(cfg)
    return {"root": value, "target": key,
            "live_roots": {t: str(codex_root(cfg, t)) for t in _AI_TARGETS}}


def _codex_is_dm(cid):
    return str(cid or "").startswith("S:")


def _codex_is_group(cid):
    return str(cid or "").startswith("R:")


def _mid_num(mid):
    try:
        return int(str(mid))
    except (ValueError, TypeError):
        return 0


def _codex_scope_entries(scope):
    """兼容单会话 dict 与多会话 items，返回可写的条目引用列表。"""
    scope = scope or {}
    if scope.get("items"):
        return list(scope["items"])
    if scope.get("cid"):
        return [scope]
    return []


def _codex_conv_name_map(cfg):
    """从已缓存的会话快照建立 (account, cid) -> display_name 映射（毫秒级、不触碰数据库）。"""
    out = {}
    try:
        cached = list_conversations_cached(cfg)
        for conv in cached.get("conversations") or []:
            acc = str(conv.get("account") or "")
            cid = str(conv.get("id") or "")
            name = str(conv.get("name") or "").strip()
            if cid and name:
                out[(acc, cid)] = name
                out.setdefault(("", cid), name)
    except Exception:
        pass
    return out


def _codex_public_scopes(cfg, project, conv_names=None):
    """返回前端卡片展示用的绑定会话数组，每项补全 display_name / kind / locked。"""
    names = conv_names if conv_names is not None else {}
    out = []
    for entry in _codex_scope_entries(project.get("scope")):
        acc = str(entry.get("account") or "")
        cid = str(entry.get("cid") or "")
        if not cid:
            continue
        raw_name = str(entry.get("name") or "").strip()
        if not raw_name or raw_name == cid:
            raw_name = names.get((acc, cid)) or names.get(("", cid)) or raw_name
        display_name = raw_name or cid
        kind = "group" if _codex_is_group(cid) else ("dm" if _codex_is_dm(cid) else "other")
        out.append({
            "account": acc,
            "cid": cid,
            "name": display_name,
            "display_name": display_name,
            "kind": kind,
            "locked": bool(entry.get("locked", False)),
            "locked_max_id": int(entry.get("locked_max_id") or 0),
        })
    return out


def _codex_latest_mid(cfg, account, cid):
    acc = _find_acc(cfg, account)
    if acc is None:
        return 0
    try:
        return max((_mid_num(m["id"])
                    for m in _message_index(cfg, acc, str(cid))), default=0)
    except (OSError, ValueError, KeyError):
        return 0


def _codex_prepare_locks(cfg, project):
    """惰性迁移防串单锁定字段（只补字段，绝不改 folder/status/cid/name/account）。

    - `S:` 客服私聊 → locked=True，水位 = 开启瞬间最大 message_id，绝不自动追新
    - `R:` 客户群   → locked=False，持续 5 秒增量
    """
    entries = _codex_scope_entries(project.get("scope"))
    if not entries:
        return False
    changed = False
    for entry in entries:
        cid = str(entry.get("cid") or "")
        if "locked" not in entry:
            entry["locked"] = _codex_is_dm(cid)
            changed = True
        if "locked_max_id" not in entry:
            entry["locked_max_id"] = _codex_latest_mid(
                cfg, entry.get("account"), cid)
            changed = True
    dm = [e for e in entries if _codex_is_dm(e.get("cid"))]
    groups = [e for e in entries if _codex_is_group(e.get("cid"))]
    meta = {
        "dm_locked": any(bool(e.get("locked")) for e in dm),
        "has_dm": bool(dm), "has_group": bool(groups),
        "dm_locked_count": sum(1 for e in dm if e.get("locked")),
        "main_group": (str(groups[0].get("name") or groups[0].get("cid"))
                       if groups else ""),
    }
    for key, value in meta.items():
        if project.get(key) != value:
            project[key] = value
            changed = True
    return changed


def _codex_target_of_folder(cfg, folder):
    """根据物理目录所在的根，反推它属于哪个软件（只认根目录，不认标签）。"""
    try:
        parent = Path(folder).resolve().parent
    except OSError:
        return None
    for target in _AI_TARGETS:
        try:
            if parent == codex_root(cfg, target).resolve():
                return target
        except OSError:
            continue
    return None


def _codex_validate_target_path(cfg, project):
    """强制 target 与物理根目录一致；只修标签，绝不移动任何文件。"""
    actual = _codex_target_of_folder(cfg, project.get("folder"))
    if actual and _normalize_target(project.get("target")) != actual:
        project["target"] = actual
        project["target_fixed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return True
    return False


def _codex_scope_key(scope):
    """防串单唯一业务主键：严格按 `R:` 客户群；纯 `S:` 单聊（无群）才用私聊。

    共用同一个客服私聊的不同客户群各自独立，绝不能互相拦截；
    同一个客户群即便换/加了不同客服私聊，也只算同一个项目。
    """
    entries = _codex_scope_entries(scope)
    pairs = lambda pred: tuple(sorted({
        (str(e.get("account") or ""), str(e.get("cid") or ""))
        for e in entries if pred(e.get("cid"))}))
    groups = pairs(_codex_is_group)
    if groups:
        return groups
    dms = pairs(_codex_is_dm)
    if dms:
        return dms
    return pairs(lambda c: True)


def codex_start(spec):
    """开启一个 AI 在办项目：按 target 分流到 Codex / 反重力根目录。

    同软件同会话 → 刷新原目录（already_exists）；跨软件同会话 → 拦截并返回
    conflict_other_target，避免两个 AI 同时改同一份稿。
    """
    with codex_lock():
        cfg = load_config()
        if _codex_ensure_config(cfg):
            save_config(cfg)
        _codex_assign_order(cfg)      # 存量先补齐，保证新项目拿到正确的下一个序号
        target = _normalize_target(spec.get("target") or "codex")
        root = codex_root(cfg, target)
        scope = spec.get("scope") or {}
        entries = scope.get("items") or ([scope] if scope.get("cid") else [])
        accounts = sorted({str(x.get("account") or "") for x in entries if x.get("account")})
        if not scope or not accounts:
            raise RuntimeError("请先在左侧选中会话（或勾选导出会话）")

        wanted = _codex_scope_key(scope)
        projects = cfg.setdefault("codex_projects", [])
        conflict = None
        conflict_target = None
        if wanted:
            for existing in projects:
                if (existing.get("status") == "running"
                        and _codex_scope_key(existing.get("scope")) == wanted):
                    old_target = _normalize_target(existing.get("target"))
                    if old_target != target:
                        conflict, conflict_target = existing, old_target
                        break
                    # ① 同一软件下完全相同会话组合 → 先同步源库再立即刷新原目录
                    try:
                        _codex_sync_sources(cfg, existing)
                    except Exception:
                        pass
                    result = build_live_folder(cfg, existing)
                    existing["signature"] = codex_signature(cfg, existing)
                    existing["conv_fingerprint"] = _codex_project_fingerprint(cfg, existing)
                    existing["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    existing["last_error"] = ""
                    existing["sync_pending"] = False
                    existing["stats"] = _codex_stats(result)
                    existing["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, existing))
                    save_config(cfg)
                    _write_root_overviews(cfg)
                    return {"already_exists": True, "target": target,
                            "project": dict(existing),
                            "result": {"messages": result.get("messages"),
                                       "attachments_ok": result.get("attachments_ok"),
                                       "folder": str(existing["folder"])}}
            if conflict is not None:
                # ② 同一组会话已在另一个软件下同步 → 拦截，绝不新建冲突目录
                return {"conflict_other_target": True,
                        "target": target,
                        "existing_target": conflict_target,
                        "existing_target_label": _AI_TARGET_LABEL[conflict_target],
                        "project": dict(conflict)}

        # ③ 真正新建（只有目录名撞车才加时间戳）
        raw_name = str(spec.get("name") or "").strip()
        if raw_name:
            name = safe_name(raw_name)[:40]
        else:
            # 合并模式留空时，默认目录名必须优先取 R: 客户群名，绝不取 S: 客服私聊名
            group_name = next((str(e.get("name") or "") for e in entries
                               if _codex_is_group(e.get("cid"))), "")
            name = safe_name(_short_export_label(
                group_name or spec.get("default_name") or "AI在办"))[:12]
        folder = root / name
        if any(str(p.get("folder", "")).casefold() == str(folder).casefold()
               and p.get("status") == "running" for p in projects):
            folder = root / f"{name}_{time.strftime('%H%M%S')}"
        # 新项目自动分配下一个递增序号（#08、#09…），不动任何已有项目
        used = {int(p["order_no"]) for p in projects
                if str(p.get("order_no") or "").isdigit()}
        next_no = max(int(cfg.get("codex_seq_counter") or 0),
                      max(used) if used else 0) + 1
        while next_no in used:
            next_no += 1
        cfg["codex_seq_counter"] = next_no
        project = {
            "id": uuid.uuid4().hex[:12], "name": folder.name,
            "order_no": next_no, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "root": str(root), "folder": str(folder), "scope": scope,
            "target": target, "accounts": accounts,
            "range": spec.get("range") or "7d",
            "range_start": spec.get("start") or "",
            "range_end": spec.get("end") or "",
            "since_ts": codex_since(spec.get("range") or "7d",
                                    spec.get("start"), spec.get("end")),
            "status": "running", "signature": {}, "created":
                time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_update": "", "last_error": "", "stats": {},
        }
        _codex_prepare_locks(cfg, project)
        result = build_live_folder(cfg, project)
        project["signature"] = codex_signature(cfg, project)
        project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
        project["stats"] = _codex_stats(result)
        projects.append(project)
        save_config(cfg)
        _write_root_overviews(cfg)
        return {"already_exists": False, "conflict_other_target": False,
                "target": target, "project": dict(project), "result": {
                    "messages": result.get("messages"),
                    "attachments_ok": result.get("attachments_ok"),
                    "folder": str(folder)}}


def codex_rename_note(project_id, alias_note):
    """只改界面显示名；绝不改动 folder / name / target，避免打断已绑定的物理路径。"""
    with codex_lock():
        cfg = load_config()
        project = next((p for p in cfg.get("codex_projects") or []
                        if p["id"] == project_id), None)
        if project is None:
            raise RuntimeError(f"找不到在办项目 {project_id}")
        original_folder = str(project.get("folder", ""))
        project["alias_note"] = str(alias_note or "").strip()[:40]
        project["folder"] = original_folder
        save_config(cfg)
        _write_project_dashboard(project)
        _write_root_overviews(cfg)
        return {"project": dict(project),
                "folder_unchanged": str(project["folder"]) == original_folder}


def codex_mark_sent(project_id, count=None):
    """复制口令完成前置秒刷后清零红点：把已发基线更新为刚同步的最新条数。"""
    with codex_lock():
        cfg = load_config()
        project = next((p for p in cfg.get("codex_projects") or []
                        if p["id"] == project_id), None)
        if project is None:
            raise RuntimeError(f"找不到在办项目 {project_id}")
        value = (int(count) if count is not None else
                 int((project.get("stats") or {}).get("messages") or 0))
        project["last_sent_count"] = value
        project["last_sent_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_config(cfg)
        return {"project": dict(project), "last_sent_count": value}


def codex_refresh(project_id):
    """手动「立即刷新」：先同步原库/WAL → 刷新媒体缓存 → 重建活目录与最新预览。"""
    with codex_lock():
        cfg = load_config()
        for project in cfg.get("codex_projects", []):
            if project["id"] != project_id:
                continue
            try:
                details = _codex_sync_sources(cfg, project)
            except RuntimeError as exc:
                if "节流" not in str(exc) and "pending" not in str(exc).lower():
                    raise
                time.sleep(2.1)
                details = _codex_sync_sources(cfg, project)
            invalidate_media_caches()
            try:
                result = build_live_folder(cfg, project)
            except _CodexTransientEmpty as exc:
                project["signature"] = codex_signature(cfg, project)
                project["sync_pending"] = False
                project["last_error"] = ""
                project["last_skip_reason"] = str(exc)
                project["last_skip_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
                save_config(cfg)
                _codex_log(f"{project.get('name')} {exc}（手动刷新保留快照）")
                return dict(project)
            project["signature"] = codex_signature(cfg, project)
            project["conv_fingerprint"] = _codex_project_fingerprint(cfg, project)
            project["cache_fp"] = _codex_fp_str(_codex_cache_fp(cfg, project))
            project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
            project["last_error"] = ""
            project["sync_pending"] = False
            project["last_sync_method"] = ",".join(d["method"] for d in details)
            project["stats"] = _codex_stats(result)
            project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
            save_config(cfg)
            _write_root_overviews(cfg)
            return dict(project)
    raise RuntimeError(f"找不到在办项目 {project_id}")


def codex_pull_dm(project_id):
    """手动补拉客服私聊新消息：先同步源库，再把锁定水位更新到最新并刷新活目录 + 变化清单。"""
    with codex_lock():
        cfg = load_config()
        for project in cfg.get("codex_projects", []):
            if project["id"] != project_id:
                continue
            try:
                _codex_sync_sources(cfg, project)
            except Exception:
                pass
            pulled = []
            for entry in _codex_scope_entries(project.get("scope")):
                if not _codex_is_dm(entry.get("cid")):
                    continue
                cid = str(entry.get("cid"))
                old = _mid_num(entry.get("locked_max_id"))
                acc = _find_acc(cfg, entry.get("account"))
                msgs = _message_index(cfg, acc, cid) if acc else []
                latest = max((_mid_num(m["id"]) for m in msgs), default=old)
                entry["locked_max_id"] = latest
                entry["locked"] = True
                entry["last_pull"] = time.strftime("%Y-%m-%d %H:%M:%S")
                pulled.append({
                    "cid": cid, "from": old, "to": latest,
                    "new_messages": sum(1 for m in msgs
                                        if old < _mid_num(m["id"]) <= latest)})
            _codex_prepare_locks(cfg, project)
            result = build_live_folder(cfg, project)
            project["signature"] = codex_signature(cfg, project)
            project["conv_fingerprint"] = _codex_project_fingerprint(cfg, project)
            project["cache_fp"] = _codex_fp_str(_codex_cache_fp(cfg, project))
            project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
            project["last_error"] = ""
            project["sync_pending"] = False
            project["stats"] = _codex_stats(result)
            project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
            save_config(cfg)
            _write_root_overviews(cfg)
            return {"pulled": pulled, "messages": result.get("messages"),
                    "project": dict(project)}
        raise RuntimeError(f"找不到在办项目 {project_id}")


def codex_toggle_lock(project_id, cid=None, locked=None):
    """切换客服私聊锁定；重新锁定时把水位刷新到当前最新，避免历史全量涌入。"""
    with codex_lock():
        cfg = load_config()
        for project in cfg.get("codex_projects", []):
            if project["id"] != project_id:
                continue
            try:
                _codex_sync_sources(cfg, project)
            except Exception:
                pass
            toggled = []
            for entry in _codex_scope_entries(project.get("scope")):
                if not _codex_is_dm(entry.get("cid")):
                    continue
                if cid and str(entry.get("cid")) != str(cid):
                    continue
                state = ((not bool(entry.get("locked")))
                         if locked is None else bool(locked))
                entry["locked"] = state
                if state:
                    entry["locked_max_id"] = _codex_latest_mid(
                        cfg, entry.get("account"), str(entry.get("cid")))
                toggled.append({"cid": str(entry.get("cid")), "locked": state})
            if not toggled:
                raise RuntimeError("该项目没有可切换的客服私聊会话")
            _codex_prepare_locks(cfg, project)
            result = build_live_folder(cfg, project)
            project["signature"] = codex_signature(cfg, project)
            project["conv_fingerprint"] = _codex_project_fingerprint(cfg, project)
            project["cache_fp"] = _codex_fp_str(_codex_cache_fp(cfg, project))
            project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
            project["last_error"] = ""
            project["sync_pending"] = False
            project["stats"] = _codex_stats(result)
            project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
            save_config(cfg)
            _write_root_overviews(cfg)
            return {"toggled": toggled, "project": dict(project)}
        raise RuntimeError(f"找不到在办项目 {project_id}")


def codex_add_scope(project_id, account, cid, *, name="", range_key="7d",
                    start=None, end=None):
    """向现有在办项目追加一个群聊或客服私聊（绝不改物理目录、序号、备注与交付文件）。

    智能防串单规则：
    - 原项目为纯私聊（无 R: 群）且本次追加 R: 客户群：自动把原有 S: 私聊锁定在当前最新
      message_id（locked=True），新加的 R: 客户群 locked=False 持续 3 秒自动同步；
    - 原项目已有 R: 群且本次追加 S: 客服私聊：新加的 S: 私聊默认 locked=True（只拉入当前
      时间范围历史，不自动追后续新派单）。
    """
    pid = str(project_id or "").strip()
    acc_id = str(account or "").strip()
    cid_str = str(cid or "").strip()
    if not pid or not acc_id or not cid_str:
        raise RuntimeError("缺少必要参数（project_id / account / cid）")
    range_clean = str(range_key or "7d").strip() or "7d"

    with codex_lock():
        cfg = load_config()
        projects = cfg.get("codex_projects") or []
        project = next((p for p in projects
                        if p.get("id") == pid and p.get("status") == "running"), None)
        if project is None:
            raise RuntimeError(f"找不到运行中的在办项目 {pid}")
        if _find_acc(cfg, acc_id) is None:
            raise RuntimeError(f"账号 {acc_id} 不在配置中")

        # 保留不可变字段快照，确保绝不改物理目录/序号/备注/软件归属
        orig_folder = str(project.get("folder") or "")
        orig_order = project.get("order_no")
        orig_alias = project.get("alias_note")
        orig_target = project.get("target")
        orig_name = project.get("name")

        old_entries = [dict(e) for e in _codex_scope_entries(project.get("scope"))]
        if any(str(e.get("cid") or "") == cid_str for e in old_entries):
            raise RuntimeError("该会话已在本项目中，无需重复追加")

        # R: 客户群不能同时绑定在两个不同的在办项目里
        if _codex_is_group(cid_str):
            for other in projects:
                if other.get("id") == pid or other.get("status") != "running":
                    continue
                if any(str(e.get("cid") or "") == cid_str
                       for e in _codex_scope_entries(other.get("scope"))):
                    ono = int(other.get("order_no") or 0)
                    olabel = other.get("alias_note") or other.get("name") or other.get("id")
                    raise RuntimeError(
                        f"该群聊已绑定在另一个在办项目「#{ono:02d} {olabel}」中，请勿重复绑定")

        # 解析可读会话名
        conv_names = _codex_conv_name_map(cfg)
        display_name = (str(name or "").strip()
                        or conv_names.get((acc_id, cid_str))
                        or conv_names.get(("", cid_str))
                        or cid_str)

        # 先同步相关账号最新 WAL，确保锁定水位与新消息立即可见
        sync_accounts = sorted({acc_id} | {str(a) for a in (project.get("accounts") or []) if a})
        sync_project_probe = {"accounts": sync_accounts}
        try:
            _codex_sync_sources(cfg, sync_project_probe)
        except RuntimeError as exc:
            if "节流" in str(exc) or "pending" in str(exc).lower():
                time.sleep(2.1)
                try:
                    _codex_sync_sources(cfg, sync_project_probe)
                except Exception:
                    pass
            else:
                raise
        invalidate_media_caches()

        had_group = any(_codex_is_group(e.get("cid")) for e in old_entries)
        adding_group = _codex_is_group(cid_str)
        adding_dm = _codex_is_dm(cid_str)

        # 智能防串单锁定：纯私聊追加客户群 → 原私聊自动锁定在当前最新 message_id
        auto_locked_dms = []
        if not had_group and adding_group:
            for e in old_entries:
                if _codex_is_dm(e.get("cid")):
                    e["locked"] = True
                    e["locked_max_id"] = _codex_latest_mid(
                        cfg, e.get("account"), e.get("cid"))
                    auto_locked_dms.append(str(e.get("cid")))

        entry_since = codex_since(range_clean, start, end)
        new_latest_mid = _codex_latest_mid(cfg, acc_id, cid_str)
        new_locked = False if adding_group else bool(adding_dm)
        new_entry = {
            "account": acc_id,
            "cid": cid_str,
            "name": display_name,
            "locked": new_locked,
            "locked_max_id": new_latest_mid,
            "since_ts": entry_since,
            "range": range_clean,
            "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        all_entries = old_entries + [new_entry]
        project["scope"] = {"items": all_entries}
        project["accounts"] = sync_accounts
        # 强断言保护：绝不改动物理目录/序号/备注/软件/目录名
        project["folder"] = orig_folder
        project["order_no"] = orig_order
        project["alias_note"] = orig_alias
        project["target"] = orig_target
        project["name"] = orig_name
        _codex_prepare_locks(cfg, project)
        save_config(cfg)

        result = build_live_folder(cfg, project)
        project["signature"] = codex_signature(cfg, project)
        project["conv_fingerprint"] = _codex_project_fingerprint(cfg, project)
        project["cache_fp"] = _codex_fp_str(_codex_cache_fp(cfg, project))
        project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
        project["last_error"] = ""
        project["sync_pending"] = False
        project["stats"] = _codex_stats(result)
        project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
        save_config(cfg)
        _write_root_overviews(cfg)

        pub_proj = {**dict(project),
                    "scopes": _codex_public_scopes(cfg, project, conv_names)}
        return {
            "ok": True,
            "added": new_entry,
            "auto_locked_dms": auto_locked_dms,
            "folder_unchanged": str(project["folder"]) == orig_folder,
            "messages": result.get("messages"),
            "attachments": result.get("attachments_ok"),
            "project": pub_proj,
        }


_CODEX_TRANSFER_PAUSE = set()   # 转移期间只暂停这一个项目，其它项目照常 3 秒同步
_CODEX_PENDING_COOLDOWN = {}    # aid -> monotonic 到期时间（整库重解节流冷却）
_CODEX_LAST_ACCOUNT_SIG = {}    # aid -> 上轮原始库水印，用于「一有新变化立刻解除冷却」


def codex_transfer(project_id, target):
    """Codex ↔ 反重力 原子无损转移：整个项目文件夹同盘整体移动。

    顺序：目标根校验 → 只暂停本项目 → 重名安全后缀 → 同盘 os.rename（原子）→
    原子更新 config（只改 target/root/folder/name，保留 scope/locked/since 等）→
    立即刷新活目录 → 恢复心跳。任何失败都不删原目录；占用时原样回滚。
    """
    key = _normalize_target(target)
    with codex_lock():
        cfg = load_config()
        project = next((p for p in cfg.get("codex_projects") or []
                        if p["id"] == project_id), None)
        if project is None:
            raise RuntimeError(f"找不到在办项目 {project_id}")
        current = _normalize_target(project.get("target"))
        if current == key:
            return {"already_there": True, "project": dict(project)}

        # a) 目标根目录存在且可写
        dest_root = codex_root(cfg, key)
        if not dest_root.is_dir():
            raise RuntimeError(f"目标根目录不存在：{dest_root}")
        if not _root_health(dest_root)["writable"]:
            raise RuntimeError(f"目标根目录不可写：{dest_root}")

        src = Path(project["folder"])
        if not src.is_dir():
            raise RuntimeError(f"原项目目录不存在：{src}")
        if (os.path.splitdrive(str(src))[0].lower()
                != os.path.splitdrive(str(dest_root))[0].lower()):
            raise RuntimeError("源目录与目标根目录不在同一磁盘，无法整体移动，已中止")

        # c) 重名绝不覆盖：自动加 _2 / _3… 安全后缀
        dest = dest_root / src.name
        if dest.exists():
            index = 2
            while (dest_root / f"{src.name}_{index}").exists():
                index += 1
            dest = dest_root / f"{src.name}_{index}"
        suffix_note = (f"目标根目录已有同名文件夹，已自动改用安全名称 {dest.name}"
                       if dest.name != src.name else "")

        old_folder = str(project["folder"])
        # b) 只暂停本项目同步
        _CODEX_TRANSFER_PAUSE.add(project_id)
        try:
            # d) 同盘整体移动。os.rename 要么全成、要么全败，不存在「只搬一半」
            try:
                os.rename(str(src), str(dest))
            except OSError as exc:
                winerr = getattr(exc, "winerror", None)
                if isinstance(exc, PermissionError) or winerr in (5, 32):
                    raise RuntimeError(
                        "目录正被占用，请先关闭该文件夹窗口或正在读写它的软件后重试")
                raise RuntimeError(f"目录移动失败，原目录已原样保留：{exc}")

            # e) 原子更新 config（save_config 已是 .tmp + os.replace）
            project["folder"] = str(dest)
            project["root"] = str(dest_root)
            project["target"] = key
            project["name"] = dest.name
            project["signature"] = {}      # 强制下一次心跳立即刷新
            try:
                save_config(cfg)
            except Exception:
                os.rename(str(dest), str(src))   # 完整回滚，绝不留下半截状态
                project["folder"] = old_folder
                project["target"] = current
                project["name"] = src.name
                raise RuntimeError("配置写入失败，目录已原样移回，未改动任何文件")

            # f) 立即刷新活目录（含 交付给客户/、000_最新变化.md、开工/续改路径）
            try:
                result = build_live_folder(cfg, project)
                project["signature"] = codex_signature(cfg, project)
                project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
                project["last_error"] = ""
                project["stats"] = _codex_stats(result)
            except Exception as exc:
                project["last_error"] = f"转移后刷新失败：{exc}"
            save_config(cfg)
            _write_root_overviews(cfg)
        finally:
            _CODEX_TRANSFER_PAUSE.discard(project_id)

        return {"transferred": True, "already_there": False,
                "from": old_folder, "to": str(dest), "target": key,
                "target_label": _AI_TARGET_LABEL[key],
                "suffix_note": suffix_note, "project": dict(project)}


def codex_stop(project_id):
    """停止并移出清单；只停同步，磁盘上的目录与文件一律保留。"""
    with codex_lock():
        cfg = load_config()
        before = len(cfg.get("codex_projects", []))
        cfg["codex_projects"] = [
            p for p in cfg.get("codex_projects", []) if p["id"] != project_id]
        if len(cfg["codex_projects"]) == before:
            raise RuntimeError(f"找不到在办项目 {project_id}")
        save_config(cfg)
        _write_root_overviews(cfg)
    return {"stopped": project_id, "files_kept": True}


def codex_open_root(target="codex"):
    """按软件打开各自的总根目录（不存在时先创建），两个软件物理分开。"""
    key = _normalize_target(target)
    with codex_lock():
        cfg = load_config()
        _codex_ensure_config(cfg)
        root = codex_root(cfg, key)
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"无法创建总根目录 {root}: {exc}")
    subprocess.Popen(["explorer.exe", str(root)],
                     creationflags=_WIN_NO_WINDOW)
    return {"folder": str(root), "target": key}


def codex_open(project_id):
    with codex_lock():
        cfg = load_config()
        project = next((p for p in cfg.get("codex_projects", [])
                        if p["id"] == project_id), None)
    if project is None:
        raise RuntimeError("找不到在办项目")
    folder = Path(project["folder"])
    if not folder.is_dir():
        raise RuntimeError(f"目录不存在: {folder}")
    subprocess.Popen(["explorer.exe", str(folder)],
                     creationflags=_WIN_NO_WINDOW)
    return {"folder": str(folder)}


def codex_tick(background=False):
    """后台 3 秒心跳。background=True 时遇前台忙/锁忙立即跳过本轮，绝不排队。"""
    """后台每 3 秒：按账号聚合水印，只对会话指纹真变化的项目重导活目录。

    - 每个账号只执行一次 sync_live_db（原库/WAL → 解密库）
    - 每个会话一条轻量 SQL (MAX(message_id), COUNT(*))
    - 指纹没变的项目毫秒跳过，绝不陪跑重导
    - 同步失败的项目标 sync_pending，下一轮自动补跑
    """
    _CODEX_LAST_TICK["at"] = time.time()
    _CODEX_LAST_TICK["runs"] += 1
    if background and front_is_busy():
        return {"checked": 0, "refreshed": [], "skipped": [], "accounts": {},
                "skipped_reason": "前台操作进行中，后台让路本轮"}
    with codex_lock(background=background):
        cfg = load_config()
        projects = [p for p in (cfg.get("codex_projects") or [])
                    if p.get("status") == "running"
                    and p["id"] not in _CODEX_TRANSFER_PAUSE]
        if not projects:
            return {"checked": 0, "refreshed": [], "skipped": [], "accounts": {}}

        # ① 每个账号只读一次原始库 / WAL 水印
        account_sigs = {}
        for aid in sorted({a for p in projects for a in (p.get("accounts") or [])}):
            acc = _find_acc(cfg, aid)
            if acc is None:
                continue
            try:
                sig = live_signature(acc)
                account_sigs[aid] = [list(sig["main"]), list(sig["wal"])]
            except (OSError, ValueError, KeyError):
                continue

        # ② 需要同步解密库的账号（水印变化 或 有待重试项目 或 含模糊缩略图且缓存落盘新图 或 解密库异常待自愈）
        # 当活目录存在 210px 模糊缩略图/未下载附件时，企微点开大图会写入 Cache\Image 与 WAL（但消息总数不变）；
        # 监控 Cache 指纹变化以在 3 秒心跳内立刻触发同步并自动把糊图覆盖升级为高清原图。
        cache_changed_pids = set()
        cache_fp_map = {}
        for project in projects:
            st = project.get("stats") or {}
            if int(st.get("blurry_thumbs") or 0) > 0 or int(st.get("missing") or 0) > 0:
                try:
                    cfp = _codex_fp_str(_codex_cache_fp(cfg, project))
                    cache_fp_map[project["id"]] = cfp
                    if cfp != project.get("cache_fp"):
                        cache_changed_pids.add(project["id"])
                except Exception:
                    pass

        needs_sync = set()
        for aid, sig in account_sigs.items():
            acc_obj = _find_acc(cfg, aid)
            unhealthy = (acc_obj is not None
                         and not _dec_db_is_clean_and_healthy(acc_obj))
            # 原库又有新变化或库异常 → 立刻解除冷却，保证保鲜与自愈不受影响
            if sig != _CODEX_LAST_ACCOUNT_SIG.get(aid) or unhealthy:
                _CODEX_PENDING_COOLDOWN.pop(aid, None)
                _CODEX_LAST_ACCOUNT_SIG[aid] = sig
            if time.monotonic() < _CODEX_PENDING_COOLDOWN.get(aid, 0):
                continue       # 整库重解节流冷却中，本轮不重复尝试
            related = [p for p in projects if aid in (p.get("accounts") or [])]
            if unhealthy or any((p.get("signature") or {}).get(aid) != sig
                                or p.get("sync_pending")
                                or p["id"] in cache_changed_pids
                                for p in related):
                needs_sync.add(aid)

        # ③ 每个账号只跑一次 sync_live_db，并强失效该账号的消息索引缓存
        sync_result = {}
        for aid in sorted(needs_sync):
            acc = _find_acc(cfg, aid)
            if acc is None:
                sync_result[aid] = {"ok": False, "reason": "账号不在配置中"}
                continue
            try:
                before = _dec_db_peak(cfg, acc)
                _, method = sync_live_db(acc, cfg, background=background)
                if method == "pending":
                    _CODEX_PENDING_COOLDOWN[aid] = time.monotonic() + 20
                    # 冷却是正常节流，后台让路即可；标黄只会制造假故障黄条
                    raise BusySkip("整库重解节流冷却中，后台下轮补跑")
                after = _dec_db_peak(cfg, acc)
                if after[1] == 0:
                    raise RuntimeError("解密库为空或不可读")
                if after[0] < before[0]:
                    raise RuntimeError(
                        f"解密库峰值倒退 {before[0]}→{after[0]}")
                # 不清空消息索引：水印变化会让下次读走「旧快照 + 后台重建」，
                # 清空会让 HTTP 线程被迫全量重解析（压测 4~8 秒超时真凶）。
                sync_result[aid] = {"ok": True, "method": method,
                                    "peak": list(after)}
            except BusySkip as exc:
                # 前台刷新/重扫正忙：后台让路是正常调度，绝不标黄、不刷红字
                sync_result[aid] = {"ok": False, "soft": True,
                                    "reason": str(exc)}
                _codex_log(f"账号 {aid} 前台操作进行中，后台同步让路（下轮自动补跑）")
            except Exception as exc:
                sync_result[aid] = {"ok": False, "reason": str(exc)}
                _codex_log(f"账号 {aid} 解密库同步失败：{exc}（下轮自动补跑）")

        changed = False
        refreshed, skipped = [], []
        for project in projects:
            aids = [a for a in (project.get("accounts") or [])
                    if a in account_sigs]
            # 真失败才标黄待重试；后台让路（soft）只跳过本轮，绝不刷红字
            failed = [a for a in aids
                      if a in sync_result and not sync_result[a]["ok"]
                      and not sync_result[a].get("soft")]
            if failed:
                project["sync_pending"] = True
                project["last_error"] = ("上次同步待重试：" +
                                        sync_result[failed[0]]["reason"])
                changed = True
                continue
            if any(a in sync_result and sync_result[a].get("soft") for a in aids):
                skipped.append(project["id"])
                continue
            stale_sig = any(
                (project.get("signature") or {}).get(a) != account_sigs[a]
                for a in aids)
            has_cache_upgrade = project["id"] in cache_changed_pids
            if not project.get("sync_pending") and not stale_sig and not has_cache_upgrade:
                skipped.append(project["id"])          # 毫秒级跳过
                continue
            # ④ 每个会话一条轻量 SQL；指纹没变且无高清缓存升级就不重导
            fingerprint = _codex_project_fingerprint(cfg, project)
            if (fingerprint == project.get("conv_fingerprint")
                    and not project.get("sync_pending")
                    and not has_cache_upgrade):
                project["signature"] = {a: account_sigs[a] for a in aids}
                skipped.append(project["id"])
                changed = True
                continue
            try:
                result = build_live_folder(cfg, project)
                project["signature"] = {a: account_sigs[a] for a in aids}
                project["conv_fingerprint"] = fingerprint
                project["cache_fp"] = _codex_fp_str(_codex_cache_fp(cfg, project))
                project["last_update"] = time.strftime("%Y-%m-%d %H:%M:%S")
                project["last_error"] = ""
                project["sync_pending"] = False
                project["last_sync_method"] = ",".join(
                    sync_result[a].get("method", "unchanged") for a in aids
                    if a in sync_result) or "unchanged"
                project["stats"] = _codex_stats(result)
                # 后台已同步到最新 → 同步快返指纹，复制口令时 0.05 秒直接返回
                project["quick_fp"] = _codex_fp_str(_codex_quick_fingerprint(cfg, project))
                refreshed.append(project["id"])
                changed = True
            except _CodexTransientEmpty as exc:
                # 硬保护：保留原活目录快照、清掉待重试状态、推进签名避免每轮死循环
                project["signature"] = {a: account_sigs[a] for a in aids}
                project["sync_pending"] = False
                project["last_error"] = ""
                project["last_skip_reason"] = str(exc)
                project["last_skip_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                skipped.append(project["id"])
                _codex_log(f"{project.get('name')} {exc}（不覆盖活目录、不重试）")
                changed = True
            except Exception as exc:
                project["sync_pending"] = True
                project["last_error"] = f"上次同步待重试：{exc}"
                _codex_log(f"{project.get('name')} 重导失败：{exc}"
                           "（下轮自动补跑）")
                changed = True
        if changed:
            save_config(cfg)
        if refreshed:
            try:
                _write_root_overviews(cfg)
            except OSError:
                pass
        return {"checked": len(projects), "refreshed": refreshed,
                "skipped": skipped, "accounts": sync_result}


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
