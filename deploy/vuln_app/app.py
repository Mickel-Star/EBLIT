from flask import Flask, request, jsonify, has_request_context
import os
import json
import sqlite3
import subprocess
import time
import secrets
import csv
import glob
import uuid
from typing import Any, Dict

app = Flask(__name__)

DB_PATH = os.environ.get("DRSEC_DB_PATH", "/app/data/app.db")
SECRETS_DIR = os.path.join(os.path.dirname(DB_PATH), "secrets")
RICH_DATA_DIR = os.environ.get("DRSEC_RICH_DATA_DIR", os.path.join(os.path.dirname(DB_PATH), "rich"))

ITEMS = [
    {"id": "sku-001", "name": "container-monitor", "price": 19.9},
    {"id": "sku-002", "name": "provenance-audit", "price": 29.9},
    {"id": "sku-003", "name": "threat-intel-pack", "price": 49.9},
]


def _init_secrets() -> None:
    os.makedirs(SECRETS_DIR, exist_ok=True)
    env_path = os.path.join(SECRETS_DIR, "demo.env")
    if not os.path.exists(env_path):
        with open(env_path, "w") as f:
            f.write("# EBLIT dummy secret - lab only, no real credentials\n")
            f.write("DB_PASSWORD=lab_dummy_pw_2026\n")
            f.write("API_KEY=lab_dummy_key_eblit\n")
            f.write("SECRET_TOKEN=lab_dummy_token_eblit\n")


def _db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer TEXT NOT NULL,
                item TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                meta_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """
        )
        now = int(time.time())
        conn.execute(
            """
            INSERT INTO users(username, password, role, created_at)
            VALUES(?,?,?,?)
            ON CONFLICT(username) DO NOTHING
            """,
            ("alice", "password", "user", now),
        )
        conn.execute(
            """
            INSERT INTO users(username, password, role, created_at)
            VALUES(?,?,?,?)
            ON CONFLICT(username) DO NOTHING
            """,
            ("bob", "password", "admin", now),
        )
        conn.commit()
    finally:
        conn.close()


def _safe_component(value: Any, default: str) -> str:
    text = str(value or default).strip()
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)
    return cleaned[:96] or default


def _request_tags(event: str) -> Dict[str, str]:
    if not has_request_context():
        return {
            "run_id": "no_request",
            "actor": "server",
            "action": _safe_component(event, "unknown_action"),
            "request_id": uuid.uuid4().hex,
        }
    return {
        "run_id": _safe_component(request.headers.get("X-DRSEC-Run-ID"), "manual"),
        "actor": _safe_component(request.headers.get("X-DRSEC-Actor"), "manual_user"),
        "action": _safe_component(request.headers.get("X-DRSEC-Action"), event),
        "request_id": _safe_component(request.headers.get("X-DRSEC-Request-ID"), uuid.uuid4().hex),
    }


def _run_dir(run_id: str) -> str:
    path = os.path.join(RICH_DATA_DIR, "runs", _safe_component(run_id, "manual"))
    os.makedirs(path, exist_ok=True)
    return path


def _append_jsonl(path: str, payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def _write_text(path: str, body: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def _artifact_path(run_id: str, category: str, actor: str, action: str, request_id: str, suffix: str) -> str:
    return os.path.join(
        _run_dir(run_id),
        category,
        _safe_component(actor, "actor"),
        _safe_component(action, "action"),
        f"{_safe_component(request_id, uuid.uuid4().hex)}{suffix}",
    )


def _audit(event: str, meta: Dict[str, Any]) -> None:
    tags = _request_tags(event)
    audit_payload = {
        "ts": int(time.time()),
        "event": event,
        "method": request.method if has_request_context() else "",
        "path": request.path if has_request_context() else "",
        "run_id": tags["run_id"],
        "actor": tags["actor"],
        "action": tags["action"],
        "request_id": tags["request_id"],
        "meta": meta,
    }
    audit_path = _artifact_path(
        tags["run_id"],
        "audit",
        tags["actor"],
        tags["action"],
        tags["request_id"],
        ".jsonl",
    )
    _append_jsonl(audit_path, audit_payload)
    _append_jsonl(os.path.join(_run_dir(tags["run_id"]), "audit_index.jsonl"), {**audit_payload, "audit_path": audit_path})

    conn = _db()
    try:
        conn.execute(
            "INSERT INTO audit_logs(event, meta_json, created_at) VALUES (?, ?, ?)",
            (event, json.dumps(meta, ensure_ascii=False), int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()


@app.route('/')
def home():
    return """
    <h1>Vulnerable App</h1>
    <p>Ping a host:</p>
    <form action="/ping" method="GET">
        <input type="text" name="ip" placeholder="127.0.0.1">
        <input type="submit" value="Ping">
    </form>
    """

@app.route('/health')
def health():
    return jsonify({"status": "ok", "ts": int(time.time())})


@app.route('/ready')
def ready():
    _init_db()
    _init_secrets()
    os.makedirs(RICH_DATA_DIR, exist_ok=True)
    _audit("ready", {"db_path": DB_PATH, "rich_data_dir": RICH_DATA_DIR})
    return jsonify({"status": "ready", "ts": int(time.time()), "rich_data_dir": RICH_DATA_DIR})


@app.route('/api/items')
def items():
    tags = _request_tags("items_list")
    snapshot_path = _artifact_path(tags["run_id"], "catalog", tags["actor"], tags["action"], tags["request_id"], ".json")
    _write_text(snapshot_path, json.dumps({"items": ITEMS, "request": tags}, ensure_ascii=False, sort_keys=True))
    _audit("items_list", {"count": len(ITEMS), "snapshot_path": snapshot_path})
    return jsonify({"items": ITEMS, "snapshot_path": snapshot_path})


@app.route('/api/items/<item_id>')
def item_detail(item_id: str):
    tags = _request_tags("item_detail")
    item = next((entry for entry in ITEMS if entry["id"] == item_id), None)
    if item is None:
        _audit("item_not_found", {"item_id": item_id})
        return jsonify({"error": "not_found"}), 404
    detail = {
        **item,
        "inventory": {"available": 100 + len(item_id), "warehouse": f"wh-{item_id[-1]}"},
        "request": tags,
    }
    detail_path = _artifact_path(tags["run_id"], "item_detail", tags["actor"], tags["action"], tags["request_id"], ".json")
    _write_text(detail_path, json.dumps(detail, ensure_ascii=False, sort_keys=True))
    _audit("item_detail", {"item_id": item_id, "detail_path": detail_path})
    return jsonify({"item": detail, "detail_path": detail_path})


@app.route('/api/order', methods=['POST'])
def create_order():
    payload = request.get_json(silent=True) or {}
    customer = str(payload.get("customer") or "anonymous")
    item = str(payload.get("item") or "sku-001")
    quantity = int(payload.get("quantity") or 1)
    status = "created"
    now = int(time.time())

    conn = _db()
    try:
        cur = conn.execute(
            "INSERT INTO orders(customer, item, quantity, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (customer, item, quantity, status, now),
        )
        conn.commit()
        order_id = int(cur.lastrowid)
    finally:
        conn.close()

    _audit("order_created", {"order_id": order_id, "customer": customer, "item": item, "quantity": quantity})
    return jsonify({"order_id": order_id, "status": status})


@app.route('/api/order/<int:order_id>')
def get_order(order_id: int):
    conn = _db()
    try:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "not_found"}), 404
    _audit("order_viewed", {"order_id": order_id})
    return jsonify(dict(row))


@app.route('/api/me/orders')
def my_orders():
    username = _get_session_username()
    if not username:
        return jsonify({"error": "unauthorized"}), 401
    tags = _request_tags("my_orders")
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT id, customer, item, quantity, status, created_at FROM orders WHERE customer = ? ORDER BY id DESC LIMIT 25",
            (username,),
        ).fetchall()
    finally:
        conn.close()
    payload = {"username": username, "orders": [dict(r) for r in rows], "request": tags}
    orders_path = _artifact_path(tags["run_id"], "orders", tags["actor"], tags["action"], tags["request_id"], ".json")
    _write_text(orders_path, json.dumps(payload, ensure_ascii=False, sort_keys=True))
    _audit("my_orders", {"username": username, "orders": len(rows), "orders_path": orders_path})
    return jsonify({"orders": payload["orders"], "orders_path": orders_path})


@app.route('/api/search')
def search():
    q = str(request.args.get("q") or "").strip().lower()
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT * FROM orders WHERE lower(customer) LIKE ? OR lower(item) LIKE ? ORDER BY id DESC LIMIT 10",
            (f"%{q}%", f"%{q}%"),
        ).fetchall()
    finally:
        conn.close()
    _audit("search", {"q": q, "hits": len(rows)})
    return jsonify({"q": q, "hits": [dict(r) for r in rows]})


def _get_session_username() -> str | None:
    auth = str(request.headers.get("Authorization") or "").strip()
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer ") :].strip()
    if not token:
        return None
    now = int(time.time())
    conn = _db()
    try:
        row = conn.execute(
            "SELECT username FROM sessions WHERE token = ? AND expires_at > ?",
            (token, now),
        ).fetchone()
        return str(row["username"]) if row else None
    finally:
        conn.close()


@app.route("/api/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    if not username or not password:
        _audit("login_failed", {"username": username, "reason": "missing_credentials"})
        return jsonify({"error": "invalid_credentials"}), 400
    conn = _db()
    try:
        row = conn.execute("SELECT password, role FROM users WHERE username = ?", (username,)).fetchone()
        if not row or str(row["password"]) != password:
            _audit("login_failed", {"username": username, "reason": "bad_credentials"})
            return jsonify({"error": "invalid_credentials"}), 401
        token = secrets.token_hex(16)
        now = int(time.time())
        expires_at = now + 3600
        conn.execute(
            "INSERT INTO sessions(token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, username, now, expires_at),
        )
        conn.commit()
        _audit("login_success", {"username": username, "role": str(row['role'])})
        return jsonify({"token": token, "expires_at": expires_at})
    finally:
        conn.close()


@app.route("/api/logout", methods=["POST"])
def logout():
    auth = str(request.headers.get("Authorization") or "").strip()
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    token = auth[len("Bearer ") :].strip()
    if not token:
        return jsonify({"error": "unauthorized"}), 401
    conn = _db()
    try:
        row = conn.execute("SELECT username FROM sessions WHERE token = ?", (token,)).fetchone()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        if row:
            _audit("logout", {"username": str(row["username"])})
    finally:
        conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/me")
def me():
    username = _get_session_username()
    if not username:
        return jsonify({"error": "unauthorized"}), 401
    conn = _db()
    try:
        u = conn.execute("SELECT username, role, created_at FROM users WHERE username = ?", (username,)).fetchone()
        recent = conn.execute(
            "SELECT id, item, quantity, status, created_at FROM orders WHERE customer = ? ORDER BY id DESC LIMIT 5",
            (username,),
        ).fetchall()
    finally:
        conn.close()
    _audit("profile_view", {"username": username, "orders": len(recent)})
    return jsonify({"user": dict(u) if u else {"username": username}, "recent_orders": [dict(r) for r in recent]})


@app.route("/api/admin/audit")
def admin_audit():
    username = _get_session_username()
    if not username:
        return jsonify({"error": "unauthorized"}), 401
    try:
        limit = min(max(int(request.args.get("limit") or 10), 1), 100)
    except Exception:
        limit = 10

    conn = _db()
    try:
        user = conn.execute("SELECT username, role FROM users WHERE username = ?", (username,)).fetchone()
        if not user or str(user["role"]) != "admin":
            _audit("admin_audit_denied", {"username": username})
            return jsonify({"error": "forbidden"}), 403
        rows = conn.execute(
            "SELECT id, event, meta_json, created_at FROM audit_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    _audit("admin_audit_view", {"username": username, "limit": limit})
    return jsonify({"events": [dict(r) for r in rows], "limit": limit})


@app.route("/api/report/export")
def report_export():
    tags = _request_tags("report_export")
    q = str(request.args.get("q") or "").strip().lower()
    try:
        limit = min(max(int(request.args.get("limit") or 20), 1), 200)
    except Exception:
        limit = 20

    like = f"%{q}%"
    conn = _db()
    try:
        rows = conn.execute(
            """
            SELECT customer, item, status, COUNT(*) AS order_count, SUM(quantity) AS total_quantity
            FROM orders
            WHERE lower(customer) LIKE ? OR lower(item) LIKE ? OR lower(status) LIKE ?
            GROUP BY customer, item, status
            ORDER BY order_count DESC, customer ASC, item ASC
            LIMIT ?
            """,
            (like, like, like, limit),
        ).fetchall()
    finally:
        conn.close()

    row_dicts = [dict(r) for r in rows]
    report_path = _artifact_path(tags["run_id"], "reports", tags["actor"], tags["action"], tags["request_id"], ".csv")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["customer", "item", "status", "order_count", "total_quantity"])
        writer.writeheader()
        writer.writerows(row_dicts)
    manifest_path = _artifact_path(tags["run_id"], "reports", tags["actor"], tags["action"], tags["request_id"], ".json")
    _write_text(manifest_path, json.dumps({"q": q, "limit": limit, "rows": row_dicts, "csv_path": report_path}, ensure_ascii=False, sort_keys=True))
    _audit("report_export", {"q": q, "limit": limit, "rows": len(rows), "report_path": report_path, "manifest_path": manifest_path})
    return jsonify({"q": q, "limit": limit, "rows": row_dicts, "report_path": report_path, "manifest_path": manifest_path})


@app.route("/api/cache/warmup", methods=["GET", "POST"])
def cache_warmup():
    tags = _request_tags("cache_warmup")
    payload = request.get_json(silent=True) or {}
    category = str(payload.get("category") or request.args.get("category") or "catalog")
    cache_body = {
        "category": category,
        "items": ITEMS,
        "request": tags,
        "generated_at": int(time.time()),
    }
    cache_path = _artifact_path(tags["run_id"], "cache", tags["actor"], tags["action"], tags["request_id"], ".json")
    _write_text(cache_path, json.dumps(cache_body, ensure_ascii=False, sort_keys=True))
    job_payload = {
        "run_id": tags["run_id"],
        "actor": tags["actor"],
        "action": tags["action"],
        "request_id": tags["request_id"],
        "kind": "cache_refresh",
        "cache_path": cache_path,
        "created_at": int(time.time()),
    }
    job_path = _artifact_path(tags["run_id"], "jobs/pending", tags["actor"], tags["action"], tags["request_id"], ".json")
    _write_text(job_path, json.dumps(job_payload, ensure_ascii=False, sort_keys=True))
    _audit("cache_warmup", {"category": category, "cache_path": cache_path, "job_path": job_path})
    return jsonify({"status": "ok", "cache_path": cache_path, "job_path": job_path})


@app.route("/api/worker/jobs")
def worker_jobs():
    tags = _request_tags("worker_jobs")
    pattern = os.path.join(_run_dir(tags["run_id"]), "jobs", "pending", "*", "*", "*.json")
    jobs = sorted(glob.glob(pattern))[:25]
    _audit("worker_jobs", {"job_count": len(jobs)})
    return jsonify({"jobs": jobs})


@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    _audit("ping", {"ip": ip})
    try:
        output = subprocess.check_output(f"ping -c 1 {ip}", shell=True, stderr=subprocess.STDOUT)
        return f"<pre>{output.decode()}</pre>"
    except subprocess.CalledProcessError as e:
        return f"<pre>Error: {e.output.decode()}</pre>"
    except Exception as e:
        return f"<pre>Error: {str(e)}</pre>"

if __name__ == '__main__':
    _init_db()
    _init_secrets()
    app.run(host='0.0.0.0', port=5000)

_init_db()
_init_secrets()
