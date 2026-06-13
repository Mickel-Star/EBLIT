"""
良性行为配置文件生成器 - 漏洞应用 (vuln_app)
本模块用于生成模拟 Web 应用的良性用户行为配置文件，用于构建 DRSEC 系统的良性行为基线库 (BBK)。
通过模拟多种典型的用户交互模式，生成正常的网络请求和系统调用，为 GMAE 模型提供训练数据。

主要功能:
1. 定义多种用户行为配置文件（profiles）
2. 模拟 HTTP 请求（登录、查询、下单、管理等）
3. 生成具有随机性和时间间隔的真实用户行为序列

"""
from __future__ import annotations

import json
import random
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


# ============================================================================
# 全局配置常量
# ============================================================================

# 商品 ID 列表，用于模拟订单创建时的商品选择
ITEM_IDS = ["sku-001", "sku-002", "sku-003"]

# 搜索关键词列表，用于模拟用户搜索行为
SEARCH_TERMS = ["sku", "alice", "bob", "container", "threat", "provenance", "audit"]

# 每个 driver thread 维护自己的轻量请求统计，避免引入额外依赖。
REQUEST_TIMEOUT_SECONDS = 10
MAX_STAGE_PARAMETER_RECORDS = 64
_REQUEST_CONTEXT = threading.local()


def _new_driver_metrics(
    *,
    profile_id: str,
    driver_role: str,
    duration_seconds: float,
    seed: int,
    phase_profile_id: str = "",
) -> dict[str, Any]:
    return {
        "profile_id": str(profile_id),
        "driver_role": str(driver_role),
        "phase_profile_id": str(phase_profile_id or profile_id),
        "duration_seconds": float(duration_seconds),
        "seed": int(seed),
        "started_at_unix": float(time.time()),
        "elapsed_seconds": 0.0,
        "request_count": 0,
        "success_count": 0,
        "http_error_count": 0,
        "exception_count": 0,
        "timeout_count": 0,
        "http_status_counts": {},
        "path_counts": {},
        "stage_counts": {},
        "stage_parameters": [],
    }


def _current_metrics() -> dict[str, Any] | None:
    metrics = getattr(_REQUEST_CONTEXT, "metrics", None)
    return metrics if isinstance(metrics, dict) else None


def _finish_metrics(metrics: dict[str, Any], started_at: float) -> dict[str, Any]:
    metrics["finished_at_unix"] = float(time.time())
    metrics["elapsed_seconds"] = float(max(time.monotonic() - started_at, 0.0))
    metrics.pop("_active_stage", None)
    return metrics


def _path_key(path: str) -> str:
    return str(path or "").split("?", 1)[0] or "/"


def _increment(mapping: dict[str, Any], key: str, amount: int = 1) -> None:
    mapping[str(key)] = int(mapping.get(str(key), 0)) + int(amount)


def _note_stage(stage_name: str, params: dict[str, Any] | None = None) -> None:
    metrics = _current_metrics()
    if metrics is None:
        return
    stage = str(stage_name or "default")
    metrics["_active_stage"] = stage
    _increment(metrics.setdefault("stage_counts", {}), stage)
    if params is not None and len(metrics.setdefault("stage_parameters", [])) < MAX_STAGE_PARAMETER_RECORDS:
        metrics["stage_parameters"].append({"stage": stage, "parameters": dict(params)})


def _record_request(path: str, *, status: int = 0, outcome: str, timeout: bool = False) -> None:
    metrics = _current_metrics()
    if metrics is None:
        return
    path_name = _path_key(path)
    metrics["request_count"] = int(metrics.get("request_count", 0)) + 1
    _increment(metrics.setdefault("path_counts", {}), path_name)
    if status:
        _increment(metrics.setdefault("http_status_counts", {}), str(int(status)))
    if outcome == "success":
        metrics["success_count"] = int(metrics.get("success_count", 0)) + 1
    elif outcome == "http_error":
        metrics["http_error_count"] = int(metrics.get("http_error_count", 0)) + 1
    else:
        metrics["exception_count"] = int(metrics.get("exception_count", 0)) + 1
    if timeout:
        metrics["timeout_count"] = int(metrics.get("timeout_count", 0)) + 1

    stage = str(metrics.get("_active_stage") or "")
    if stage:
        by_stage = metrics.setdefault("request_counts_by_stage", {})
        stage_payload = by_stage.setdefault(
            stage,
            {
                "request_count": 0,
                "success_count": 0,
                "http_error_count": 0,
                "exception_count": 0,
                "timeout_count": 0,
            },
        )
        stage_payload["request_count"] = int(stage_payload.get("request_count", 0)) + 1
        if outcome == "success":
            stage_payload["success_count"] = int(stage_payload.get("success_count", 0)) + 1
        elif outcome == "http_error":
            stage_payload["http_error_count"] = int(stage_payload.get("http_error_count", 0)) + 1
        else:
            stage_payload["exception_count"] = int(stage_payload.get("exception_count", 0)) + 1
        if timeout:
            stage_payload["timeout_count"] = int(stage_payload.get("timeout_count", 0)) + 1


def _is_timeout_exception(exc: BaseException) -> bool:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return True
    reason = getattr(exc, "reason", None)
    return isinstance(reason, (socket.timeout, TimeoutError))


def profile_catalog() -> dict[str, dict[str, Any]]:
    """
    配置文件说明:
        - health_idle_poll: 低频健康检查和商品列表轮询
        - auth_read_session: 完整的用户认证会话（登录-读取-登出）
        - catalog_browse_search: 商品目录浏览和搜索行为
        - order_write_checkout: 订单创建和结账流程
        - admin_readonly_audit: 管理员只读审计操作
        - report_export_batch: 批量报告导出和聚合读取
        - burst_then_idle_retry: 突发活动后空闲轮询模式
    """
    return {
        "health_idle_poll": {
            "description": "low-frequency health, catalog, small search, and small report polling"
        },
        "auth_read_session": {
            "description": "alice/bob login, occasional failed password, randomized session reads, logout"
        },
        "catalog_browse_search": {
            "description": "catalog browse/search with light order readback"
        },
        "order_write_checkout": {
            "description": "login, create orders, read back order state, logout"
        },
        "admin_readonly_audit": {
            "description": "admin login, profile read, audit-log browsing, logout"
        },
        "report_export_batch": {
            "description": "read-heavy report export, batch search, and aggregate reads"
        },
        "burst_then_idle_retry": {
            "description": "short active bursts, failed retries with backoff, then idle polling"
        },
    }


def run_profile(profile_id: str, *, base_url: str, duration_seconds: float, seed: int) -> dict[str, Any]:
    """
    根据给定的配置文件 ID，在指定时间内循环执行对应的用户行为模拟。
    使用随机种子确保行为模式可重现。
    Args:
        profile_id: 配置文件 ID，必须在 profile_catalog() 返回的键中
        base_url: 目标 Web 应用的基础 URL（如 http://localhost:5000）
        duration_seconds: 执行持续时间（秒）
        seed: 随机数种子，用于生成可重现的行为序列
    """
    # 使用指定种子初始化随机数生成器，确保行为可重现
    rng = random.Random(int(seed))
    
    # 计算执行截止时间
    deadline = time.monotonic() + max(float(duration_seconds), 0.0)
    
    # 配置文件 ID 到执行函数的映射
    runners = {
        "health_idle_poll": _health_idle_poll,
        "auth_read_session": _auth_read_session,
        "catalog_browse_search": _catalog_browse_search,
        "order_write_checkout": _order_write_checkout,
        "admin_readonly_audit": _admin_readonly_audit,
        "report_export_batch": _report_export_batch,
        "burst_then_idle_retry": _burst_then_idle_retry,
    }
    
    # 获取对应的执行函数
    runner = runners.get(str(profile_id))
    if runner is None:
        raise RuntimeError(f"unsupported profile: {profile_id}")
    
    metrics = _new_driver_metrics(
        profile_id=str(profile_id),
        driver_role="foreground_user",
        duration_seconds=float(duration_seconds),
        seed=int(seed),
    )
    previous_metrics = getattr(_REQUEST_CONTEXT, "metrics", None)
    _REQUEST_CONTEXT.metrics = metrics
    started_at = time.monotonic()
    try:
        # 循环执行直到达到截止时间
        while deadline > time.monotonic():
            runner(str(base_url).rstrip("/"), deadline, rng)
    finally:
        if previous_metrics is None:
            try:
                delattr(_REQUEST_CONTEXT, "metrics")
            except AttributeError:
                pass
        else:
            _REQUEST_CONTEXT.metrics = previous_metrics
    return _finish_metrics(metrics, started_at)


def run_background_worker(*, base_url: str, duration_seconds: float, seed: int, phase_profile_id: str = "") -> dict[str, Any]:
    """
    运行后台工作线程，模拟后台服务和定时任务的行为。
    后台工作线程会持续执行健康检查、商品列表更新、报告导出和管理员审计等操作，
    模拟真实应用环境中的后台活动。
    Args:
        base_url: 目标 Web 应用的基础 URL
        duration_seconds: 执行持续时间（秒）
        seed: 随机数种子
        phase_profile_id: 阶段配置文件 ID（当前未使用，保留用于扩展）
    行为模式:
        - 100% 执行健康检查
        - 55% 概率执行商品列表查询
        - 45% 概率执行报告导出
        - 25% 概率执行管理员审计操作
    """
    rng = random.Random(int(seed))
    deadline = time.monotonic() + max(float(duration_seconds), 0.0)
    base_url = str(base_url).rstrip("/")
    metrics = _new_driver_metrics(
        profile_id="background_worker",
        driver_role="background_worker",
        phase_profile_id=str(phase_profile_id or "background_worker"),
        duration_seconds=float(duration_seconds),
        seed=int(seed),
    )
    previous_metrics = getattr(_REQUEST_CONTEXT, "metrics", None)
    _REQUEST_CONTEXT.metrics = metrics
    started_at = time.monotonic()

    keepalive_interval = rng.uniform(4.0, 8.0)
    metrics_interval = rng.uniform(18.0, 32.0)
    report_interval = rng.uniform(25.0, 45.0)
    retry_interval = rng.uniform(35.0, 55.0)
    next_keepalive = time.monotonic()
    next_metrics = time.monotonic() + rng.uniform(0.0, metrics_interval)
    next_report = time.monotonic() + rng.uniform(2.0, report_interval)
    next_retry = time.monotonic() + rng.uniform(5.0, retry_interval)

    try:
        while deadline > time.monotonic():
            now = time.monotonic()
            if now >= next_keepalive:
                _note_stage("keepalive_poll", {"interval_seconds": round(keepalive_interval, 3)})
                _health(base_url)
                if rng.random() < 0.45:
                    _items(base_url)
                next_keepalive = now + keepalive_interval + rng.uniform(-1.0, 1.5)

            if now >= next_metrics:
                _note_stage("metrics_poll", {"interval_seconds": round(metrics_interval, 3)})
                _search(base_url, rng.choice(["sku", "audit", "provenance"]))
                next_metrics = now + metrics_interval + rng.uniform(-3.0, 4.0)

            if now >= next_report:
                limit = rng.choice([5, 10, 25, 50])
                _note_stage("report_poll", {"interval_seconds": round(report_interval, 3), "limit": limit})
                _report_export(base_url, rng.choice(SEARCH_TERMS), limit)
                next_report = now + report_interval + rng.uniform(-4.0, 6.0)

            if now >= next_retry:
                _note_stage("webhook_retry", {"interval_seconds": round(retry_interval, 3), "status": "normal_failed_retry"})
                _request("GET", base_url, f"/api/order/{rng.randint(8000, 9999)}")
                next_retry = now + retry_interval + rng.uniform(-5.0, 8.0)

            if rng.random() < 0.08:
                _note_stage("admin_audit_poll", {"limit": "small"})
                token = _login(base_url, "bob")
                _admin_audit(base_url, token, rng.randint(3, 12))
                _logout(base_url, token)

            _sleep_between(rng, 1.0, 2.5, deadline)
    finally:
        if previous_metrics is None:
            try:
                delattr(_REQUEST_CONTEXT, "metrics")
            except AttributeError:
                pass
        else:
            _REQUEST_CONTEXT.metrics = previous_metrics
    return _finish_metrics(metrics, started_at)


def _request(method: str, base_url: str, path: str, payload: dict[str, Any] | None = None, token: str = "") -> dict[str, Any]:
    """
    发送 HTTP 请求并返回响应数据。
    封装了 urllib.request 的请求逻辑，支持 GET/POST 等方法，
    自动处理 JSON 序列化和认证令牌。
    Args:
        method: HTTP 方法（GET, POST, PUT, DELETE 等）
        base_url: 基础 URL（如 http://localhost:5000）
        path: 请求路径（如 /api/items）
        payload: 请求体数据（字典格式，将被序列化为 JSON）
        token: 认证令牌（将添加到 Authorization 头）
    Returns:
        dict: 响应数据（JSON 解析后的字典），失败时返回空字典
    """
    # 构建请求头
    headers = {"Accept": "application/json"}
    body = None
    
    # 处理请求体
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    
    # 添加认证令牌
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    # 创建请求对象
    req = urllib.request.Request(base_url + path, data=body, headers=headers, method=method)
    
    try:
        # 发送请求并读取响应
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            text = resp.read().decode("utf-8", "ignore")
            _record_request(path, status=int(getattr(resp, "status", 0) or 0), outcome="success")
            if not text:
                return {}
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text}
                
    except urllib.error.HTTPError as exc:
        # 处理 HTTP 错误响应
        _record_request(path, status=int(getattr(exc, "code", 0) or 0), outcome="http_error")
        try:
            text = exc.read().decode("utf-8", "ignore")
            return json.loads(text) if text else {}
        except Exception:
            return {}
            
    except Exception as exc:
        # 处理其他异常
        _record_request(path, outcome="exception", timeout=_is_timeout_exception(exc))
        return {}


def _sleep_between(rng: random.Random, low_seconds: float, high_seconds: float, deadline: float) -> None:
    """
    在指定范围内随机休眠，模拟用户思考时间。
    休眠时间不会超过截止时间，确保行为序列按时结束。
    Args:
        rng: 随机数生成器实例
        low_seconds: 最小休眠时间（秒）
        high_seconds: 最大休眠时间（秒）
        deadline: 执行截止时间（单调时钟）
    """
    # 计算剩余时间
    remaining = max(deadline - time.monotonic(), 0.0)
    if remaining <= 0:
        return
    
    # 休眠随机时间，但不超过剩余时间
    time.sleep(min(rng.uniform(float(low_seconds), float(high_seconds)), remaining))


def _login(base_url: str, username: str) -> str:
    """
    用户登录，获取认证令牌。
    Args:
        base_url: 基础 URL
        username: 用户名
    Returns:
        str: 认证令牌，登录失败返回空字符串
    """
    payload = _login_with_password(base_url, username, "password")
    return str(payload.get("token") or "")


def _login_with_password(base_url: str, username: str, password: str) -> dict[str, Any]:
    return _request("POST", base_url, "/api/login", {"username": username, "password": password})


def _logout(base_url: str, token: str) -> None:
    """
    用户登出，使认证令牌失效。
    Args:
        base_url: 基础 URL
        token: 认证令牌
    """
    if token:
        _request("POST", base_url, "/api/logout", token=token)


def _me(base_url: str, token: str) -> None:
    """
    获取当前用户信息。
    Args:
        base_url: 基础 URL
        token: 认证令牌
    """
    if token:
        _request("GET", base_url, "/api/me", token=token)


def _items(base_url: str) -> None:
    """
    获取商品列表。
    Args:
        base_url: 基础 URL
    """
    _request("GET", base_url, "/api/items")


def _health(base_url: str) -> None:
    """
    健康检查端点。
    Args:
        base_url: 基础 URL
    """
    _request("GET", base_url, "/health")


def _search(base_url: str, term: str) -> None:
    """
    搜索商品或内容。
    Args:
        base_url: 基础 URL
        term: 搜索关键词
    """
    _request("GET", base_url, f"/api/search?{urllib.parse.urlencode({'q': term})}")


def _order(base_url: str, customer: str, rng: random.Random) -> int:
    """
    创建订单。
    Args:
        base_url: 基础 URL
        customer: 客户名称
        rng: 随机数生成器
    Returns:
        int: 订单 ID，创建失败返回 0
    """
    payload = _request(
        "POST",
        base_url,
        "/api/order",
        {"customer": customer, "item": rng.choice(ITEM_IDS), "quantity": rng.randint(1, 3)},
    )
    try:
        return int(payload.get("order_id") or 0)
    except Exception:
        return 0


def _order_lookup(base_url: str, order_id: int) -> None:
    """
    查询订单详情。
    Args:
        base_url: 基础 URL
        order_id: 订单 ID
    """
    if order_id > 0:
        _request("GET", base_url, f"/api/order/{int(order_id)}")


def _admin_audit(base_url: str, token: str, limit: int = 10) -> None:
    """
    管理员审计日志查询。
    Args:
        base_url: 基础 URL
        token: 管理员认证令牌
        limit: 返回记录数量限制
    """
    if token:
        _request("GET", base_url, f"/api/admin/audit?{urllib.parse.urlencode({'limit': int(limit)})}", token=token)


def _report_export(base_url: str, term: str, limit: int = 20) -> None:
    """
    导出报告数据。
    Args:
        base_url: 基础 URL
        term: 搜索关键词
        limit: 返回记录数量限制
    """
    _request("GET", base_url, f"/api/report/export?{urllib.parse.urlencode({'q': term, 'limit': int(limit)})}")


# ============================================================================
# 配置文件执行函数
# ============================================================================

def _health_idle_poll(base_url: str, deadline: float, rng: random.Random) -> None:
    """
    配置文件: 健康检查和低频轮询。
    模拟监控服务或健康检查器的行为，定期查询健康状态和商品列表。
    这是最简单的配置文件，适合作为基线行为。
    
    行为序列:
        1. 健康检查 GET /health
        2. 商品列表 GET /api/items
        3. 等待 3-5 秒
        
    Args:
        base_url: 基础 URL
        deadline: 执行截止时间
        rng: 随机数生成器
    """
    _note_stage("idle_poll", {"search_probability": 0.35, "small_report_probability": 0.18})
    _health(base_url)
    if rng.random() < 0.75:
        _items(base_url)
    if rng.random() < 0.35:
        _search(base_url, rng.choice(["sku", "audit", "provenance"]))
    if rng.random() < 0.18:
        _report_export(base_url, rng.choice(["sku", "alice", "bob"]), rng.choice([3, 5, 8]))
    _sleep_between(rng, 2.5, 6.5, deadline)


def _auth_read_session(base_url: str, deadline: float, rng: random.Random) -> None:
    """
    配置文件: 认证会话读取操作。
    模拟普通用户的完整会话流程，包括登录、读取个人信息、浏览商品、登出。
    行为序列:
        1. 登录 POST /api/login
        2. 等待 0.2-0.5 秒
        3. 获取用户信息 GET /api/me
        4. 等待 0.2-0.5 秒
        5. 获取商品列表 GET /api/items
        6. 等待 0.2-0.5 秒
        7. 登出 POST /api/logout
    Args:
        base_url: 基础 URL
        deadline: 执行截止时间
        rng: 随机数生成器
    """
    username = rng.choice(["alice", "bob"])
    if rng.random() < 0.08:
        _note_stage("failed_login", {"username": username, "reason": "normal_bad_password"})
        _login_with_password(base_url, username, "bad-password")
        _sleep_between(rng, 0.2, 0.8, deadline)

    _note_stage("auth_read", {"username": username, "session_reads": "randomized"})
    token = _login(base_url, username)
    _sleep_between(rng, 0.2, 0.5, deadline)
    for _ in range(rng.randint(1, 3)):
        if deadline <= time.monotonic():
            break
        _me(base_url, token)
        _sleep_between(rng, 0.15, 0.6, deadline)
        if rng.random() < 0.65:
            _items(base_url)
        if rng.random() < 0.25:
            _search(base_url, rng.choice(["sku", username]))
        _sleep_between(rng, 0.15, 0.6, deadline)
    _logout(base_url, token)


def _catalog_browse_search(base_url: str, deadline: float, rng: random.Random) -> None:
    """
    配置文件: 商品目录浏览和搜索。
    模拟用户浏览商品目录、搜索商品、查看订单详情的行为。
    行为序列:
        1. 获取商品列表 GET /api/items
        2. 创建订单 POST /api/order
        3. 循环 2-5 次搜索操作
        4. 查询订单详情 GET /api/order/{id}
        5. 等待 0.4-1.2 秒
    Args:
        base_url: 基础 URL
        deadline: 执行截止时间
        rng: 随机数生成器
    """
    order_id = 0
    _note_stage("catalog_browse", {"light_order_readback_probability": 0.35})
    for _ in range(rng.randint(1, 3)):
        if deadline <= time.monotonic():
            break
        _items(base_url)
        _sleep_between(rng, 0.1, 0.4, deadline)
    if rng.random() < 0.35:
        order_id = _order(base_url, rng.choice(["alice", "bob"]), rng)
    
    # 执行多次搜索
    for _ in range(rng.randint(2, 6)):
        if deadline <= time.monotonic():
            break
        _search(base_url, rng.choice(SEARCH_TERMS))
        _sleep_between(rng, 0.15, 0.8, deadline)
    
    if order_id > 0:
        _order_lookup(base_url, order_id)
    _sleep_between(rng, 0.4, 1.4, deadline)


def _order_write_checkout(base_url: str, deadline: float, rng: random.Random) -> None:
    """
    配置文件: 订单创建和结账流程。
    模拟用户下单和结账的完整流程，包括登录、创建多个订单、查询订单状态、登出。
    行为序列:
        1. 登录 POST /api/login
        2. 等待 0.2-0.5 秒
        3. 循环 1-3 次创建订单
        4. 查询所有创建的订单
        5. 获取用户信息 GET /api/me
        6. 登出 POST /api/logout
    Args:
        base_url: 基础 URL
        deadline: 执行截止时间
        rng: 随机数生成器
    """
    username = rng.choice(["alice", "bob"])
    order_count = rng.randint(1, 4)
    lookup_repeats = rng.randint(1, 3)
    _note_stage(
        "checkout",
        {"username": username, "order_count": order_count, "lookup_repeats": lookup_repeats},
    )
    token = _login(base_url, username)
    _sleep_between(rng, 0.15, 0.7, deadline)
    
    # 创建多个订单
    order_ids = []
    for _ in range(order_count):
        order_ids.append(_order(base_url, username, rng))
        _sleep_between(rng, 0.15, 0.8, deadline)
    
    # 查询订单状态
    for _ in range(lookup_repeats):
        for order_id in order_ids:
            _order_lookup(base_url, order_id)
            _sleep_between(rng, 0.15, 0.7, deadline)
    
    _me(base_url, token)
    if rng.random() < 0.35:
        _report_export(base_url, username, rng.choice([5, 10, 20]))
    _logout(base_url, token)


def _admin_readonly_audit(base_url: str, deadline: float, rng: random.Random) -> None:
    """
    配置文件: 管理员只读审计操作。
    模拟管理员查看审计日志和搜索用户的行为，这是典型的管理后台操作。
    行为序列:
        1. 管理员登录 POST /api/login (用户 bob)
        2. 等待 0.2-0.5 秒
        3. 获取管理员信息 GET /api/me
        4. 等待 0.2-0.5 秒
        5. 查询审计日志 GET /api/admin/audit
        6. 等待 0.2-0.6 秒
        7. 搜索用户 GET /api/search
        8. 登出 POST /api/logout
    Args:
        base_url: 基础 URL
        deadline: 执行截止时间
        rng: 随机数生成器
    """
    # deploy/vuln_app/app.py 中 bob 初始化为 admin；此 profile 只做只读审计。
    _note_stage("admin_readonly", {"username": "bob", "role": "admin"})
    token = _login(base_url, "bob")
    _sleep_between(rng, 0.2, 0.5, deadline)
    _me(base_url, token)
    _sleep_between(rng, 0.2, 0.5, deadline)
    for _ in range(rng.randint(1, 3)):
        if deadline <= time.monotonic():
            break
        _admin_audit(base_url, token, rng.choice([5, 10, 20, 35]))
        _sleep_between(rng, 0.2, 0.7, deadline)
    _sleep_between(rng, 0.2, 0.6, deadline)
    _search(base_url, rng.choice(["alice", "bob", "sku"]))
    _logout(base_url, token)


def _report_export_batch(base_url: str, deadline: float, rng: random.Random) -> None:
    """
    配置文件: 批量报告导出。
    模拟批量导出报告和搜索的操作，这是典型的数据分析场景。
    行为序列（循环 2-4 次）:
        1. 搜索 GET /api/search
        2. 等待 0.2-0.6 秒
        3. 导出报告 GET /api/report/export
        4. 等待 0.2-0.6 秒  
    Args:
        base_url: 基础 URL
        deadline: 执行截止时间
        rng: 随机数生成器
    """
    limit_buckets = {
        "small": [5, 8, 10],
        "medium": [20, 35, 50],
        "large": [80, 120, 160],
    }
    _note_stage("report_batch", {"limit_buckets": sorted(limit_buckets)})
    for _ in range(rng.randint(2, 5)):
        if deadline <= time.monotonic():
            break
        _search(base_url, rng.choice(SEARCH_TERMS))
        _sleep_between(rng, 0.2, 0.6, deadline)
        bucket = rng.choices(["small", "medium", "large"], weights=[0.5, 0.35, 0.15], k=1)[0]
        _report_export(base_url, rng.choice(SEARCH_TERMS), rng.choice(limit_buckets[bucket]))
        _sleep_between(rng, 0.2, 0.8, deadline)


def _burst_then_idle_retry(base_url: str, deadline: float, rng: random.Random) -> None:
    """
    配置文件: 突发活动后空闲轮询模式。
    模拟复杂的行为模式，包括:
    1. 突发活动阶段：高频请求和部分失败登录
    2. 重试阶段：指数退避重试失败请求
    3. 空闲阶段：低频健康检查
    这个配置文件特别适合测试系统对异常行为模式的检测能力。
    
    阶段 1 - 突发活动 (20-35 秒):
        - 高频商品列表和搜索请求
        - 35% 概率创建订单
        - 25% 概率尝试失败登录（错误密码）
        
    阶段 2 - 重试阶段 (8-15 秒):
        - 查询不存在的订单（模拟失败请求）
        - 指数退避重试
        
    阶段 3 - 空闲阶段 (25-45 秒):
        - 低频健康检查和商品列表查询
        
    Args:
        base_url: 基础 URL
        deadline: 执行截止时间
        rng: 随机数生成器
    """
    # ========================================================================
    # 阶段 1: 突发活动阶段
    # ========================================================================
    burst_seconds = rng.uniform(20.0, 35.0)
    retry_seconds = rng.uniform(8.0, 15.0)
    idle_seconds = rng.uniform(25.0, 45.0)
    _note_stage(
        "burst",
        {
            "burst_seconds": round(burst_seconds, 3),
            "retry_seconds": round(retry_seconds, 3),
            "idle_seconds": round(idle_seconds, 3),
        },
    )
    burst_deadline = min(deadline, time.monotonic() + burst_seconds)
    while burst_deadline > time.monotonic():
        _items(base_url)
        _search(base_url, rng.choice(SEARCH_TERMS))
        
        # 35% 概率创建订单
        if rng.random() < 0.35:
            _order(base_url, "alice", rng)
        
        # 25% 概率尝试失败登录（模拟错误密码）
        if rng.random() < 0.25:
            _request("POST", base_url, "/api/login", {"username": "alice", "password": "bad-password"})
            _sleep_between(rng, 0.4, 1.2, burst_deadline)
        
        _sleep_between(rng, 0.1, 0.3, burst_deadline)

    # ========================================================================
    # 阶段 2: 重试阶段（指数退避）
    # ========================================================================
    _note_stage("retry", {"pattern": "normal_missing_order_backoff"})
    retry_deadline = min(deadline, time.monotonic() + retry_seconds)
    backoff = 0.4  # 初始退避时间
    
    while retry_deadline > time.monotonic():
        # 查询不存在的订单（模拟失败请求）
        _request("GET", base_url, f"/api/order/{rng.randint(8000, 9999)}")
        _sleep_between(rng, backoff, min(backoff * 2.0, 3.0), retry_deadline)
        backoff = min(backoff * 1.5, 3.0)  # 指数退避，最大 3 秒

    # ========================================================================
    # 阶段 3: 空闲阶段
    # ========================================================================
    _note_stage("idle", {"poll": "health_items"})
    idle_deadline = min(deadline, time.monotonic() + idle_seconds)
    while idle_deadline > time.monotonic():
        _health(base_url)
        _items(base_url)
        _sleep_between(rng, 3.0, 5.0, idle_deadline)
