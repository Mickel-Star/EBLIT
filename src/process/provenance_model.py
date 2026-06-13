#!/usr/bin/env python3
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import networkx as nx
from src.common.text import tokenize_identifier


def parse_ip_port(addr: str) -> Tuple[str, int]:
    if not addr:
        return ("", 0)
    addr = str(addr).strip()
    # 匹配 IPv6 地址
    m6 = re.match(r"^\[([0-9a-fA-F:]+)\](?::([0-9]{1,5}))?$", addr)
    if m6:
        ip = m6.group(1)
        port = int(m6.group(2)) if m6.group(2) else 0
        return (ip, port)
    # 匹配 IPv4 地址
    m4 = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::([0-9]{1,5}))?", addr)
    if m4:
        ip = m4.group(1)
        port = int(m4.group(2)) if m4.group(2) else 0
        return (ip, port)
    return (addr, 0)


@dataclass(frozen=True)
class ProvenanceEdge:
    src: str
    dst: str
    edge_type: str
    event_name: str
    timestamp_ns: int
    src_meta: Dict[str, Any]
    dst_meta: Dict[str, Any]


class ProvenanceEventMapper:
    def __init__(self):
        self.event_semantics = {
            "read": ("Read", "backward"),
            "recvfrom": ("Receive", "backward"),
            "mmap": ("Mmap", "backward"),
            "write": ("Write", "forward"),
            "sendto": ("Send", "forward"),
            "execve": ("Execute", "forward"),
            "sched_process_exec": ("Execute", "forward"),
            "fork": ("Fork", "forward"),
            "vfork": ("Fork", "forward"),
            "clone": ("Fork", "forward"),
            "connect": ("Send", "forward"),
            "security_socket_connect": ("Send", "forward"),
            "accept": ("Receive", "backward"),
            "accept4": ("Receive", "backward"),
            "security_socket_accept": ("Receive", "backward"),
            "openat": ("Write", "forward"),
            "close": ("Write", "forward"),
        }
        self.state_only_events = {"socket", "bind", "listen", "getpeername", "getsockname"}
        self._fd_files: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
        self._fd_nets: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
        self._fd_local_sockets: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
        self.af_unspec_count: int = 0
        self.addrlen_zero_count: int = 0

    def _container_scope(self, container_id: Any) -> str:
        value = str(container_id or "").strip().lower()
        return value[:12] if value else "host"

    def _safe_int(self, value: Any, default: int = 0) -> int:
        if isinstance(value, bool):
            return int(default)
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            return int(value)
        text = str(value or "").strip()
        if not text:
            return int(default)
        if re.fullmatch(r"-?\d+", text):
            return int(text)
        try:
            return int(float(text))
        except (ValueError, TypeError):
            return int(default)

    def _coerce_child_pid(self, args: Dict[str, Any], log: Dict[str, Any]) -> int:
        for name in ("child_pid", "newpid", "child_tid"):
            value = args.get(name)
            if value in (None, ""):
                continue
            parsed = self._safe_int(value, 0)
            if parsed > 0:
                return parsed
        return self._safe_int(self._ret_fd(log), 0)

    def parse_log_event(self, log: Dict[str, Any]) -> Optional[ProvenanceEdge]:
        event = (log.get("event") or "").strip()
        pid = self._safe_int(log.get("pid", 0), 0)
        args = log.get("args", {}) or {}
        container_id = log.get("container_id")
        container_scope = self._container_scope(container_id)

        # 纯状态事件：不产生溯源边,只更新内部状态,为后续的connect/sendto/accept等事件提供必需的上下文（例如套接字的本地地址、监听端口）
        if event in self.state_only_events:
            self._update_socket_state_event(event, args, container_scope, pid, log)
            return None

        if event not in self.event_semantics:
            return None

        edge_type, direction = self.event_semantics[event]
        comm = log.get("comm", "unknown")
        timestamp_ns = int(float(log.get("timestamp", 0.0)) * 1e9)

        proc_uuid = f"container:{container_scope}:pid:{pid}"
        proc_node = f"proc:{proc_uuid}"

        proc_path = str(args.get("pathname") or args.get("path") or "")
        proc_meta: Dict[str, Any] = {
            "uuid": proc_uuid,
            "pathname": proc_path,
            "name": comm,
            "pid": pid,
            "container_id": container_id,
            "container_image": log.get("container_image"),
            "pod_name": log.get("pod_name"),
        }
        if log.get("process_entity_id") is not None:
            proc_meta["process_entity_id"] = log["process_entity_id"]

        if event in {"openat", "execve", "sched_process_exec", "read", "write", "close", "mmap"}:
            resolved = self._resolve_file_object(event, args, container_scope, pid, log)
            if resolved is None:
                return None
            obj_node, obj_meta = resolved

        elif event in {"connect", "security_socket_connect", "accept", "accept4", "security_socket_accept", "sendto", "recvfrom"}:
            resolved = self._resolve_net_object(event, args, container_scope, pid, log)
            if resolved is None:
                return None
            obj_node, obj_meta = resolved

        elif event in {"fork", "vfork", "clone"}:
            child_pid = self._coerce_child_pid(args, log)
            if child_pid <= 0:
                return None
            child_uuid = f"container:{container_scope}:pid:{child_pid}"
            obj_node = f"proc:{child_uuid}"
            obj_meta = {
                "uuid": child_uuid,
                "pathname": "",
                "name": f"child_pid_{child_pid}",
                "pid": int(child_pid),
                "container_id": container_id,
                "container_image": log.get("container_image"),
                "pod_name": log.get("pod_name"),
            }
            if log.get("parent_entity_id") is not None:
                obj_meta["process_entity_id"] = log["parent_entity_id"]

        if not obj_node:
            return None

        if direction == "backward":
            edge = ProvenanceEdge(
                src=obj_node,
                dst=proc_node,
                edge_type=edge_type,
                event_name=event,
                timestamp_ns=timestamp_ns,
                src_meta=obj_meta,
                dst_meta=proc_meta,
            )
            self._cleanup_after_event(event, args, container_scope, pid)
            return edge

        edge = ProvenanceEdge(
            src=proc_node,
            dst=obj_node,
            edge_type=edge_type,
            event_name=event,
            timestamp_ns=timestamp_ns,
            src_meta=proc_meta,
            dst_meta=obj_meta,
        )
        self._cleanup_after_event(event, args, container_scope, pid)
        return edge

    def _fd_value(self, args: Dict[str, Any], *names: str) -> str:
        for name in names:
            value = args.get(name)
            if value is not None and str(value).strip():
                fd, _path = self._split_fd_value(value)
                return fd
        return ""

    def _fd_path(self, args: Dict[str, Any], *names: str) -> str:
        for name in names:
            value = args.get(name)
            if value is None or not str(value).strip():
                continue
            _fd, path = self._split_fd_value(value)
            if path:
                return path
        return ""

    def _split_fd_value(self, value: Any) -> Tuple[str, str]:
        text = str(value or "").strip()
        if not text:
            return "", ""
        match = re.match(r"^(-?\d+)\s*=\s*(.+)$", text)
        if match:
            fd = match.group(1).strip()
            path = match.group(2).strip()
            return fd, path
        return text, ""

    def _is_real_file_path(self, path: str) -> bool:
        value = str(path or "").strip()
        if not value:
            return False
        if value.startswith(("socket:[", "pipe:[", "anon_inode:", "memfd:")):
            return False
        return value.startswith("/") or value.startswith("./") or value.startswith("../")

    def _fd_key(self, container_scope: str, pid: int, fd: str) -> Tuple[str, int, str]:
        return (str(container_scope), int(pid), str(fd))

    def _file_from_path(self, path: str, args: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        inode = str(args.get("inode") or "")
        # 每个文件在磁盘上都有一个唯一的 inode， 两个不同路径但 inode 相同的文件（硬链接）是同一个物理文件
        file_uuid = f"{path}|inode:{inode}" if inode else path
        return f"file:{file_uuid}", {"uuid": file_uuid, "pathname": path, "name": path}

    def _resolve_file_object(
        self,
        event: str,
        args: Dict[str, Any],
        container_scope: str,
        pid: int,
        log: Dict[str, Any],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        path = str(args.get("pathname") or args.get("path") or args.get("mountpoint") or "")
        fd = self._fd_value(args, "fd")
        fd_path = self._fd_path(args, "fd")
        if not path and self._is_real_file_path(fd_path):
            path = fd_path
        # 日志格式在提供 fd 的同时还附带该 fd 对应的路径（如 fd_path: "/tmp/foo"）
        if path:
            node, meta = self._file_from_path(path, args)
            if event == "openat":
                # openat 系统调用会返回一个新的文件描述符（fd），该返回值存储在 log["ret"] 中
                returned_fd = int(log.get("ret", -1))
                if returned_fd >= 0:
                    self._fd_files[self._fd_key(container_scope, pid, str(returned_fd))] = {
                        "node": node,
                        "meta": meta,
                    }  # 这样，后续的 read(fd, ...) 或 write(fd, ...) 就可以直接通过 fd 找到对应的文件节点，无需重复传递路径。
            return node, meta

        if fd:
            file_entry = self._fd_files.get(self._fd_key(container_scope, pid, fd))
            if file_entry:
                return str(file_entry["node"]), dict(file_entry["meta"])

            if event == "mmap":  # 对于 mmap 事件且没有 fd 缓存：返回 None
                return None

            if event == "close":  # close 既可以关闭普通文件，也可以关闭网络套接字。如果 _fd_files 中没有对应的条目，则尝试从 _fd_nets 中获取
                net_entry = self._fd_nets.get(self._fd_key(container_scope, pid, fd))
                if net_entry:
                    return str(net_entry["node"]), dict(net_entry["meta"])

            path = f"fd:{fd}_container:{container_scope}_pid:{pid}"
            # 为该资源创建一个唯一的节点标识，避免丢失数据流关系
            return self._file_from_path(path, args)

        return None

    def _addr_arg(self, args: Dict[str, Any], *names: str) -> Any:
        for name in names:
            value = args.get(name)
            if value:
                normalized = self._normalize_addr(value)
                if normalized:
                    return value
        return ""

    def _net_from_addr(self, remote_raw: Any, local_raw: Any, args: Dict[str, Any], pid: int) -> Tuple[str, Dict[str, Any]]:
        remote_addr = self._normalize_addr(remote_raw)
        local_addr = self._normalize_addr(local_raw)
        dst_ip, dst_port = parse_ip_port(remote_addr)
        src_ip, src_port = parse_ip_port(local_addr)
        if not dst_ip:
            dst_ip, dst_port = ("unknown", 0)
        if not src_ip:
            src_ip, src_port = ("pid", pid)
        proto = str(args.get("protocol") or args.get("proto") or "tcp").lower()
        net_uuid = f"{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        meta = {
            "uuid": net_uuid,
            "src_ip": str(src_ip),
            "src_port": int(src_port),
            "dst_ip": str(dst_ip),
            "dst_port": int(dst_port),
            "local_addr": local_addr,
            "remote_addr": remote_addr,
            "remote_addr_known": bool(remote_addr and dst_ip != "unknown"),
            "name": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
        }
        return f"net:{net_uuid}", meta

    def _resolve_net_object(
        self,
        event: str,
        args: Dict[str, Any],
        container_scope: str,
        pid: int,
        log: Dict[str, Any],
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        fd = self._fd_value(args, "sockfd", "fd")
        cache_fd = fd
        if event in {"accept", "accept4"}:
            accepted_fd = self._ret_fd(log)
            if accepted_fd:
                cache_fd = accepted_fd
        fd_key = self._fd_key(container_scope, pid, fd) if fd else None
        cache_fd_key = self._fd_key(container_scope, pid, cache_fd) if cache_fd else None

        remote_raw = self._addr_arg(args, "remote_addr", "dest_addr", "addr", "dst")
        if event in {"accept", "accept4", "security_socket_accept", "recvfrom"}:
            remote_raw = self._addr_arg(args, "src_addr", "remote_addr", "peer_addr", "upeer_sockaddr", "addr", "dst")
        local_raw = self._addr_arg(args, "local_addr", "src")
        if not local_raw:
            local_raw = self._local_raw_for_fd(container_scope, pid, fd)

        is_unspec = self._args_contain_unspec_addr(args) or self._is_addrlen_zero(args)
        self._record_addr_context_stats(args)

        if (not remote_raw or is_unspec) and fd_key is not None:
            cached = self._fd_nets.get(fd_key)
            if cached:
                return str(cached["node"]), dict(cached["meta"])
        if (not remote_raw or is_unspec) and cache_fd_key is not None and cache_fd_key != fd_key:
            cached = self._fd_nets.get(cache_fd_key)
            if cached:
                return str(cached["node"]), dict(cached["meta"])

        if event in {"sendto", "recvfrom"} and is_unspec:
            return self._make_unknown_connected_socket(event, args, container_scope, pid, fd)

        if event in {"connect", "security_socket_connect", "accept", "accept4", "security_socket_accept"} and (
            not remote_raw or is_unspec
        ):
            return None

        if not remote_raw:
            return None

        node, meta = self._net_from_addr(remote_raw, local_raw, args, pid)
        if event in {"connect", "security_socket_connect"} and cache_fd_key is not None and self._ret_success(log):
            self._fd_nets[cache_fd_key] = {"node": node, "meta": meta}
        elif event in {"accept", "accept4"} and cache_fd_key is not None and cache_fd != fd and self._ret_success(log):
            self._fd_nets[cache_fd_key] = {"node": node, "meta": meta}
        elif event == "security_socket_accept" and cache_fd_key is not None and self._ret_success(log):
            self._fd_nets[cache_fd_key] = {"node": node, "meta": meta}
        return node, meta

    def _ret_fd(self, log: Dict[str, Any]) -> str:
        try:
            value = int(log.get("ret", -1))
        except (ValueError, TypeError):
            return ""
        return str(value) if value >= 0 else ""

    def _ret_success(self, log: Dict[str, Any]) -> bool:
        try:
            return int(log.get("ret", 0)) >= 0
        except (ValueError, TypeError):
            return True

    def _local_raw_for_fd(self, container_scope: str, pid: int, fd: str) -> Any:
        if not fd:
            return ""
        entry = self._fd_local_sockets.get(self._fd_key(container_scope, pid, fd))
        if not entry:
            return ""
        return entry.get("local_raw") or ""

    def _update_socket_state_event(
        self,
        event: str,
        args: Dict[str, Any],
        container_scope: str,
        pid: int,
        log: Dict[str, Any],
    ) -> None:
        self._record_addr_context_stats(args)
        fd = self._fd_value(args, "sockfd", "fd")
        if event == "socket":
            fd = self._ret_fd(log) or fd
        if not fd or not self._ret_success(log):
            return

        key = self._fd_key(container_scope, pid, fd)
        entry = dict(self._fd_local_sockets.get(key) or {})
        entry["fd"] = fd
        entry["container_scope"] = container_scope
        entry["pid"] = int(pid)
        proto = str(args.get("protocol") or args.get("proto") or entry.get("protocol") or "tcp").lower()
        entry["protocol"] = proto
        if args.get("domain") is not None:
            entry["domain"] = args.get("domain")
        if args.get("type") is not None:
            entry["socket_type"] = args.get("type")

        if event in {"bind", "getsockname"}:
            local_raw = self._addr_arg(args, "local_addr", "src", "addr", "sockaddr")
            if local_raw:  # 从参数中提取本地地址的原始表示
                entry["local_raw"] = local_raw
                entry["local_addr"] = self._normalize_addr(local_raw)
            if event == "bind":
                entry["bound"] = True  # 表示该套接字已绑定到本地地址
            else:
                entry["getsockname_seen"] = True  # 记录已查询过本地地址
        elif event == "listen":
            entry["listening"] = True
            if args.get("backlog") is not None:
                entry["backlog"] = args.get("backlog")
        elif event == "getpeername":
            # 只有成功获取 remote_raw，且不是未指定地址才能作为有效的网络对端
            remote_raw = self._addr_arg(args, "remote_addr", "peer_addr", "addr", "dst")
            if remote_raw and not (self._args_contain_unspec_addr(args) or self._is_addrlen_zero(args)):
                local_raw = entry.get("local_raw") or self._addr_arg(args, "local_addr", "src")
                node, meta = self._net_from_addr(remote_raw, local_raw, args, pid)
                # 返回一个网络对象节点（如 net:tcp:192.168.1.100:54321）及其元数据
                # 网络对象节点格式：{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}
                self._fd_nets[key] = {"node": node, "meta": meta}
            entry["getpeername_seen"] = True

        self._fd_local_sockets[key] = entry

    def _record_addr_context_stats(self, args: Dict[str, Any]) -> None:
        if not (self._args_contain_unspec_addr(args) or self._is_addrlen_zero(args)):
            return
        if self._args_contain_unspec_addr(args):
            self.af_unspec_count += 1
        else:
            self.addrlen_zero_count += 1

    def _args_contain_unspec_addr(self, args: Dict[str, Any]) -> bool:
        for name in (
            "remote_addr",
            "dest_addr",
            "addr",
            "dst",
            "src_addr",
            "peer_addr",
            "upeer_sockaddr",
            "local_addr",
            "src",
            "sockaddr",
        ):
            value = args.get(name)
            if isinstance(value, dict):
                family = str(value.get("sa_family") or "").upper()
                if family == "AF_UNSPEC":
                    return True
        return False

    def _is_addrlen_zero(self, args: Dict[str, Any]) -> bool:
        for name in ("addrlen", "upeer_addrlen", "peer_addrlen"):
            addrlen = args.get(name)
            if addrlen is not None:
                try:
                    return int(addrlen) == 0
                except (ValueError, TypeError):
                    pass
        return False

    def _make_unknown_connected_socket(
        self,
        event: str,
        args: Dict[str, Any],
        container_scope: str,
        pid: int,
        fd: str,
    ) -> Tuple[str, Dict[str, Any]]:
        proto = str(args.get("protocol") or args.get("proto") or "tcp").lower()
        net_uuid = "unknown_connected_socket"
        meta = {
            "uuid": net_uuid,
            "src_ip": "pid",
            "dst_ip": "unknown_connected_socket",
            "name": "unknown_connected_socket",
            "is_unspec_net": True,
            "remote_addr_known": False,
            "reason": "af_unspec_or_addrlen_zero",
            "event_name": event,
            "protocol": proto,
            "container_scope": container_scope,
            "pid": int(pid),
            "fd": str(fd or ""),
        }
        return f"net:{net_uuid}", meta

    def _cleanup_after_event(self, event: str, args: Dict[str, Any], container_scope: str, pid: int) -> None:
        if event != "close":
            return
        fd = self._fd_value(args, "fd", "sockfd")
        if not fd:
            return
        key = self._fd_key(container_scope, pid, fd)
        self._fd_files.pop(key, None)
        self._fd_nets.pop(key, None)
        self._fd_local_sockets.pop(key, None)

    def _normalize_addr(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, dict):
            family = str(value.get("sa_family") or "").upper()
            if family == "AF_UNSPEC":
                return ""
            if "sun_path" in value:
                return str(value.get("sun_path") or "")
            if "sin_addr" in value:
                addr = str(value.get("sin_addr") or "")
                port = str(value.get("sin_port") or "")
                if addr and port and port != "0":
                    return f"{addr}:{port}"
                return addr
            if "sin6_addr" in value:
                addr = str(value.get("sin6_addr") or "")
                port = str(value.get("sin6_port") or "")
                if addr and port and port != "0":
                    return f"[{addr}]:{port}"
                return addr
            return " ".join([f"{k}:{v}" for k, v in value.items()])
        return str(value)


def rarity_score_from_supports(supports: List[float]) -> float:
    score = 0.0
    for s in supports:
        s = max(float(s), 1e-9)
        score += -math.log2(s)
    return score


def collect_keywords(meta: Dict[str, Any]) -> List[str]:
    kws: List[str] = []
    if not meta:
        return kws
    for key in ("pathname", "name", "src_ip", "dst_ip"):
        val = meta.get(key, "")
        if not val:
            continue
        kws.extend(tokenize_identifier(val))
    return kws


class RarePathSelector:
    def __init__(self, k1: int = 10, k2: int = 10):
        self.k1 = int(k1)
        self.k2 = int(k2)

    def select_with_chains(self, g: nx.MultiDiGraph, seed: str, support_fn) -> List[Dict[str, Any]]:
        if seed not in g:
            return []

        results: List[Dict[str, Any]] = []
        frontier: List[Tuple[str, List[Tuple[str, str, str, str]], int]] = [(seed, [], -1)]
        visited_states = {(seed, 0, -1)}

        for _ in range(self.k1):
            next_frontier: List[Tuple[str, List[Tuple[str, str, str, str]], int]] = []
            for node, edge_chain, last_ts in frontier:
                outgoing = sorted(
                    list(g.out_edges(node, keys=True, data=True)),
                    key=lambda item: (
                        int((item[3] or {}).get("first_ts", 0) or 0),
                        str(item[0]),
                        str(item[1]),
                        str(item[2]),
                    ),
                )
                incoming = sorted(
                    list(g.in_edges(node, keys=True, data=True)),
                    key=lambda item: (
                        int((item[3] or {}).get("first_ts", 0) or 0),
                        str(item[0]),
                        str(item[1]),
                        str(item[2]),
                    ),
                )

                for _, nbr, key, data in outgoing:
                    nbr_meta = g.nodes[nbr].get("meta") or {}
                    if nbr_meta.get("is_unspec_net"):
                        continue
                    et = str(data.get("type"))
                    edge_ts = int((data or {}).get("first_ts", 0) or 0)
                    if edge_ts < int(last_ts):
                        continue
                    chain2 = edge_chain + [(node, et, nbr, "out")]
                    state = (nbr, tuple(chain2), edge_ts)
                    if state not in visited_states:
                        visited_states.add(state)
                        next_frontier.append((nbr, chain2, edge_ts))
                        supports = []
                        for u, t, v, direction in chain2:
                            src_meta = g.nodes[u].get("meta", {}) if direction == "out" else g.nodes[v].get("meta", {})
                            dst_meta = g.nodes[v].get("meta", {}) if direction == "out" else g.nodes[u].get("meta", {})
                            try:
                                if direction == "out":
                                    supports.append(float(support_fn(u, v, t, src_meta, dst_meta)))
                                else:
                                    supports.append(float(support_fn(v, u, t, src_meta, dst_meta)))
                            except Exception:
                                supports.append(1e-9)
                        score = rarity_score_from_supports(supports)
                        text = self._chain_to_text(g, seed, chain2)
                        kws = []
                        kws.extend(collect_keywords(g.nodes[seed].get("meta", {})))
                        kws.extend(collect_keywords(g.nodes[nbr].get("meta", {})))
                        results.append(
                            {
                                "text": text,
                                "score": score,
                                "keywords": list(dict.fromkeys(kws)),
                                "chain": chain2,
                            }
                        )

                for nbr, _, key, data in incoming:
                    nbr_meta = g.nodes[nbr].get("meta") or {}
                    if nbr_meta.get("is_unspec_net"):
                        continue
                    et = str(data.get("type"))
                    edge_ts = int((data or {}).get("first_ts", 0) or 0)
                    if edge_ts < int(last_ts):
                        continue
                    chain2 = edge_chain + [(node, et, nbr, "in")]
                    state = (nbr, tuple(chain2), edge_ts)
                    if state not in visited_states:
                        visited_states.add(state)
                        next_frontier.append((nbr, chain2, edge_ts))
                        supports = []
                        for u, t, v, direction in chain2:
                            src_meta = g.nodes[u].get("meta", {}) if direction == "out" else g.nodes[v].get("meta", {})
                            dst_meta = g.nodes[v].get("meta", {}) if direction == "out" else g.nodes[u].get("meta", {})
                            try:
                                if direction == "out":
                                    supports.append(float(support_fn(u, v, t, src_meta, dst_meta)))
                                else:
                                    supports.append(float(support_fn(v, u, t, src_meta, dst_meta)))
                            except Exception:
                                supports.append(1e-9)
                        score = rarity_score_from_supports(supports)
                        text = self._chain_to_text(g, seed, chain2)
                        kws = []
                        kws.extend(collect_keywords(g.nodes[seed].get("meta", {})))
                        kws.extend(collect_keywords(g.nodes[nbr].get("meta", {})))
                        results.append(
                            {
                                "text": text,
                                "score": score,
                                "keywords": list(dict.fromkeys(kws)),
                                "chain": chain2,
                            }
                        )
            frontier = next_frontier

        results.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
        return results[: self.k2]

    def _chain_to_text(self, g: nx.MultiDiGraph, seed: str, chain: List[Tuple[str, str, str, str]]) -> str:
        parts: List[str] = []
        seed_meta = g.nodes[seed].get("meta", {})
        seed_name = seed_meta.get("pathname") or seed_meta.get("name") or seed
        parts.append(str(seed_name))
        for _, et, v, direction in chain:
            v_meta = g.nodes[v].get("meta", {})
            v_name = v_meta.get("pathname") or v_meta.get("name") or v
            parts.append(f"{et}{'<-' if direction == 'in' else '->'}")
            parts.append(str(v_name))
        return " ".join(parts)
