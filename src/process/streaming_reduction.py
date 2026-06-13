#!/usr/bin/env python3
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Tuple

import networkx as nx

from src.common.defaults import DEFAULT_DETECT_STRIDE_SECONDS, DEFAULT_TIME_BIN_SECONDS, DEFAULT_WINDOW_SECONDS
from src.process.provenance_model import ProvenanceEventMapper, ProvenanceEdge


@dataclass(frozen=True)
class StreamingReductionConfig:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS
    edge_key_mode: str = "event_time_bin"

    @property
    def window_ns(self) -> int:
        return int(self.window_seconds) * 1_000_000_000

    @property
    def bin_ns(self) -> int:
        return max(int(self.time_bin_seconds), 1) * 1_000_000_000

    def normalized_edge_key_mode(self) -> str:
        value = str(self.edge_key_mode or "").strip().lower()
        if value in {"semantic", "event_time_bin"}:
            return value
        return "event_time_bin"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_seconds": int(self.window_seconds),
            "time_bin_seconds": int(self.time_bin_seconds),
            "edge_key_mode": self.normalized_edge_key_mode(),
        }


def normalize_window_mode(value: str | None) -> str:
    mode = str(value or "sliding").strip().lower()
    if mode in {"sliding", "fixed"}:
        return mode
    return "sliding"


class StreamingReducer:
    def __init__(
        self,
        mapper: Optional[ProvenanceEventMapper] = None,
        config: Optional[StreamingReductionConfig] = None,
    ):
        self.mapper = mapper or ProvenanceEventMapper()
        self.config = config or StreamingReductionConfig()
        self._window_start_ns: Optional[int] = None
        self._graph: nx.MultiDiGraph = self._new_graph()
        self._metas: Dict[str, Dict[str, Any]] = {}
        self._semantic_versions: Dict[str, int] = {}

    def _new_graph(self) -> nx.MultiDiGraph:
        graph = nx.MultiDiGraph()
        graph.graph["reduction_config"] = self.config.to_dict()
        return graph

    def ingest_logs(self, logs: Iterable[Dict[str, Any]]) -> Iterator[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        for log in logs:
            g = self.ingest_log(log)
            if g is not None:
                yield g
        final = self.flush()
        if final is not None:
            yield final

    def ingest_log(self, log: Dict[str, Any]) -> Optional[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        e = self.mapper.parse_log_event(log)
        if not e:
            return None
        return self.ingest_edge(e)

    def ingest_edge(self, e: ProvenanceEdge) -> Optional[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        if self._window_start_ns is None:
            self._window_start_ns = e.timestamp_ns
        elif e.timestamp_ns - self._window_start_ns >= self.config.window_ns:
            finished = (self._graph, self._metas)
            self._reset_window(e.timestamp_ns)
            self._add_edge(e)
            return finished

        self._add_edge(e)
        return None

    def flush(self) -> Optional[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
        if self._window_start_ns is None or self._graph.number_of_nodes() == 0:
            return None
        finished = (self._graph, self._metas)
        self._reset_window(None)
        return finished

    def _reset_window(self, new_start_ns: Optional[int]) -> None:
        self._window_start_ns = new_start_ns
        self._graph = self._new_graph()
        self._metas = {}
        self._semantic_versions = {}

    def _time_bin(self, ts_ns: int) -> int:
        if self._window_start_ns is None:
            return 0
        return int((ts_ns - self._window_start_ns) // self.config.bin_ns) + 1

    def _add_edge(self, e: ProvenanceEdge) -> None:
        if e.src not in self._graph:
            self._graph.add_node(e.src, meta=e.src_meta)
        if e.dst not in self._graph:
            self._graph.add_node(e.dst, meta=e.dst_meta)

        self._metas[e.src] = e.src_meta
        self._metas[e.dst] = e.dst_meta
        self._semantic_versions.setdefault(str(e.src), 0)
        self._semantic_versions.setdefault(str(e.dst), 0)

        et = str(e.edge_type)
        event_name = str(e.event_name or "")
        bin_idx = self._time_bin(e.timestamp_ns)
        source_version = int(self._semantic_versions.get(str(e.src), 0))

        found_key = None
        for key, attrs in self._graph.get_edge_data(e.src, e.dst, default={}).items():
            if self._same_reduced_edge(attrs, et, event_name, bin_idx, source_version):
                found_key = key
                break

        if found_key is None:
            segments = [{"bin": int(bin_idx), "count": 1}]
            self._graph.add_edge(
                e.src,
                e.dst,
                type=et,
                event_name=event_name,
                event_names=[event_name] if event_name else [],
                bin_idx=int(bin_idx),
                source_semantic_version=int(source_version),
                count=1,
                first_ts=e.timestamp_ns,
                last_ts=e.timestamp_ns,
                segments=segments,
            )
        else:
            cur = self._graph[e.src][e.dst][found_key]
            cur["count"] = int(cur.get("count", 1)) + 1
            cur["last_ts"] = e.timestamp_ns
            event_names = list(cur.get("event_names") or [])
            if event_name and event_name not in event_names:
                event_names.append(event_name)
            cur["event_names"] = event_names
            segs = cur.get("segments") or []
            if segs and int(segs[-1].get("bin", -1)) == int(bin_idx):
                segs[-1]["count"] = int(segs[-1].get("count", 0)) + 1
            else:
                segs.append({"bin": int(bin_idx), "count": 1})
            cur["segments"] = segs

        self._apply_semantic_transition(e)

    def _same_reduced_edge(
        self,
        attrs: Dict[str, Any],
        edge_type: str,
        event_name: str,
        bin_idx: int,
        source_version: int,
    ) -> bool:
        if attrs.get("type") != edge_type:
            return False
        if str(edge_type) == "Fork":
            return False
        return (
            str(attrs.get("event_name") or "") == str(event_name or "")
            and int(attrs.get("bin_idx") or 0) == int(bin_idx)
            and int(attrs.get("source_semantic_version") or 0) == int(source_version)
        )

    def _node_kind(self, node_id: str) -> str:
        node = str(node_id or "")
        if node.startswith("proc:"):
            return "proc"
        if node.startswith("file:"):
            return "file"
        if node.startswith("net:"):
            return "net"
        return "unknown"

    def _apply_semantic_transition(self, e: ProvenanceEdge) -> None:
        edge_type = str(e.edge_type or "")
        src_kind = self._node_kind(str(e.src))
        dst_kind = self._node_kind(str(e.dst))

        if edge_type == "Fork":
            if dst_kind == "proc":
                self._semantic_versions[str(e.dst)] = 0
            return

        if edge_type in {"Read", "Receive", "Mmap", "Execute"}:
            if src_kind == "proc":
                target = str(e.src)
            elif dst_kind == "proc":
                target = str(e.dst)
            else:
                target = ""
            if target:
                self._semantic_versions[target] = int(self._semantic_versions.get(target, 0)) + 1
            return

        if edge_type in {"Write", "Send"}:
            if src_kind == "proc" and dst_kind in {"file", "net"}:
                target = str(e.dst)
            elif dst_kind == "proc" and src_kind in {"file", "net"}:
                target = str(e.src)
            else:
                target = ""
            if target:
                self._semantic_versions[target] = int(self._semantic_versions.get(target, 0)) + 1


@dataclass(frozen=True)
class SlidingWindowConfig:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS
    edge_key_mode: str = "event_time_bin"

    @property
    def window_ns(self) -> int:
        return int(self.window_seconds) * 1_000_000_000

    @property
    def stride_ns(self) -> int:
        return int(self.stride_seconds) * 1_000_000_000

    @property
    def bin_ns(self) -> int:
        return max(int(self.time_bin_seconds), 1) * 1_000_000_000

    def normalized_edge_key_mode(self) -> str:
        value = str(self.edge_key_mode or "").strip().lower()
        if value in {"semantic", "event_time_bin"}:
            return value
        return "event_time_bin"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_seconds": int(self.window_seconds),
            "stride_seconds": int(self.stride_seconds),
            "time_bin_seconds": int(self.time_bin_seconds),
            "edge_key_mode": self.normalized_edge_key_mode(),
        }


@dataclass(frozen=True)
class SlidingWindowResult:
    window_start_ns: int
    window_end_ns: int
    graph: nx.MultiDiGraph
    metas: Dict[str, Dict[str, Any]]
    event_count: int
    complete: bool = True

    @property
    def window_start(self) -> float:
        return float(self.window_start_ns) / 1_000_000_000.0

    @property
    def window_end(self) -> float:
        return float(self.window_end_ns) / 1_000_000_000.0


class SlidingWindowReducer:
    def __init__(
        self,
        mapper: Optional[ProvenanceEventMapper] = None,
        config: Optional[SlidingWindowConfig] = None,
    ):
        self.mapper = mapper or ProvenanceEventMapper()
        self.config = config or SlidingWindowConfig()
        if int(self.config.window_seconds) <= 0:
            raise ValueError("window_seconds must be > 0")
        if int(self.config.stride_seconds) <= 0:
            raise ValueError("stride_seconds must be > 0")
        if int(self.config.stride_seconds) > int(self.config.window_seconds):
            raise ValueError("stride_seconds must be <= window_seconds")

        self._edges: Deque[ProvenanceEdge] = deque()
        self._origin_ns: Optional[int] = None
        self._next_window_start_ns: Optional[int] = None
        self._last_seen_ts_ns: Optional[int] = None

    def add_event(self, log: Dict[str, Any]) -> List[SlidingWindowResult]:
        edge = self.mapper.parse_log_event(log)
        if edge is None:
            return []
        return self.add_edge(edge)

    def ingest_log(self, log: Dict[str, Any]) -> List[SlidingWindowResult]:
        return self.add_event(log)

    def ingest_logs(self, logs: Iterable[Dict[str, Any]], *, emit_partial: bool = False) -> Iterator[SlidingWindowResult]:
        for log in logs:
            for window in self.add_event(log):
                yield window
        for window in self.flush(emit_partial=emit_partial):
            yield window

    def add_edge(self, edge: ProvenanceEdge) -> List[SlidingWindowResult]:
        ts_ns = int(edge.timestamp_ns)
        if self._origin_ns is None:
            self._origin_ns = ts_ns
            self._next_window_start_ns = ts_ns

        emitted = self._emit_due_windows(ts_ns)
        self._edges.append(edge)
        self._last_seen_ts_ns = ts_ns
        self._drop_expired_edges()
        return emitted

    def flush(self, *, emit_partial: bool = True) -> List[SlidingWindowResult]:
        if not emit_partial:
            self._reset()
            return []
        if self._next_window_start_ns is None or self._last_seen_ts_ns is None:
            return []

        window_start_ns = int(self._next_window_start_ns)
        if window_start_ns > int(self._last_seen_ts_ns):
            self._reset()
            return []

        result = self._build_window(window_start_ns, complete=False)
        self._reset()
        if result.event_count <= 0:
            return []
        return [result]

    def finalize(self, *, emit_partial: bool = True) -> List[SlidingWindowResult]:
        return self.flush(emit_partial=emit_partial)

    def _emit_due_windows(self, current_ts_ns: int) -> List[SlidingWindowResult]:
        if self._next_window_start_ns is None:
            return []

        emitted: List[SlidingWindowResult] = []
        while int(current_ts_ns) >= int(self._next_window_start_ns) + self.config.window_ns:
            emitted.append(self._build_window(int(self._next_window_start_ns), complete=True))
            self._next_window_start_ns = int(self._next_window_start_ns) + self.config.stride_ns
        return emitted

    def _build_window(self, window_start_ns: int, *, complete: bool) -> SlidingWindowResult:
        window_end_ns = int(window_start_ns) + self.config.window_ns
        selected = [
            edge
            for edge in self._edges
            if int(window_start_ns) <= int(edge.timestamp_ns) < int(window_end_ns)
        ]

        reduction_config = StreamingReductionConfig(
            window_seconds=int(self.config.window_seconds),
            time_bin_seconds=int(self.config.time_bin_seconds),
            edge_key_mode=self.config.normalized_edge_key_mode(),
        )
        reducer = StreamingReducer(mapper=self.mapper, config=reduction_config)
        reducer._window_start_ns = int(window_start_ns)
        for edge in selected:
            reducer._add_edge(edge)

        graph = reducer._graph
        graph.graph["reduction_config"] = reduction_config.to_dict()
        graph.graph["sliding_window_config"] = self.config.to_dict()
        graph.graph["window_start_ns"] = int(window_start_ns)
        graph.graph["window_end_ns"] = int(window_end_ns)
        graph.graph["window_start"] = float(window_start_ns) / 1_000_000_000.0
        graph.graph["window_end"] = float(window_end_ns) / 1_000_000_000.0
        graph.graph["event_count"] = int(len(selected))
        graph.graph["complete"] = bool(complete)
        graph.graph["window_mode"] = "sliding"

        return SlidingWindowResult(
            window_start_ns=int(window_start_ns),
            window_end_ns=int(window_end_ns),
            graph=graph,
            metas=dict(reducer._metas),
            event_count=int(len(selected)),
            complete=bool(complete),
        )

    def _drop_expired_edges(self) -> None:
        if self._next_window_start_ns is None:
            return
        keep_from_ns = int(self._next_window_start_ns)
        while self._edges and int(self._edges[0].timestamp_ns) < keep_from_ns:
            self._edges.popleft()

    def _reset(self) -> None:
        self._edges.clear()
        self._origin_ns = None
        self._next_window_start_ns = None
        self._last_seen_ts_ns = None


def iter_reduced_edges(g: nx.MultiDiGraph) -> List[Tuple[str, str, str, int]]:
    edges = []
    for u, v, key, data in g.edges(keys=True, data=True):
        edges.append((u, v, str(data.get("type")), int(data.get("count", 1))))
    return edges


def iter_window_graphs(
    logs: Iterable[Dict[str, Any]],
    *,
    window_mode: str = "sliding",
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS,
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS,
    mapper: Optional[ProvenanceEventMapper] = None,
    emit_partial: bool = True,
) -> Iterator[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
    """Yield reduced provenance window graphs.

    Sliding windows are the default detection path. Fixed windows are retained
    for baseline runs and legacy comparisons.
    """

    mode = normalize_window_mode(window_mode)
    if mode == "fixed":
        reducer = StreamingReducer(
            mapper=mapper,
            config=StreamingReductionConfig(
                window_seconds=int(window_seconds),
                time_bin_seconds=int(time_bin_seconds),
            ),
        )
        yield from reducer.ingest_logs(logs)
        return

    reducer = SlidingWindowReducer(
        mapper=mapper,
        config=SlidingWindowConfig(
            window_seconds=int(window_seconds),
            stride_seconds=int(stride_seconds),
            time_bin_seconds=int(time_bin_seconds),
        ),
    )
    for result in reducer.ingest_logs(logs, emit_partial=bool(emit_partial)):
        yield result.graph, result.metas
