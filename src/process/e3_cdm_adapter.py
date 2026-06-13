from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from src.process.provenance_model import ProvenanceEdge
from src.process.streaming_reduction import SlidingWindowConfig, SlidingWindowReducer


SUPPORTED_EVENT_TYPES = {
    "EVENT_ACCEPT": ("Receive", "backward"),
    "EVENT_CLOSE": ("Write", "forward"),
    "EVENT_CONNECT": ("Send", "forward"),
    "EVENT_EXECUTE": ("Execute", "forward"),
    "EVENT_FORK": ("Fork", "forward"),
    "EVENT_MMAP": ("Mmap", "backward"),
    "EVENT_OPEN": ("Write", "forward"),
    "EVENT_READ": ("Read", "backward"),
    "EVENT_RECVFROM": ("Receive", "backward"),
    "EVENT_SENDTO": ("Send", "forward"),
    "EVENT_WRITE": ("Write", "forward"),
}


def _unwrap_value(value: Any) -> Any:
    if isinstance(value, dict) and len(value) == 1:
        only = next(iter(value.values()))
        if isinstance(only, (str, int, float, bool)) or only is None:
            return only
    return value


def _uuid_field(value: Any) -> str:
    if isinstance(value, dict):
        for item in value.values():
            text = str(item or "").strip()
            if text:
                return text
        return ""
    return str(value or "").strip()


def _string_field(value: Any) -> str:
    raw = _unwrap_value(value)
    return str(raw or "").strip()


def _int_field(value: Any, default: int = 0) -> int:
    raw = _unwrap_value(value)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _properties_map(payload: Dict[str, Any]) -> Dict[str, Any]:
    props = payload.get("properties")
    if isinstance(props, dict):
        value = props.get("map")
        if isinstance(value, dict):
            return dict(value)
    return {}


def _predicate_path(event: Dict[str, Any], key: str) -> str:
    value = event.get(key)
    if isinstance(value, dict):
        for candidate in value.values():
            text = str(candidate or "").strip()
            if text:
                return text
        return ""
    return str(value or "").strip()


def _iter_cadets_json_files(root: Path) -> List[Path]:
    bases: Dict[str, List[tuple[int, Path]]] = {}
    for path in root.iterdir():
        if not path.is_file():
            continue
        if path.name == "cadets.txt":
            continue
        if not path.name.endswith(".json") and ".json." not in path.name:
            continue
        if ".json." in path.name:
            base, suffix = path.name.split(".json.", 1)
            shard_idx = int(suffix) if suffix.isdigit() else 10_000
            key = base + ".json"
        else:
            key = path.name
            shard_idx = 0
        bases.setdefault(key, []).append((shard_idx, path))
    ordered: List[Path] = []
    for key in sorted(bases):
        ordered.extend(path for _idx, path in sorted(bases[key], key=lambda item: item[0]))
    return ordered


@dataclass
class E3WindowBuildResult:
    graph: Any
    split_role: str
    source_run_id: str
    source_profile: str
    trainable: bool
    metadata: Dict[str, Any]


class E3CADETSMapper:
    def __init__(self, malicious_uuids: Optional[Iterable[str]] = None):
        self.subjects: Dict[str, Dict[str, Any]] = {}
        self.file_objects: Dict[str, Dict[str, Any]] = {}
        self.netflow_objects: Dict[str, Dict[str, Any]] = {}
        self.principals: Dict[str, Dict[str, Any]] = {}
        self.malicious_uuids = {str(item or "").strip().upper() for item in (malicious_uuids or []) if str(item or "").strip()}

    def register_record(self, record_type: str, payload: Dict[str, Any]) -> None:
        uuid = str(payload.get("uuid") or "").strip().upper()
        if not uuid:
            return
        if record_type == "Subject":
            self.subjects[uuid] = dict(payload)
        elif record_type == "FileObject":
            self.file_objects[uuid] = dict(payload)
        elif record_type == "NetFlowObject":
            self.netflow_objects[uuid] = dict(payload)
        elif record_type == "Principal":
            self.principals[uuid] = dict(payload)

    def event_is_malicious(self, event: Dict[str, Any]) -> bool:
        for key in ("subject", "predicateObject", "predicateObject2"):
            uuid = _uuid_field(event.get(key)).upper()
            if uuid and uuid in self.malicious_uuids:
                return True
        return False

    def event_to_edge(self, event: Dict[str, Any]) -> Optional[ProvenanceEdge]:
        event_type = str(event.get("type") or "").strip()
        if event_type not in SUPPORTED_EVENT_TYPES:
            return None
        subject_uuid = _uuid_field(event.get("subject")).upper()
        if not subject_uuid:
            return None
        subject = self.subjects.get(subject_uuid)
        if not subject:
            return None

        edge_type, direction = SUPPORTED_EVENT_TYPES[event_type]
        timestamp_ns = _int_field(event.get("timestampNanos"), 0)
        if timestamp_ns <= 0:
            return None

        props = _properties_map(event)
        proc_node, proc_meta = self._subject_node(subject, props)

        object_uuid = _uuid_field(event.get("predicateObject")).upper()
        obj_node = ""
        obj_meta: Dict[str, Any] = {}

        if event_type == "EVENT_FORK":
            child_subject = self.subjects.get(object_uuid)
            if child_subject is None:
                return None
            obj_node, obj_meta = self._subject_node(child_subject, _properties_map(child_subject))
        elif object_uuid in self.netflow_objects:
            obj_node, obj_meta = self._netflow_node(self.netflow_objects[object_uuid])
        elif object_uuid in self.file_objects:
            path_hint = _predicate_path(event, "predicateObjectPath") or str(props.get("partial_path") or "")
            obj_node, obj_meta = self._file_object_node(self.file_objects[object_uuid], path_hint=path_hint)
        else:
            return None

        if event_type == "EVENT_EXECUTE":
            exec_path = _predicate_path(event, "predicateObjectPath")
            if exec_path:
                proc_meta = dict(proc_meta)
                proc_meta["exec_target_path"] = exec_path
            predicate2_path = _predicate_path(event, "predicateObject2Path")
            if predicate2_path:
                obj_meta = dict(obj_meta)
                obj_meta["predicate_object2_path"] = predicate2_path
                obj_meta["loader_path"] = predicate2_path

        event_name = _string_field(event.get("name")) or event_type
        if direction == "backward":
            return ProvenanceEdge(
                src=obj_node,
                dst=proc_node,
                edge_type=edge_type,
                event_name=event_name,
                timestamp_ns=timestamp_ns,
                src_meta=obj_meta,
                dst_meta=proc_meta,
            )
        return ProvenanceEdge(
            src=proc_node,
            dst=obj_node,
            edge_type=edge_type,
            event_name=event_name,
            timestamp_ns=timestamp_ns,
            src_meta=proc_meta,
            dst_meta=obj_meta,
        )

    def _subject_node(self, subject: Dict[str, Any], props: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        uuid = str(subject.get("uuid") or "").strip().upper()
        cid = _int_field(subject.get("cid"), 0)
        start_ts = _int_field(subject.get("startTimestampNanos"), 0)
        proc_uuid = f"cadets:{uuid}:cid:{cid or 0}"
        cmdline = _string_field(subject.get("cmdLine"))
        exec_name = str(props.get("exec") or "").strip()
        parent = str(props.get("ppid") or "").strip()
        meta = {
            "uuid": uuid,
            "pid": cid,
            "name": exec_name or cmdline or f"subject_{cid or uuid[:8].lower()}",
            "pathname": cmdline or exec_name,
            "container_id": "cadets_host",
            "container_image": "darpa_e3_cadets",
            "host_id": _string_field(subject.get("hostId")),
            "start_timestamp_ns": start_ts,
            "principal_uuid": _string_field(subject.get("localPrincipal")),
            "ppid": parent,
            "source_dataset": "darpa_e3_cadets",
        }
        return f"proc:{proc_uuid}", meta

    def _file_object_node(self, file_object: Dict[str, Any], *, path_hint: str = "") -> tuple[str, Dict[str, Any]]:
        uuid = str(file_object.get("uuid") or "").strip().upper()
        file_type = _string_field(file_object.get("type"))
        normalized_path = str(path_hint or "").strip()
        if not normalized_path:
            normalized_path = f"cadets://{file_type.lower() or 'file'}/{uuid.lower()}"
        node_id = f"file:{normalized_path}"
        meta = {
            "uuid": uuid,
            "pathname": normalized_path,
            "name": normalized_path,
            "cadets_file_type": file_type,
            "source_dataset": "darpa_e3_cadets",
            "socket_type": "unix" if "SOCKET" in file_type else "",
        }
        return node_id, meta

    def _netflow_node(self, netflow: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        uuid = str(netflow.get("uuid") or "").strip().upper()
        local_addr = _string_field(netflow.get("localAddress"))
        local_port = _int_field(netflow.get("localPort"), 0)
        remote_addr = _string_field(netflow.get("remoteAddress"))
        remote_port = _int_field(netflow.get("remotePort"), 0)
        protocol = _string_field(netflow.get("ipProtocol")) or "ip"
        label = f"{local_addr}:{local_port}->{remote_addr}:{remote_port}"
        node_id = f"net:{protocol}:{local_addr}:{local_port}->{remote_addr}:{remote_port}"
        meta = {
            "uuid": uuid,
            "src_ip": local_addr,
            "src_port": int(local_port),
            "dst_ip": remote_addr,
            "dst_port": int(remote_port),
            "name": label,
            "protocol": protocol,
            "source_dataset": "darpa_e3_cadets",
        }
        return node_id, meta


def load_malicious_uuid_list(path: str | Path) -> set[str]:
    p = Path(path)
    values: set[str] = set()
    if not p.exists():
        return values
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = str(line or "").strip()
        if not text or text.startswith("#"):
            continue
        values.add(text.upper())
    return values


def iter_cadets_events(e3_dir: str | Path) -> Iterator[tuple[str, Dict[str, Any], int]]:
    root = Path(e3_dir).expanduser().resolve()
    for path in _iter_cadets_json_files(root):
        with path.open("r", encoding="utf-8", errors="ignore") as fp:
            for line_no, line in enumerate(fp, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except Exception:
                    continue
                datum = payload.get("datum") if isinstance(payload, dict) else None
                if not isinstance(datum, dict) or not datum:
                    continue
                key = next(iter(datum.keys()))
                short = key.split(".")[-1]
                record = datum[key]
                if isinstance(record, dict):
                    yield short, record, line_no


def build_e3_windows(
    *,
    e3_dir: str | Path,
    groundtruth_path: str | Path,
    window_seconds: int,
    stride_seconds: int,
    time_bin_seconds: int,
    max_windows: int = 0,
    emit_partial: bool = False,
) -> tuple[List[E3WindowBuildResult], Dict[str, Any]]:
    malicious = load_malicious_uuid_list(groundtruth_path)
    mapper = E3CADETSMapper(malicious_uuids=malicious)
    reducer = SlidingWindowReducer(
        mapper=None,
        config=SlidingWindowConfig(
            window_seconds=int(window_seconds),
            stride_seconds=int(stride_seconds),
            time_bin_seconds=int(time_bin_seconds),
        ),
    )
    results: List[E3WindowBuildResult] = []
    counters = {
        "records_total": 0,
        "events_total": 0,
        "events_supported": 0,
        "events_malicious_filtered": 0,
        "events_unsupported": 0,
        "events_unresolved": 0,
        "windows_total": 0,
    }
    excluded_window_count = 0
    max_window_count = max(0, int(max_windows))

    def append_window(window) -> bool:
        metadata = {
            "window_start": window.window_start,
            "window_end": window.window_end,
            "event_count": int(window.event_count),
            "complete": bool(window.complete),
        }
        results.append(
            E3WindowBuildResult(
                graph=window.graph,
                split_role="train",
                source_run_id="cadets_e3_pretrain",
                source_profile="cadets_e3_benign_filtered",
                trainable=bool(window.event_count > 0),
                metadata=metadata,
            )
        )
        counters["windows_total"] += 1
        return bool(max_window_count > 0 and len(results) >= max_window_count)

    for record_type, payload, _line_no in iter_cadets_events(e3_dir):
        counters["records_total"] += 1
        if record_type != "Event":
            mapper.register_record(record_type, payload)
            continue
        counters["events_total"] += 1
        if mapper.event_is_malicious(payload):
            counters["events_malicious_filtered"] += 1
            continue
        event_type = str(payload.get("type") or "").strip()
        if event_type not in SUPPORTED_EVENT_TYPES:
            counters["events_unsupported"] += 1
            continue
        edge = mapper.event_to_edge(payload)
        if edge is None:
            counters["events_unresolved"] += 1
            continue
        counters["events_supported"] += 1
        for window in reducer.add_edge(edge):
            if append_window(window):
                summary = {
                    **counters,
                    "malicious_uuid_count": int(len(malicious)),
                    "excluded_attack_window_count": int(excluded_window_count),
                    "groundtruth_path": str(Path(groundtruth_path).expanduser().resolve()),
                    "dataset": "darpa_e3_cadets",
                    "source_mode": "e3_cadets_pretrain",
                    "windows_limited_to": int(max_window_count),
                    "truncated": True,
                }
                return results, summary

    for window in reducer.finalize(emit_partial=bool(emit_partial)):
        if append_window(window):
            break

    summary = {
        **counters,
        "malicious_uuid_count": int(len(malicious)),
        "excluded_attack_window_count": int(excluded_window_count),
        "groundtruth_path": str(Path(groundtruth_path).expanduser().resolve()),
        "dataset": "darpa_e3_cadets",
        "source_mode": "e3_cadets_pretrain",
    }
    return results, summary
