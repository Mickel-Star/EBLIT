import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Tuple

import networkx as nx

from src.common.defaults import DEFAULT_DETECT_STRIDE_SECONDS, DEFAULT_TIME_BIN_SECONDS, DEFAULT_WINDOW_SECONDS
from src.process.log_parser import TraceeLogParser
from src.process.streaming_reduction import (
    SlidingWindowConfig,
    SlidingWindowReducer,
    StreamingReductionConfig,
    StreamingReducer,
    normalize_window_mode,
)


@dataclass(frozen=True)
class RealtimeConfig:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    time_bin_seconds: int = DEFAULT_TIME_BIN_SECONDS
    poll_interval_seconds: float = 0.2
    start_at_end: bool = True
    window_mode: str = "sliding"
    stride_seconds: int = DEFAULT_DETECT_STRIDE_SECONDS
    emit_partial: bool = False


class TraceeTail:
    def __init__(self, file_path: str, start_at_end: bool = True):
        self.file_path = file_path
        self.start_at_end = bool(start_at_end)
        self._fp = None

    def __enter__(self):
        self._fp = open(self.file_path, "r", encoding="utf-8", errors="ignore")
        if self.start_at_end:
            self._fp.seek(0, os.SEEK_END)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._fp:
                self._fp.close()
        finally:
            self._fp = None

    def read_new_lines(self) -> List[str]:
        if not self._fp:
            return []
        lines = []
        while True:
            pos = self._fp.tell()
            line = self._fp.readline()
            if not line:
                self._fp.seek(pos)
                break
            s = line.strip()
            if s:
                lines.append(s)
        return lines


def iter_realtime_windows(
    file_path: str,
    cfg: RealtimeConfig,
) -> Iterator[Tuple[nx.MultiDiGraph, Dict[str, Dict[str, Any]]]]:
    parser = TraceeLogParser()
    window_mode = normalize_window_mode(cfg.window_mode)
    if window_mode not in {"fixed", "sliding"}:
        raise ValueError(f"unsupported realtime window_mode: {cfg.window_mode!r}")

    if window_mode == "fixed":
        reducer = StreamingReducer(
            config=StreamingReductionConfig(
                window_seconds=int(cfg.window_seconds),
                time_bin_seconds=int(cfg.time_bin_seconds),
            )
        )
    else:
        reducer = SlidingWindowReducer(
            config=SlidingWindowConfig(
                window_seconds=int(cfg.window_seconds),
                stride_seconds=int(cfg.stride_seconds),
                time_bin_seconds=int(cfg.time_bin_seconds),
            )
        )

    with TraceeTail(file_path, start_at_end=cfg.start_at_end) as tail:
        while True:
            new_lines = tail.read_new_lines()
            if not new_lines:
                if bool(cfg.emit_partial):
                    if window_mode == "fixed":
                        out = reducer.flush()
                        if out is not None:
                            yield out
                            continue
                    else:
                        emitted_partial = False
                        for result in reducer.flush(emit_partial=True):
                            emitted_partial = True
                            yield result.graph, result.metas
                        if emitted_partial:
                            continue
                time.sleep(float(cfg.poll_interval_seconds))
                continue
            for line in new_lines:
                parsed = parser.parse_line(line)
                if not parsed:
                    continue
                if window_mode == "fixed":
                    out = reducer.ingest_log(parsed)
                    if out is not None:
                        yield out
                else:
                    for result in reducer.ingest_log(parsed):
                        yield result.graph, result.metas
