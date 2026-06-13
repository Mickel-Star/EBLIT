import json

from src.process.log_parser import TraceeLogParser


def test_tracee_json_line_preserves_full_fields() -> None:
    payload = {
        "timestamp": 1_779_999_999_123_456_789,
        "userId": 0,
        "processName": "Thread-2 (process_request_thread)",
        "processId": 8,
        "threadId": 9,
        "hostProcessId": 167116,
        "hostThreadId": 167529,
        "returnValue": 165,
        "eventName": "sendto",
        "containerId": "0a68610a418d",
        "containerImage": "deploy-vuln-app:latest",
        "args": [
            {"name": "sockfd", "value": 4},
            {"name": "dest_addr", "value": {"sa_family": "AF_UNSPEC"}},
        ],
    }

    parsed = TraceeLogParser().parse_line(json.dumps(payload))

    assert parsed is not None
    assert parsed["timestamp"] == 1_779_999_999.1234567
    assert parsed["comm"] == "Thread-2 (process_request_thread)"
    assert parsed["container_image"] == "deploy-vuln-app:latest"
    assert parsed["pid"] == 167116
    assert parsed["tid"] == 167529
    assert parsed["args"]["sockfd"] == 4


def test_tracee_table_line_is_rejected(tmp_path) -> None:
    line = (
        "09:53:40:808997  0a68610a418d  deploy-vuln-app: 0      "
        "Thread-2 (proce  1      /167116  8      /167529  165              "
        "sendto                    sockfd: 4, buf: 0x758e641aa8f0, len: 165"
    )
    trace_path = tmp_path / "trace.log"
    trace_path.write_text("TIME             CONTAINER_ID  IMAGE            UID    COMM\n" + line + "\n", encoding="utf-8")

    logs, stats = TraceeLogParser().parse_log_file_with_stats(str(trace_path))

    assert logs == []
    assert stats["trace_lines_total"] == 2
    assert stats["trace_lines_non_json"] == 2
    assert stats["trace_lines_failed"] == 2
