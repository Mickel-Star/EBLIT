#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

CONFIG_PATH="configs/benign_corpus_v3_smoke_tracee.yaml"
OUTPUT_DIR_ARG=""
DURATION_SECONDS_ARG=""
COMPOSE_FILE_ARG=""
SKIP_COMPOSE_UP_CLI=0
SKIP_TRACEE_CLI=0
TRACEE_IMAGE_ARG=""
TRACEE_OUTPUT_FORMAT_ARG=""
CONTAINER_FILTER_ARG=""

usage() {
  cat <<'EOF'
Usage: scripts/run_benign_corpus_v3_tracee.sh [options]

Options:
  --config <path>                 Config path. Default: configs/benign_corpus_v3_smoke_tracee.yaml
  --output-dir <path>             Output dir. Default from config, or data/benign_corpus_v3/smoke/run_smoke_tracee
  --duration-seconds <int>        Override config duration_seconds. Default: 300
  --compose-file <path>           Docker Compose file. Default from config, or deploy/docker-compose.yml
  --skip-compose-up               Use an already-running app and skip docker compose up.
  --skip-tracee                   Run only the workload driver and collection summary.
  --tracee-image <image>          Tracee image. Default: aquasec/tracee:0.24.1
  --tracee-output-format <format> Tracee output format. Allowed: json/jsonl. Default: json
  --container-filter <filter>     Extra Tracee --scope expression.
  -h, --help                      Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)
      CONFIG_PATH="${2:?missing value for --config}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR_ARG="${2:?missing value for --output-dir}"
      shift 2
      ;;
    --duration-seconds)
      DURATION_SECONDS_ARG="${2:?missing value for --duration-seconds}"
      shift 2
      ;;
    --compose-file)
      COMPOSE_FILE_ARG="${2:?missing value for --compose-file}"
      shift 2
      ;;
    --skip-compose-up)
      SKIP_COMPOSE_UP_CLI=1
      shift
      ;;
    --skip-tracee)
      SKIP_TRACEE_CLI=1
      shift
      ;;
    --tracee-image)
      TRACEE_IMAGE_ARG="${2:?missing value for --tracee-image}"
      shift 2
      ;;
    --tracee-output-format)
      TRACEE_OUTPUT_FORMAT_ARG="${2:?missing value for --tracee-output-format}"
      shift 2
      ;;
    --container-filter)
      CONTAINER_FILTER_ARG="${2:?missing value for --container-filter}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

config_get() {
  local key="$1"
  local default_value="$2"
  "${PYTHON_BIN}" - "${CONFIG_PATH}" "${key}" "${default_value}" <<'PY'
from pathlib import Path
import sys
from src.process.benign_workload_driver import load_config

cfg = load_config(Path(sys.argv[1]))
value = cfg
for part in sys.argv[2].split("."):
    if isinstance(value, dict) and part in value:
        value = value[part]
    else:
        value = None
        break
if value is None:
    print(sys.argv[3])
elif isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

is_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

utc_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

sanitize_name() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

CONFIG_PATH="$(realpath -m "${CONFIG_PATH}")"
RUN_ID="$(config_get run_id run_smoke_tracee)"
SPLIT="$(config_get split smoke)"
DATASET="$(config_get dataset benign_corpus_v3)"
DURATION_SECONDS="${DURATION_SECONDS_ARG:-$(config_get duration_seconds 300)}"
OUTPUT_DIR="${OUTPUT_DIR_ARG:-$(config_get output_dir data/benign_corpus_v3/smoke/run_smoke_tracee)}"
COMPOSE_FILE="${COMPOSE_FILE_ARG:-$(config_get collection.compose_file deploy/docker-compose.yml)}"
TRACEE_IMAGE="${TRACEE_IMAGE_ARG:-$(config_get collection.tracee_image aquasec/tracee:0.24.1)}"
TRACEE_CONFIGURED_OUTPUT_FORMAT="${TRACEE_OUTPUT_FORMAT_ARG:-$(config_get collection.tracee_output_format json)}"
TRACEE_CONFIGURED_OUTPUT_FORMAT="$(printf '%s' "${TRACEE_CONFIGURED_OUTPUT_FORMAT}" | tr '[:upper:]' '[:lower:]')"
case "${TRACEE_CONFIGURED_OUTPUT_FORMAT}" in
  json)
    TRACEE_OUTPUT_FORMAT="json"
    ;;
  jsonl)
    TRACEE_OUTPUT_FORMAT="json"
    ;;
  *)
    echo "ERROR: Tracee output format must be json/jsonl for training data, got: ${TRACEE_CONFIGURED_OUTPUT_FORMAT}" >&2
    exit 2
    ;;
esac
TRACE_LOG_NAME="$(config_get collection.trace_log_name trace.log)"
TRACEE_RUNTIME_LOG_NAME="$(config_get collection.tracee_runtime_log_name tracee_runtime.log)"
READINESS_TIMEOUT_SECONDS="$(config_get collection.readiness_timeout_seconds 60)"
TRACEE_STARTUP_TIMEOUT_SECONDS="$(config_get collection.tracee_startup_timeout_seconds 120)"
TRACEE_SETTLE_SECONDS="$(config_get collection.tracee_settle_seconds 3)"
TRACEE_FLUSH_SECONDS="$(config_get collection.tracee_flush_seconds 3)"
TRACEE_EVENTS="$(config_get collection.tracee_events sched_process_exec,execve,openat,read,write,close,socket,bind,listen,accept,accept4,connect,getpeername,getsockname,sendto,recvfrom,fork,clone,vfork,mmap,security_socket_connect,security_socket_accept)"
BASE_URL_FROM_CONFIG="$(config_get base_url http://127.0.0.1:5000)"

SKIP_COMPOSE_UP=0
if is_true "$(config_get collection.skip_compose_up false)"; then
  SKIP_COMPOSE_UP=1
fi
if [ "${SKIP_COMPOSE_UP_CLI}" -eq 1 ]; then
  SKIP_COMPOSE_UP=1
fi

SKIP_TRACEE=0
if ! is_true "$(config_get collection.tracee_enabled true)"; then
  SKIP_TRACEE=1
fi
if [ "${SKIP_TRACEE_CLI}" -eq 1 ]; then
  SKIP_TRACEE=1
fi

if [ -n "${CONTAINER_FILTER_ARG}" ]; then
  CONTAINER_FILTER="${CONTAINER_FILTER_ARG}"
else
  CONTAINER_FILTER="$(config_get collection.container_filter "")"
fi

OUTPUT_DIR="$(realpath -m "${OUTPUT_DIR}")"
COMPOSE_FILE="$(realpath -m "${COMPOSE_FILE}")"
EFFECTIVE_CONFIG="${OUTPUT_DIR}/effective_config.yaml"
TRACE_LOG="${OUTPUT_DIR}/${TRACE_LOG_NAME}"
TRACEE_RUNTIME_LOG="${OUTPUT_DIR}/${TRACEE_RUNTIME_LOG_NAME}"
COLLECTION_SUMMARY="${OUTPUT_DIR}/collection_summary.json"
ERRORS_FILE="${OUTPUT_DIR}/.collection_errors.tmp"
WARNINGS_FILE="${OUTPUT_DIR}/.collection_warnings.tmp"
TRACEE_CONTAINER_NAME="tracee_benign_v3_$(sanitize_name "${RUN_ID}")"

mkdir -p "${OUTPUT_DIR}"
rm -f "${TRACE_LOG}" "${TRACEE_RUNTIME_LOG}" "${COLLECTION_SUMMARY}" "${ERRORS_FILE}" "${WARNINGS_FILE}"
: > "${ERRORS_FILE}"
: > "${WARNINGS_FILE}"
: > "${TRACEE_RUNTIME_LOG}"

START_TS="$(utc_now)"
START_EPOCH="$(date +%s)"
END_TS=""
DRIVER_EXIT_CODE=-1
FINAL_EXIT_CODE=0
TRACE_STARTUP_SUCCESS=false
TRACE_STOP_SUCCESS=false
TRACEE_ENABLED=false
TRACE_PID=""
TRACE_CMD_STRING=""
DRIVER_CMD_STRING=""
COMPOSE_STARTED_BY_SCRIPT=false
COMPOSE_OWNED_BY_SCRIPT=false
TRACE_FILTER_ENABLED=false
BASE_URL_EFFECTIVE="${BASE_URL_FROM_CONFIG}"
COMPOSE_CMD_STRING=""
COMPOSE_CMD=()

add_error() {
  printf '%s\n' "$*" >> "${ERRORS_FILE}"
  echo "ERROR: $*" >&2
}

add_warning() {
  printf '%s\n' "$*" >> "${WARNINGS_FILE}"
  echo "WARN: $*" >&2
}

write_effective_config() {
  local base_url_override="$1"
  "${PYTHON_BIN}" - "${CONFIG_PATH}" "${EFFECTIVE_CONFIG}" "${OUTPUT_DIR}" "${DURATION_SECONDS}" "${base_url_override}" <<'PY'
import json
import sys
from pathlib import Path
from src.process.benign_workload_driver import load_config

source = Path(sys.argv[1])
target = Path(sys.argv[2])
cfg = load_config(source)
cfg["output_dir"] = sys.argv[3]
cfg["duration_seconds"] = int(float(sys.argv[4]))
if sys.argv[5]:
    cfg["base_url"] = sys.argv[5]
target.write_text(json.dumps(cfg, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
PY
}

write_summary() {
  END_TS="${END_TS:-$(utc_now)}"
  local end_epoch
  end_epoch="$(date +%s)"
  local actual_seconds=$(( end_epoch - START_EPOCH ))
  export SUMMARY_DATASET="${DATASET}"
  export SUMMARY_RUN_ID="${RUN_ID}"
  export SUMMARY_SPLIT="${SPLIT}"
  export SUMMARY_OUTPUT_DIR="${OUTPUT_DIR}"
  export SUMMARY_CONFIG_PATH="${CONFIG_PATH}"
  export SUMMARY_EFFECTIVE_CONFIG_PATH="${EFFECTIVE_CONFIG}"
  export SUMMARY_START_TS="${START_TS}"
  export SUMMARY_END_TS="${END_TS}"
  export SUMMARY_DURATION_REQUESTED="${DURATION_SECONDS}"
  export SUMMARY_DURATION_ACTUAL="${actual_seconds}"
  export SUMMARY_COMPOSE_FILE="${COMPOSE_FILE}"
  export SUMMARY_COMPOSE_STARTED="${COMPOSE_STARTED_BY_SCRIPT}"
  export SUMMARY_SKIP_COMPOSE_UP="${SKIP_COMPOSE_UP}"
  export SUMMARY_SKIP_TRACEE="${SKIP_TRACEE}"
  export SUMMARY_TRACEE_ENABLED="${TRACEE_ENABLED}"
  export SUMMARY_TRACEE_IMAGE="${TRACEE_IMAGE}"
  export SUMMARY_TRACEE_CONTAINER_NAME="${TRACEE_CONTAINER_NAME}"
  export SUMMARY_TRACEE_COMMAND="${TRACE_CMD_STRING}"
  export SUMMARY_TRACEE_TRACE_LOG_NAME="${TRACE_LOG_NAME}"
  export SUMMARY_TRACEE_RUNTIME_LOG_NAME="${TRACEE_RUNTIME_LOG_NAME}"
  export SUMMARY_TRACEE_STARTUP_SUCCESS="${TRACE_STARTUP_SUCCESS}"
  export SUMMARY_TRACEE_STOP_SUCCESS="${TRACE_STOP_SUCCESS}"
  export SUMMARY_TRACEE_CONFIGURED_OUTPUT_FORMAT="${TRACEE_CONFIGURED_OUTPUT_FORMAT}"
  export SUMMARY_TRACEE_CLI_OUTPUT_FORMAT="${TRACEE_OUTPUT_FORMAT}"
  export SUMMARY_TRACEE_CONTAINER_FILTER="${CONTAINER_FILTER}"
  export SUMMARY_TRACEE_CONTAINER_FILTER_ENABLED="${TRACE_FILTER_ENABLED}"
  export SUMMARY_DRIVER_COMMAND="${DRIVER_CMD_STRING}"
  export SUMMARY_DRIVER_EXIT_CODE="${DRIVER_EXIT_CODE}"
  export SUMMARY_ERRORS_FILE="${ERRORS_FILE}"
  export SUMMARY_WARNINGS_FILE="${WARNINGS_FILE}"
  export SUMMARY_TRACE_LOG="${TRACE_LOG}"
  export SUMMARY_TRACEE_RUNTIME_LOG="${TRACEE_RUNTIME_LOG}"
  export SUMMARY_RUN_META="${OUTPUT_DIR}/run_meta.json"
  export SUMMARY_DRIVER_LOG="${OUTPUT_DIR}/driver.log"
  export SUMMARY_REQUEST_EVENTS="${OUTPUT_DIR}/request_events.jsonl"
  export SUMMARY_WORKLOAD_SUMMARY="${OUTPUT_DIR}/workload_summary.json"
  export SUMMARY_COLLECTION_SUMMARY="${COLLECTION_SUMMARY}"
  "${PYTHON_BIN}" - <<'PY'
import json
import os
from pathlib import Path
from src.process.log_parser import detect_trace_log_format

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)

def env_bool(name: str) -> bool:
    return env(name).lower() in {"1", "true", "yes", "y", "on"}

def env_int(name: str, default: int = 0) -> int:
    try:
        return int(float(env(name, str(default))))
    except Exception:
        return int(default)

def lines(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]

trace_log = Path(env("SUMMARY_TRACE_LOG"))
tracee_runtime_log = Path(env("SUMMARY_TRACEE_RUNTIME_LOG"))
run_meta = Path(env("SUMMARY_RUN_META"))
driver_log = Path(env("SUMMARY_DRIVER_LOG"))
request_events = Path(env("SUMMARY_REQUEST_EVENTS"))
workload_summary = Path(env("SUMMARY_WORKLOAD_SUMMARY"))
collection_summary = Path(env("SUMMARY_COLLECTION_SUMMARY"))
trace_format_detection = detect_trace_log_format(trace_log)
configured_output_format = env("SUMMARY_TRACEE_CONFIGURED_OUTPUT_FORMAT", "json").strip().lower()
cli_output_format = env("SUMMARY_TRACEE_CLI_OUTPUT_FORMAT", "json").strip().lower()
warnings = lines(env("SUMMARY_WARNINGS_FILE"))
errors = lines(env("SUMMARY_ERRORS_FILE"))
actual_trace_format = str(trace_format_detection.get("actual_trace_format") or "missing")
compatible_actual_formats = {
    "json": {"jsonl"},
    "jsonl": {"jsonl"},
}.get(configured_output_format, set())
if env_bool("SUMMARY_TRACEE_ENABLED") and actual_trace_format not in compatible_actual_formats:
    errors.append(f"trace_format_mismatch:configured={configured_output_format}:actual={actual_trace_format}")
elif env_bool("SUMMARY_TRACEE_ENABLED") and configured_output_format != actual_trace_format:
    warnings.append(f"trace_format_alias:configured={configured_output_format}:actual={actual_trace_format}")

payload = {
    "dataset": env("SUMMARY_DATASET", "benign_corpus_v3"),
    "run_id": env("SUMMARY_RUN_ID", "run_smoke_tracee"),
    "split": env("SUMMARY_SPLIT", "smoke"),
    "output_dir": env("SUMMARY_OUTPUT_DIR"),
    "config_path": env("SUMMARY_CONFIG_PATH"),
    "effective_config_path": env("SUMMARY_EFFECTIVE_CONFIG_PATH"),
    "start_ts": env("SUMMARY_START_TS"),
    "end_ts": env("SUMMARY_END_TS"),
    "duration_seconds_requested": env_int("SUMMARY_DURATION_REQUESTED", 300),
    "duration_seconds_actual": env_int("SUMMARY_DURATION_ACTUAL", 0),
    "compose_file": env("SUMMARY_COMPOSE_FILE"),
    "compose_started_by_script": env_bool("SUMMARY_COMPOSE_STARTED"),
    "skip_compose_up": env_bool("SUMMARY_SKIP_COMPOSE_UP"),
    "skip_tracee": env_bool("SUMMARY_SKIP_TRACEE"),
    "tracee": {
        "enabled": env_bool("SUMMARY_TRACEE_ENABLED"),
        "image": env("SUMMARY_TRACEE_IMAGE", "aquasec/tracee:0.24.1"),
        "container_name": env("SUMMARY_TRACEE_CONTAINER_NAME"),
        "command": env("SUMMARY_TRACEE_COMMAND"),
        "trace_log": env("SUMMARY_TRACEE_TRACE_LOG_NAME", "trace.log"),
        "tracee_runtime_log": env("SUMMARY_TRACEE_RUNTIME_LOG_NAME", "tracee_runtime.log"),
        "trace_log_exists": trace_log.exists(),
        "trace_log_size_bytes": trace_log.stat().st_size if trace_log.exists() else 0,
        "startup_success": env_bool("SUMMARY_TRACEE_STARTUP_SUCCESS"),
        "stop_success": env_bool("SUMMARY_TRACEE_STOP_SUCCESS"),
        "configured_output_format": configured_output_format,
        "cli_output_format": cli_output_format,
        "output_format": cli_output_format,
        "actual_trace_format": actual_trace_format,
        "trace_format_detection": trace_format_detection,
        "container_filter_enabled": env_bool("SUMMARY_TRACEE_CONTAINER_FILTER_ENABLED"),
        "container_filter": env("SUMMARY_TRACEE_CONTAINER_FILTER"),
        "scope_expression": ["container", "comm!=tracee"] + ([env("SUMMARY_TRACEE_CONTAINER_FILTER")] if env("SUMMARY_TRACEE_CONTAINER_FILTER") else []),
    },
    "driver": {
        "command": env("SUMMARY_DRIVER_COMMAND"),
        "exit_code": env_int("SUMMARY_DRIVER_EXIT_CODE", -1),
        "run_meta_exists": run_meta.exists(),
        "request_events_exists": request_events.exists(),
        "workload_summary_exists": workload_summary.exists(),
    },
    "artifacts": {
        "trace_log": str(trace_log),
        "tracee_runtime_log": str(tracee_runtime_log),
        "run_meta": str(run_meta),
        "driver_log": str(driver_log),
        "request_events": str(request_events),
        "workload_summary": str(workload_summary),
        "collection_summary": str(collection_summary),
    },
    "errors": errors,
    "warnings": warnings,
}
collection_summary.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
PY
}

detect_compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
  else
    return 1
  fi
  COMPOSE_CMD_STRING="${COMPOSE_CMD[*]}"
}

is_loopback_base_url() {
  "${PYTHON_BIN}" - "$1" <<'PY'
import sys
from urllib.parse import urlparse
host = urlparse(sys.argv[1]).hostname or ""
raise SystemExit(0 if host in {"localhost", "0.0.0.0", "::1"} or host.startswith("127.") else 1)
PY
}

container_base_url() {
  local current_url="$1"
  local ip="$2"
  "${PYTHON_BIN}" - "${current_url}" "${ip}" <<'PY'
import sys
from urllib.parse import urlparse, urlunparse
u = urlparse(sys.argv[1])
scheme = u.scheme or "http"
port = u.port or (443 if scheme == "https" else 80)
print(urlunparse((scheme, f"{sys.argv[2]}:{port}", "", "", "", "")))
PY
}

wait_for_readiness() {
  "${PYTHON_BIN}" - "${EFFECTIVE_CONFIG}" "${READINESS_TIMEOUT_SECONDS}" <<'PY'
import sys
import time
from pathlib import Path
from src.process.benign_workload_driver import HttpClient, load_config, normalize_endpoints

cfg = load_config(Path(sys.argv[1]))
timeout = float(sys.argv[2])
base_url = str(cfg.get("base_url") or "").rstrip("/")
endpoints = normalize_endpoints(dict(cfg.get("endpoints") or {}))
health = endpoints.get("health")
if not base_url or health is None:
    time.sleep(min(timeout, 10.0))
    raise SystemExit(0)

client = HttpClient(base_url, float(cfg.get("request_timeout_seconds") or 5.0))
deadline = time.time() + timeout
last_error = ""
while time.time() < deadline:
    result = client.request(method=health.method, path=health.path)
    if result.success:
        raise SystemExit(0)
    last_error = result.error or f"status={result.status_code}"
    time.sleep(1.0)
print(f"health check failed for {base_url}{health.path}: {last_error}", file=sys.stderr)
raise SystemExit(1)
PY
}

ensure_tracee_image() {
  if docker image inspect "${TRACEE_IMAGE}" >/dev/null 2>&1; then
    echo "tracee image already available: ${TRACEE_IMAGE}" >> "${TRACEE_RUNTIME_LOG}"
    return 0
  fi
  echo "pulling tracee image before capture: ${TRACEE_IMAGE}" | tee -a "${TRACEE_RUNTIME_LOG}"
  docker pull "${TRACEE_IMAGE}" >> "${TRACEE_RUNTIME_LOG}" 2>&1
}

wait_for_tracee_startup() {
  local deadline
  deadline=$(( $(date +%s) + ${TRACEE_STARTUP_TIMEOUT_SECONDS%.*} ))
  while [ "$(date +%s)" -le "${deadline}" ]; do
    if docker ps --format '{{.Names}}' | grep -qx "${TRACEE_CONTAINER_NAME}"; then
      sleep "${TRACEE_SETTLE_SECONDS}"
      return 0
    fi
    if ! kill -0 "${TRACE_PID}" 2>/dev/null; then
      return 1
    fi
    sleep 1
  done
  return 1
}

stop_tracee() {
  if [ "${TRACEE_ENABLED}" != "true" ] || [ -z "${TRACE_PID}" ]; then
    return 0
  fi
  sleep "${TRACEE_FLUSH_SECONDS}" || true
  if [ "${DEBUG_KEEP_TRACEE:-0}" = "1" ]; then
    docker stop "${TRACEE_CONTAINER_NAME}" >> "${TRACEE_RUNTIME_LOG}" 2>&1 || true
  else
    docker rm -f "${TRACEE_CONTAINER_NAME}" >> "${TRACEE_RUNTIME_LOG}" 2>&1 || true
  fi
  wait "${TRACE_PID}" >/dev/null 2>&1 || true
  TRACE_PID=""
  TRACE_STOP_SUCCESS=true
}

cleanup_compose() {
  if [ "${COMPOSE_OWNED_BY_SCRIPT}" = "true" ] && [ "${#COMPOSE_CMD[@]}" -gt 0 ]; then
    "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" stop vuln-app >> "${TRACEE_RUNTIME_LOG}" 2>&1 || true
    "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" rm -f vuln-app >> "${TRACEE_RUNTIME_LOG}" 2>&1 || true
  fi
}

cleanup() {
  stop_tracee || true
  cleanup_compose || true
}

on_interrupt() {
  trap - INT TERM ERR
  add_error "interrupted by user signal"
  FINAL_EXIT_CODE=130
  END_TS="$(utc_now)"
  cleanup || true
  write_summary || true
  exit 130
}

on_error() {
  local exit_code=$?
  local line_no="$1"
  local command="$2"
  trap - ERR
  add_error "script failed at line ${line_no}: ${command}"
  FINAL_EXIT_CODE="${exit_code}"
  END_TS="$(utc_now)"
  cleanup || true
  write_summary || true
  exit "${exit_code}"
}

trap 'on_error ${LINENO} "${BASH_COMMAND}"' ERR
trap on_interrupt INT TERM
trap cleanup EXIT

write_effective_config "${BASE_URL_EFFECTIVE}"

if ! command -v docker >/dev/null 2>&1; then
  if [ "${SKIP_COMPOSE_UP}" -eq 0 ] || [ "${SKIP_TRACEE}" -eq 0 ]; then
    add_error "docker command is required unless both --skip-compose-up and --skip-tracee are set"
    FINAL_EXIT_CODE=1
    write_summary
    exit 1
  fi
fi

if [ "${SKIP_COMPOSE_UP}" -eq 0 ]; then
  if ! detect_compose_cmd; then
    add_error "neither 'docker compose' nor 'docker-compose' is available"
    FINAL_EXIT_CODE=1
    write_summary
    exit 1
  fi
fi

if [ "${SKIP_TRACEE}" -eq 0 ]; then
  TRACEE_ENABLED=true
  docker rm -f "${TRACEE_CONTAINER_NAME}" >> "${TRACEE_RUNTIME_LOG}" 2>&1 || true
  if ! ensure_tracee_image; then
    add_error "failed to prepare Tracee image: ${TRACEE_IMAGE}"
    FINAL_EXIT_CODE=1
    END_TS="$(utc_now)"
    write_summary
    exit 1
  fi
  TRACEE_CMD=(docker run --name "${TRACEE_CONTAINER_NAME}")
  if [ "${DEBUG_KEEP_TRACEE:-0}" != "1" ]; then
    TRACEE_CMD+=(--rm)
  fi
  TRACEE_CMD+=(
    -i
    --privileged
    --pid=host
    --cgroupns=host
    --network=host
    -v /lib/modules:/lib/modules:ro
    -v /usr/src:/usr/src:ro
    -v /etc/os-release:/etc/os-release-host:ro
    -v /var/run/docker.sock:/var/run/docker.sock
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro
    "${TRACEE_IMAGE}"
    --containers enrich=true
    --containers sockets.docker=/var/run/docker.sock
    --containers cgroupfs.path=/sys/fs/cgroup
    --containers cgroupfs.force=true
    --scope container
    --scope comm!=tracee
  )
  if [ -n "${CONTAINER_FILTER}" ]; then
    TRACE_FILTER_ENABLED=true
    TRACEE_CMD+=(--scope "${CONTAINER_FILTER}")
  fi
  TRACEE_CMD+=(
    --events "${TRACEE_EVENTS}"
    --output "${TRACEE_OUTPUT_FORMAT}"
    --output option:parse-arguments
  )
  printf -v TRACE_CMD_STRING '%q ' "${TRACEE_CMD[@]}"
  echo "tracee command: ${TRACE_CMD_STRING}" >> "${TRACEE_RUNTIME_LOG}"
  "${TRACEE_CMD[@]}" > "${TRACE_LOG}" 2>&1 &
  TRACE_PID=$!
  if ! wait_for_tracee_startup; then
    add_error "Tracee container did not stay running; see ${TRACE_LOG} and ${TRACEE_RUNTIME_LOG}"
    FINAL_EXIT_CODE=1
    END_TS="$(utc_now)"
    cleanup
    write_summary
    exit 1
  fi
  TRACE_STARTUP_SUCCESS=true
else
  TRACEE_ENABLED=false
  add_warning "skip-tracee enabled; trace.log will not be produced"
fi

if [ "${SKIP_COMPOSE_UP}" -eq 0 ]; then
  COMPOSE_OWNED_BY_SCRIPT=true
  COMPOSE_STARTED_BY_SCRIPT=true
  echo "compose up: ${COMPOSE_CMD_STRING} -f ${COMPOSE_FILE} up -d --build --force-recreate vuln-app" | tee -a "${TRACEE_RUNTIME_LOG}"
  "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" up -d --build --force-recreate vuln-app >> "${TRACEE_RUNTIME_LOG}" 2>&1
  if is_loopback_base_url "${BASE_URL_FROM_CONFIG}"; then
    target_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' drsec-target 2>>"${TRACEE_RUNTIME_LOG}" || true)"
    if [ -n "${target_ip}" ]; then
      BASE_URL_EFFECTIVE="$(container_base_url "${BASE_URL_FROM_CONFIG}" "${target_ip}")"
      add_warning "config base_url is loopback but compose service is not port-published; using target container IP ${BASE_URL_EFFECTIVE}"
      write_effective_config "${BASE_URL_EFFECTIVE}"
    else
      add_warning "could not resolve drsec-target container IP; keeping configured base_url ${BASE_URL_FROM_CONFIG}"
    fi
  fi
fi

if ! wait_for_readiness; then
  add_error "demo app readiness check failed within ${READINESS_TIMEOUT_SECONDS}s"
  FINAL_EXIT_CODE=1
  END_TS="$(utc_now)"
  write_summary
  exit 1
fi

DRIVER_CMD=(
  "${PYTHON_BIN}"
  -m src.process.benign_workload_driver
  --config "${EFFECTIVE_CONFIG}"
  --output-dir "${OUTPUT_DIR}"
  --duration-seconds "${DURATION_SECONDS}"
)
printf -v DRIVER_CMD_STRING '%q ' "${DRIVER_CMD[@]}"
echo "driver command: ${DRIVER_CMD_STRING}" >> "${TRACEE_RUNTIME_LOG}"
set +e
"${DRIVER_CMD[@]}"
DRIVER_EXIT_CODE=$?
set -e
if [ "${DRIVER_EXIT_CODE}" -ne 0 ]; then
  add_error "benign workload driver failed with exit code ${DRIVER_EXIT_CODE}"
  FINAL_EXIT_CODE="${DRIVER_EXIT_CODE}"
fi

stop_tracee

if [ "${TRACEE_ENABLED}" = "true" ]; then
  if [ ! -s "${TRACE_LOG}" ]; then
    add_error "Tracee was enabled but ${TRACE_LOG} is missing or empty"
    FINAL_EXIT_CODE=1
  fi
fi

END_TS="$(utc_now)"
write_summary

if [ "${FINAL_EXIT_CODE}" -eq 0 ]; then
  echo "benign corpus v3 collection complete: ${OUTPUT_DIR}"
else
  echo "benign corpus v3 collection finished with errors: ${OUTPUT_DIR}" >&2
fi

exit "${FINAL_EXIT_CODE}"
