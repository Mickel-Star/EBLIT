#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

if [ -z "${PROXY_PORT:-}" ] && [ -n "${DRSEC_PROXY_PORT:-}" ]; then
  export PROXY_PORT="${DRSEC_PROXY_PORT}"
fi

export DOCKER_CONFIG="${ROOT_DIR}/.docker"
mkdir -p "${DOCKER_CONFIG}"
mkdir -p "${ROOT_DIR}/logs" "${ROOT_DIR}/data/raw" "${ROOT_DIR}/data/processed/realtime_debug" "${ROOT_DIR}/data/processed/realtime_windows"

TRACE_OUT="${ROOT_DIR}/data/raw/realtime_tracee.log"
WINDOW_SECONDS="${DRSEC_WINDOW_SECONDS:-1800}"
STRIDE_SECONDS="${DRSEC_STRIDE_SECONDS:-600}"
POLL_INTERVAL="${DRSEC_POLL_INTERVAL:-0.1}"
THRESHOLD="${DRSEC_THRESHOLD:-0.5}"
DEMO_SECONDS="${DRSEC_DEMO_SECONDS:-120}"
MAX_WINDOWS="${DRSEC_MAX_WINDOWS:-1}"
export LLM_TIMEOUT_SECONDS="${LLM_TIMEOUT_SECONDS:-20}"
export LLM_MAX_RETRIES="${LLM_MAX_RETRIES:-0}"
WITH_LLM_FLAG="--with-llm"
if [ "${1:-}" = "--no-llm" ] || [ "${REALTIME_WITH_LLM:-1}" = "0" ]; then
  WITH_LLM_FLAG="--no-llm"
fi

cleanup() {
  docker rm -f drsec-tracee-realtime >/dev/null 2>&1 || true
  docker compose -f deploy/docker-compose.yml --profile benign --profile attack down >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f drsec-tracee-realtime >/dev/null 2>&1 || true
docker compose -f deploy/docker-compose.yml --profile benign --profile attack down >/dev/null 2>&1 || true

if [ ! -f "${ROOT_DIR}/data/kb/ark_logic_graph.json" ]; then
  "${ROOT_DIR}/.venv/bin/python" -m src.process.main build_ark >/dev/null 2>&1 || true
fi

rm -f "${ROOT_DIR}/data/processed/realtime_windows"/window_*.json 2>/dev/null || true
rm -f "${ROOT_DIR}/data/processed/realtime_debug"/*_debug.json 2>/dev/null || true
rm -f "${ROOT_DIR}/data/processed/realtime_debug"/*_prompt*.txt 2>/dev/null || true
rm -f "${ROOT_DIR}/data/processed/realtime_debug"/*_attack_graph.txt 2>/dev/null || true
rm -f "${ROOT_DIR}/data/processed/realtime_debug"/*_report.md 2>/dev/null || true

docker compose -f deploy/docker-compose.yml up -d

rm -f "${TRACE_OUT}"
docker run \
  --name drsec-tracee-realtime \
  --rm \
  -i \
  --privileged \
  --pid=host \
  --cgroupns=host \
  --network=host \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  aquasec/tracee:0.24.1 \
  --containers enrich=true \
  --containers sockets.docker=/var/run/docker.sock \
  --containers cgroupfs.path=/sys/fs/cgroup \
  --containers cgroupfs.force=true \
  --scope container \
  --scope comm!=tracee \
  --events sched_process_exec,execve,openat,read,write,close,connect,accept,sendto,recvfrom,fork,clone,vfork,mmap,security_socket_connect,security_socket_accept \
  --output json \
  --output option:parse-arguments \
  > "${TRACE_OUT}" 2>&1 &

(
  sleep 3
  docker compose -f deploy/docker-compose.yml --profile benign up -d
  sleep 2
  docker compose -f deploy/docker-compose.yml --profile attack up -d
  sleep "${DEMO_SECONDS}"
  docker compose -f deploy/docker-compose.yml --profile benign --profile attack down
) >/dev/null 2>&1 &

RUN_META="${ROOT_DIR}/data/processed/realtime_debug/run_meta.json"
ATTACKER_ID=""
BENIGN_ID=""
TARGET_ID=""
DSOCK_ID=""
C2_ID=""
for i in $(seq 1 30); do
  [ -z "${TARGET_ID}" ] && TARGET_ID="$(docker inspect -f '{{.Id}}' drsec-target 2>/dev/null | head -n 1 || true)"
  [ -z "${BENIGN_ID}" ] && BENIGN_ID="$(docker inspect -f '{{.Id}}' drsec-benign-client 2>/dev/null | head -n 1 || true)"
  [ -z "${DSOCK_ID}" ] && DSOCK_ID="$(docker inspect -f '{{.Id}}' drsec-target-dsock 2>/dev/null | head -n 1 || true)"
  [ -z "${C2_ID}" ] && C2_ID="$(docker inspect -f '{{.Id}}' drsec-c2 2>/dev/null | head -n 1 || true)"
  [ -z "${ATTACKER_ID}" ] && ATTACKER_ID="$(docker inspect -f '{{.Id}}' drsec-attacker 2>/dev/null | head -n 1 || true)"
  if [ -n "${ATTACKER_ID}" ] && [ -n "${BENIGN_ID}" ]; then
    break
  fi
  sleep 1
done
cat > "${RUN_META}" <<EOF
{"attacker_container_id":"${ATTACKER_ID}","benign_container_id":"${BENIGN_ID}","target_container_id":"${TARGET_ID}","target_dsock_container_id":"${DSOCK_ID}","c2_container_id":"${C2_ID}","trace_out":"${TRACE_OUT}","window_mode":"sliding","window_seconds":${WINDOW_SECONDS},"stride_seconds":${STRIDE_SECONDS},"threshold":${THRESHOLD},"max_windows":${MAX_WINDOWS}}
EOF

echo ""
echo "Tracee output: ${TRACE_OUT}"
echo "Realtime demo: window=${WINDOW_SECONDS}s poll=${POLL_INTERVAL}s threshold=${THRESHOLD} duration=${DEMO_SECONDS}s"
echo ""

"${ROOT_DIR}/.venv/bin/python" - <<'PY' || true
from src.analysis.llm_client import get_llm_client, MockLLMClient
c=get_llm_client()
print("LLM client:", type(c).__name__, "mock=", isinstance(c, MockLLMClient))
PY

timeout "$((DEMO_SECONDS + 240))"s "${ROOT_DIR}/.venv/bin/python" -m src.process.main realtime "${TRACE_OUT}" \
  --threshold "${THRESHOLD}" \
  --window-mode sliding \
  --window-seconds "${WINDOW_SECONDS}" \
  --stride-seconds "${STRIDE_SECONDS}" \
  --poll-interval "${POLL_INTERVAL}" \
  --start-from-begin \
  --persist-windows-dir "${ROOT_DIR}/data/processed/realtime_windows" \
  --debug-dump-dir "${ROOT_DIR}/data/processed/realtime_debug" \
  --max-alerts-per-window 1 \
  --max-windows "${MAX_WINDOWS}" \
  ${WITH_LLM_FLAG} || true
