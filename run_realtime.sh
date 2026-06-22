#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 使用 Conda 环境的 Python
export PATH="/home/yzx/anaconda3/envs/drsec/bin:$PATH"
export DOCKER_CONFIG="${ROOT_DIR}/.docker"

if [ -z "${HTTPS_PROXY:-}" ] && [ -n "${PROXY_PORT:-}" ]; then
  export HTTP_PROXY="http://127.0.0.1:${PROXY_PORT}"
  export HTTPS_PROXY="http://127.0.0.1:${PROXY_PORT}"
  export ALL_PROXY="http://127.0.0.1:${PROXY_PORT}"
fi

mkdir -p "${DOCKER_CONFIG}"
mkdir -p "${ROOT_DIR}/data/raw" "${ROOT_DIR}/data/processed/realtime_debug" "${ROOT_DIR}/data/processed/realtime_windows"

TRACE_OUT="${ROOT_DIR}/data/raw/realtime_tracee.log"
WITH_LLM_FLAG="--no-llm"
if [ "${1:-}" = "--with-llm" ] || [ "${REALTIME_WITH_LLM:-0}" = "1" ]; then
  WITH_LLM_FLAG="--with-llm"
fi

cleanup() {
  docker rm -f drsec-manual >/dev/null 2>&1 || true
  docker rm -f drsec-tracee-realtime >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f drsec-manual >/dev/null 2>&1 || true
docker run -d --name drsec-manual --rm curlimages/curl:8.6.0 sh -lc "sleep infinity" >/dev/null

docker rm -f drsec-tracee-realtime >/dev/null 2>&1 || true

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

sleep 2

echo ""
echo "Realtime monitor started."
echo "- Tracee output: ${TRACE_OUT}"
echo "- Manual container: drsec-manual"
echo ""
echo "Open a new terminal and run:"
echo "  docker exec -it drsec-manual sh"
echo ""

"${ROOT_DIR}/.venv/bin/python" -m src.process.main realtime "${TRACE_OUT}" \
  --threshold 0.5 \
  --window-mode sliding \
  --window-seconds 1800 \
  --stride-seconds 600 \
  --two-stage \
  --poll-interval 0.2 \
  --persist-windows-dir "${ROOT_DIR}/data/processed/realtime_windows" \
  --debug-dump-dir "${ROOT_DIR}/data/processed/realtime_debug" \
  --max-alerts-per-window 1 \
  ${WITH_LLM_FLAG}
