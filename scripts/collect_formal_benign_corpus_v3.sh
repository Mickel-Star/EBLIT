#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

CONFIG_PATH="configs/benign_corpus_v3_formal.yaml"
CORPUS_DIR="data/benign_corpus_v3"
CORPUS_DIR_SET=0
RUNS_ARG=""
SKIP_TRACEE=0
SKIP_COMPOSE_UP=0
DURATION_SCALE="1.0"
REHEARSAL=0
NO_MANIFEST=0
NO_WINDOW_ACTIVITY=0
CONTINUE_ON_ERROR=0
INTERRUPTED=0

usage() {
  cat <<'EOF'
Usage: scripts/collect_formal_benign_corpus_v3.sh [options]

Options:
  --config <path>             Formal config. Default: configs/benign_corpus_v3_formal.yaml
  --corpus-dir <path>         Corpus dir. Default: data/benign_corpus_v3
  --runs <list>               Comma-separated run IDs, e.g. run_a,run_b
  --skip-tracee               Do not start Tracee; build windows from request_events.jsonl.
  --skip-compose-up           Use an already-running app and skip docker compose up.
  --duration-scale <float>    Scale every run and phase duration.
  --rehearsal                 Use duration-scale 0.1 and data/benign_corpus_v3_rehearsal.
  --no-manifest               Collect runs only; skip corpus manifest/report manifest checks.
  --no-window-activity        Collect trace and driver outputs only.
  --continue-on-error         Continue later runs after a run failure; final exit is non-zero.
  -h, --help                  Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)
      CONFIG_PATH="${2:?missing value for --config}"
      shift 2
      ;;
    --corpus-dir)
      CORPUS_DIR="${2:?missing value for --corpus-dir}"
      CORPUS_DIR_SET=1
      shift 2
      ;;
    --runs)
      RUNS_ARG="${2:?missing value for --runs}"
      shift 2
      ;;
    --skip-tracee)
      SKIP_TRACEE=1
      shift
      ;;
    --skip-compose-up)
      SKIP_COMPOSE_UP=1
      shift
      ;;
    --duration-scale)
      DURATION_SCALE="${2:?missing value for --duration-scale}"
      shift 2
      ;;
    --rehearsal)
      REHEARSAL=1
      shift
      ;;
    --no-manifest)
      NO_MANIFEST=1
      shift
      ;;
    --no-window-activity)
      NO_WINDOW_ACTIVITY=1
      shift
      ;;
    --continue-on-error)
      CONTINUE_ON_ERROR=1
      shift
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

if [ "${REHEARSAL}" -eq 1 ]; then
  DURATION_SCALE="0.1"
  if [ "${CORPUS_DIR_SET}" -eq 0 ]; then
    CORPUS_DIR="data/benign_corpus_v3_rehearsal"
  fi
fi

PLAN_COMMON=(
  --config "${CONFIG_PATH}"
  --corpus-dir "${CORPUS_DIR}"
  --duration-scale "${DURATION_SCALE}"
)
[ -n "${RUNS_ARG}" ] && PLAN_COMMON+=(--runs "${RUNS_ARG}")
[ "${REHEARSAL}" -eq 1 ] && PLAN_COMMON+=(--rehearsal)
[ "${SKIP_TRACEE}" -eq 1 ] && PLAN_COMMON+=(--skip-tracee)
[ "${SKIP_COMPOSE_UP}" -eq 1 ] && PLAN_COMMON+=(--skip-compose-up)

REPORT_COMMON=(
  --config "${CONFIG_PATH}"
  --corpus-dir "${CORPUS_DIR}"
  --duration-scale "${DURATION_SCALE}"
)
[ -n "${RUNS_ARG}" ] && REPORT_COMMON+=(--runs "${RUNS_ARG}")
[ "${REHEARSAL}" -eq 1 ] && REPORT_COMMON+=(--rehearsal)
[ "${SKIP_TRACEE}" -eq 1 ] && REPORT_COMMON+=(--allow-missing-trace)
[ "${NO_WINDOW_ACTIVITY}" -eq 1 ] && REPORT_COMMON+=(--no-window-activity)
[ "${NO_MANIFEST}" -eq 1 ] && REPORT_COMMON+=(--no-manifest)

write_report() {
  "${PYTHON_BIN}" -m src.process.benign_manifest_builder report "${REPORT_COMMON[@]}" --print-summary || true
}

cleanup_tracee() {
  if command -v docker >/dev/null 2>&1; then
    docker rm -f tracee_benign_v3_run_a tracee_benign_v3_run_b tracee_benign_v3_run_c tracee_benign_v3_run_d >/dev/null 2>&1 || true
  fi
}

on_interrupt() {
  INTERRUPTED=1
  echo "ERROR: interrupted; writing partial formal report" >&2
  cleanup_tracee || true
  write_report || true
  exit 130
}

trap on_interrupt INT TERM
trap cleanup_tracee EXIT

mkdir -p "${CORPUS_DIR}"

mapfile -t PLAN_LINES < <("${PYTHON_BIN}" -m src.process.benign_manifest_builder emit-plan "${PLAN_COMMON[@]}")
if [ "${#PLAN_LINES[@]}" -eq 0 ]; then
  echo "ERROR: no runs selected" >&2
  exit 2
fi

FAILED=0

for line in "${PLAN_LINES[@]}"; do
  IFS=$'\t' read -r RUN_ID SPLIT RUN_DIR DURATION_SECONDS <<<"${line}"
  echo ""
  echo "==> collecting ${RUN_ID} (${SPLIT}) duration=${DURATION_SECONDS}s output=${RUN_DIR}"

  mkdir -p "${RUN_DIR}"

  RUN_CONFIG="${RUN_DIR}/effective_config.yaml"
  WRITE_ARGS=(
    --config "${CONFIG_PATH}"
    --corpus-dir "${CORPUS_DIR}"
    --duration-scale "${DURATION_SCALE}"
    --run-id "${RUN_ID}"
    --output "${RUN_CONFIG}"
  )
  [ "${REHEARSAL}" -eq 1 ] && WRITE_ARGS+=(--rehearsal)
  [ "${SKIP_TRACEE}" -eq 1 ] && WRITE_ARGS+=(--skip-tracee)
  [ "${SKIP_COMPOSE_UP}" -eq 1 ] && WRITE_ARGS+=(--skip-compose-up)
  "${PYTHON_BIN}" -m src.process.benign_manifest_builder write-run-config "${WRITE_ARGS[@]}"

  rm -f \
    "${RUN_DIR}/.collection_errors.tmp" \
    "${RUN_DIR}/.collection_warnings.tmp" \
    "${RUN_DIR}/collection_summary.json" \
    "${RUN_DIR}/driver.log" \
    "${RUN_DIR}/request_events.jsonl" \
    "${RUN_DIR}/run_meta.json" \
    "${RUN_DIR}/trace.log" \
    "${RUN_DIR}/tracee_runtime.log" \
    "${RUN_DIR}/window_activity.jsonl" \
    "${RUN_DIR}/window_activity_summary.json" \
    "${RUN_DIR}/workload_summary.json"
  echo "collecting fresh run data; existing raw artifacts in ${RUN_DIR} will be overwritten"
  COLLECT_ARGS=(
    --config "${RUN_CONFIG}"
    --output-dir "${RUN_DIR}"
    --duration-seconds "${DURATION_SECONDS}"
  )
  [ "${SKIP_TRACEE}" -eq 1 ] && COLLECT_ARGS+=(--skip-tracee)
  [ "${SKIP_COMPOSE_UP}" -eq 1 ] && COLLECT_ARGS+=(--skip-compose-up)

  set +e
  bash scripts/run_benign_corpus_v3_tracee.sh "${COLLECT_ARGS[@]}"
  COLLECT_EXIT=$?
  set -e
  if [ "${COLLECT_EXIT}" -ne 0 ]; then
    echo "ERROR: collection failed for ${RUN_ID} with exit code ${COLLECT_EXIT}" >&2
    FAILED=1
    if [ "${CONTINUE_ON_ERROR}" -ne 1 ]; then
      write_report
      exit "${COLLECT_EXIT}"
    fi
    continue
  fi

  if [ "${NO_WINDOW_ACTIVITY}" -ne 1 ]; then
    BUILDER_ARGS=(
      --run-dir "${RUN_DIR}"
      --window-seconds 30
      --time-bin-seconds 2
      --force
    )
    [ "${SKIP_TRACEE}" -eq 1 ] && BUILDER_ARGS+=(--allow-missing-trace)
    echo "building window activity: ${RUN_DIR}"
    set +e
    "${PYTHON_BIN}" -m src.process.window_activity_builder "${BUILDER_ARGS[@]}"
    WINDOW_EXIT=$?
    set -e
    if [ "${WINDOW_EXIT}" -ne 0 ]; then
      echo "ERROR: window_activity build failed for ${RUN_ID} with exit code ${WINDOW_EXIT}" >&2
      FAILED=1
      if [ "${CONTINUE_ON_ERROR}" -ne 1 ]; then
        write_report
        exit "${WINDOW_EXIT}"
      fi
      continue
    fi

    CHECK_WA_ARGS=(--run-dir "${RUN_DIR}")
    echo "checking window activity: ${RUN_DIR}"
    "${PYTHON_BIN}" scripts/check_benign_corpus_v3.py window-activity "${CHECK_WA_ARGS[@]}" || true
  fi
done

if [ "${NO_MANIFEST}" -ne 1 ]; then
  MANIFEST_ARGS=(
    --corpus-dir "${CORPUS_DIR}"
    --window-seconds 30
    --time-bin-seconds 2
    --seed 20260501
    --force
  )
  echo "building benign corpus manifest: ${CORPUS_DIR}"
  set +e
  "${PYTHON_BIN}" -m src.process.benign_manifest_builder "${MANIFEST_ARGS[@]}"
  MANIFEST_EXIT=$?
  set -e
  if [ "${MANIFEST_EXIT}" -ne 0 ]; then
    echo "ERROR: corpus manifest build failed with exit code ${MANIFEST_EXIT}" >&2
    FAILED=1
    if [ "${CONTINUE_ON_ERROR}" -ne 1 ]; then
      write_report
      exit "${MANIFEST_EXIT}"
    fi
  fi

  CHECK_MANIFEST_ARGS=(--corpus-dir "${CORPUS_DIR}")
  echo "checking benign corpus manifest: ${CORPUS_DIR}"
  "${PYTHON_BIN}" scripts/check_benign_corpus_v3.py manifest "${CHECK_MANIFEST_ARGS[@]}" || true
fi

write_report

if [ "${NO_MANIFEST}" -eq 0 ] && [ "${NO_WINDOW_ACTIVITY}" -eq 0 ]; then
  CHECK_ARGS=(--corpus-dir "${CORPUS_DIR}")
  [ "${SKIP_TRACEE}" -eq 1 ] && CHECK_ARGS+=(--allow-missing-trace)
  [ -n "${RUNS_ARG}" ] && CHECK_ARGS+=(--runs "${RUNS_ARG}")
  if [ "${REHEARSAL}" -eq 1 ]; then
    CHECK_ARGS+=(--min-nonempty-windows 1)
  fi
  set +e
  "${PYTHON_BIN}" scripts/check_benign_corpus_v3.py formal "${CHECK_ARGS[@]}"
  CHECK_EXIT=$?
  set -e
  if [ "${CHECK_EXIT}" -ne 0 ]; then
    FAILED=1
  fi
else
  echo "final formal check skipped because --no-manifest or --no-window-activity was set"
fi

if [ "${INTERRUPTED}" -ne 0 ]; then
  exit 130
fi
if [ "${FAILED}" -ne 0 ]; then
  exit 1
fi
exit 0
