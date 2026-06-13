from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from src.common.defaults import DEFAULT_ALERT_THRESHOLD
from src.common.io import read_json


ALLOWED_ROLES: tuple[str, ...] = ("attacker", "benign", "target", "target_dsock", "c2")
POSITIVE_LABEL = "positive"
NEGATIVE_LABEL = "negative"
IGNORED_LABEL = "ignored"
DEFAULT_THRESHOLD = DEFAULT_ALERT_THRESHOLD
DEFAULT_SWEEP_THRESHOLDS: tuple[float, ...] = tuple(round(step * 0.05, 2) for step in range(1, 20))


def normalize_container_id(container_id: str) -> str:
    if not container_id:
        return ""
    return str(container_id).strip().lower()


def short_container_id(container_id: str) -> str:
    return normalize_container_id(container_id)[:12]


def sanitize_name(value: str) -> str:
    out = []
    for ch in str(value or ""):
        if ch.isalnum() or ch in ("-", "_"):
            out.append(ch)
        else:
            out.append("-")
    text = "".join(out).strip("-")
    return text or "unknown"


def normalize_command_variant(raw: Any, index: int, scenario_id: str) -> Dict[str, Any]:
    if isinstance(raw, dict):
        normalized = dict(raw)
        command = str(raw.get("command") or raw.get("attack_command") or "").strip()
        variant_id = str(raw.get("variant_id") or raw.get("id") or f"variant_{int(index):02d}").strip()
        command_template_id = str(raw.get("command_template_id") or f"{scenario_id}.{variant_id}").strip()
        parameters = raw.get("parameters") if isinstance(raw.get("parameters"), dict) else {}
        description = str(raw.get("description") or "").strip()
    else:
        normalized = {}
        command = str(raw or "").strip()
        variant_id = f"variant_{int(index):02d}"
        command_template_id = f"{scenario_id}.inline_{int(index):02d}"
        parameters = {}
        description = ""
    if not command:
        raise ValueError(f"{scenario_id}: command variant {index} is missing command")
    normalized.update(
        {
            "variant_id": variant_id,
            "command_template_id": command_template_id,
            "parameters": dict(parameters),
            "command": command,
            "description": description,
        }
    )
    return normalized


def role_label(role: str, positive_roles: Sequence[str], negative_roles: Sequence[str]) -> str:
    if role in set(positive_roles or []):
        return POSITIVE_LABEL
    if role in set(negative_roles or []):
        return NEGATIVE_LABEL
    return IGNORED_LABEL


def _validate_roles(roles: Iterable[str], field_name: str) -> List[str]:
    values: List[str] = []
    seen = set()
    for role in roles or []:
        role_name = str(role or "").strip()
        if not role_name:
            continue
        if role_name not in ALLOWED_ROLES:
            raise ValueError(f"{field_name} contains unsupported role: {role_name}")
        if role_name not in seen:
            seen.add(role_name)
            values.append(role_name)
    return values


def validate_scenario_manifest(payload: Dict[str, Any]) -> Dict[str, Any]:
    scenarios = payload.get("scenarios") or []
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("scenario manifest must contain a non-empty scenarios list")

    scenario_ids = set()
    validated: List[Dict[str, Any]] = []
    for raw in scenarios:
        if not isinstance(raw, dict):
            raise ValueError("scenario entry must be an object")

        scenario_id = str(raw.get("id") or "").strip()
        if not scenario_id:
            raise ValueError("scenario id is required")
        if scenario_id in scenario_ids:
            raise ValueError(f"duplicate scenario id: {scenario_id}")
        scenario_ids.add(scenario_id)

        kind = str(raw.get("kind") or "").strip().lower()
        if kind not in {"attack", "benign"}:
            raise ValueError(f"{scenario_id}: kind must be attack or benign")

        target_service = str(raw.get("target_service") or "").strip()
        command = str(raw.get("command") or "").strip()
        command_variants = [
            normalize_command_variant(item, idx, scenario_id)
            for idx, item in enumerate(list(raw.get("command_variants") or []), start=1)
        ]
        variant_metadata = list(raw.get("variant_metadata") or [])
        for idx, variant in enumerate(command_variants, start=1):
            meta = variant_metadata[idx - 1] if idx <= len(variant_metadata) and isinstance(variant_metadata[idx - 1], dict) else {}
            if not meta:
                continue
            if meta.get("variant_id") or meta.get("id"):
                variant["variant_id"] = str(meta.get("variant_id") or meta.get("id") or "").strip()
            if meta.get("command_template_id"):
                variant["command_template_id"] = str(meta.get("command_template_id") or "").strip()
            if isinstance(meta.get("parameters"), dict):
                variant["parameters"] = dict(meta.get("parameters") or {})
            if meta.get("description"):
                variant["description"] = str(meta.get("description") or "").strip()
        first_variant_command = str(command_variants[0]["command"]) if command_variants else ""
        attack_command = str(raw.get("attack_command") or command or first_variant_command).strip()
        duration_seconds = int(raw.get("duration_seconds") or 0)
        warmup_seconds = int(raw.get("warmup_seconds") or 0)
        attack_seconds = int(raw.get("attack_seconds") or 0)
        cooldown_seconds = int(raw.get("cooldown_seconds") or 0)
        if duration_seconds <= 0 and (warmup_seconds or attack_seconds or cooldown_seconds):
            duration_seconds = int(warmup_seconds + attack_seconds + cooldown_seconds)
        if not target_service:
            raise ValueError(f"{scenario_id}: target_service is required")
        if not attack_command:
            raise ValueError(f"{scenario_id}: command is required")
        if duration_seconds <= 0:
            raise ValueError(f"{scenario_id}: duration_seconds must be > 0")

        positive_roles = _validate_roles(raw.get("positive_roles") or [], f"{scenario_id}.positive_roles")
        negative_roles = _validate_roles(raw.get("negative_roles") or [], f"{scenario_id}.negative_roles")
        overlap = set(positive_roles) & set(negative_roles)
        if overlap:
            raise ValueError(f"{scenario_id}: roles cannot be both positive and negative: {sorted(overlap)}")

        driver_role = str(raw.get("driver_role") or ("attacker" if kind == "attack" else "benign")).strip()
        if driver_role not in ALLOWED_ROLES:
            raise ValueError(f"{scenario_id}: unsupported driver_role: {driver_role}")

        normalized = dict(raw)
        normalized.update(
            {
                "id": scenario_id,
                "kind": kind,
                "target_service": target_service,
                "command": command or attack_command,
                "attack_command": attack_command,
                "command_variants": command_variants,
                "warmup_command": str(raw.get("warmup_command") or "").strip(),
                "cooldown_command": str(raw.get("cooldown_command") or "").strip(),
                "duration_seconds": duration_seconds,
                "warmup_seconds": warmup_seconds,
                "attack_seconds": attack_seconds,
                "cooldown_seconds": cooldown_seconds,
                "driver_role": driver_role,
                "positive_roles": positive_roles,
                "negative_roles": negative_roles,
                "description": str(raw.get("description") or "").strip(),
                "family_id": str(raw.get("family_id") or scenario_id).strip(),
                "benchmark_split": str(raw.get("benchmark_split") or "").strip(),
            }
        )
        validated.append(normalized)

    manifest = dict(payload)
    manifest.update(
        {
            "scenario_set": str(payload.get("scenario_set") or "default"),
            "allowed_roles": list(ALLOWED_ROLES),
            "scenarios": validated,
        }
    )
    return manifest


def resolve_scenario_manifest(repo_root: str, scenario_set: str) -> Path:
    candidate = Path(scenario_set)
    if candidate.exists():
        return candidate.resolve()
    return Path(repo_root, "config", f"benchmark_scenarios.{scenario_set}.json").resolve()


def load_scenario_manifest(repo_root: str, scenario_set: str) -> Dict[str, Any]:
    manifest_path = resolve_scenario_manifest(repo_root, scenario_set)
    if not manifest_path.exists():
        raise FileNotFoundError(f"scenario manifest not found: {manifest_path}")
    payload = read_json(str(manifest_path))
    validated = validate_scenario_manifest(payload)
    validated["manifest_path"] = str(manifest_path)
    return validated


def validate_labels_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    containers = payload.get("containers") or []
    if not isinstance(containers, list):
        raise ValueError("labels payload containers must be a list")

    positive_roles = _validate_roles(payload.get("positive_roles") or [], "labels.positive_roles")
    negative_roles = _validate_roles(payload.get("negative_roles") or [], "labels.negative_roles")
    overlap = set(positive_roles) & set(negative_roles)
    if overlap:
        raise ValueError(f"labels payload role overlap: {sorted(overlap)}")

    validated_containers: List[Dict[str, Any]] = []
    seen = set()
    for raw in containers:
        if not isinstance(raw, dict):
            raise ValueError("label container entry must be an object")
        role = str(raw.get("role") or "").strip()
        if role not in ALLOWED_ROLES:
            raise ValueError(f"unsupported label role: {role}")
        container_id = normalize_container_id(raw.get("container_id") or "")
        container_name = str(raw.get("container_name") or "").strip()
        key = (role, short_container_id(container_id), container_name)
        if key in seen:
            continue
        seen.add(key)
        validated_containers.append(
            {
                "role": role,
                "container_id": container_id,
                "container_name": container_name,
                "label": str(raw.get("label") or role_label(role, positive_roles, negative_roles)),
            }
        )

    return {
        "schema_version": int(payload.get("schema_version") or 1),
        "scenario_id": str(payload.get("scenario_id") or "").strip(),
        "kind": str(payload.get("kind") or "").strip().lower(),
        "positive_roles": positive_roles,
        "negative_roles": negative_roles,
        "containers": validated_containers,
    }
