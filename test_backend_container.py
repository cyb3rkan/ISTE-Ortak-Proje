"""
Backend container data survives a re-created container.

Web reports are kept for REPORT_RETENTION_DAYS and are fetched again by id,
and the README tells operators to re-create the backend after changing a
key. Without volumes every re-creation silently dropped the cache, the saved
reports and the log. The compose file mounts named volumes (Docker-managed,
no host paths) at the directories the image prepares for the app user, and
points the app at them.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker" / "docker-compose.yml"
DOCKERFILE = ROOT / "docker" / "Dockerfile.backend"

_MOUNTS = {"/app/data", "/app/reports", "/app/logs"}


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _backend_mounts() -> dict:
    mounts = {}
    for entry in _compose()["services"]["backend"].get("volumes", []):
        source, target = str(entry).split(":", 1)
        mounts[target] = source
    return mounts


def test_backend_runtime_directories_are_on_named_volumes() -> None:
    mounts = _backend_mounts()
    assert set(mounts) == _MOUNTS
    declared = set((_compose().get("volumes") or {}).keys())
    for source in mounts.values():
        assert not source.startswith((".", "/", "~")), "host bind mounts are not used"
        assert source in declared


def test_the_app_is_pointed_at_the_mounted_directories() -> None:
    env = _compose()["services"]["backend"]["environment"]
    assert env["IOC_ENRICHER_DATA_DIR"] == "/app/data"
    assert env["IOC_ENRICHER_REPORTS_DIR"] == "/app/reports"
    assert env["LOG_FILE"].startswith("/app/logs/")


def test_the_image_prepares_the_mount_points_for_the_app_user() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(r"mkdir -p /app/logs /app/reports /app/data/cache", dockerfile)
    assert re.search(r"chown -R app:app /app/logs /app/reports /app/data", dockerfile)
    assert re.search(r"^USER app$", dockerfile, flags=re.M)


def test_redis_still_keeps_nothing_on_disk() -> None:
    redis = _compose()["services"]["redis"]
    assert "volumes" not in redis
    assert redis["command"] == ["redis-server", "--save", "", "--appendonly", "no"]
