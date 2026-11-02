"""
The shipped example configuration contains nothing the server would use as a
credential, and it matches the code's secure defaults.

Until Phase 2 ``.env.example`` and ``docker/README.md`` carried placeholder
JWT secrets and an admin-hash placeholder written like ready-to-use values.

Failures report key names and line numbers only, never a value.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from dotenv import dotenv_values

from ioc_enricher.web.settings import WebSettings

_ROOT = Path(__file__).resolve().parents[2]
_ENV_EXAMPLE = _ROOT / ".env.example"
_DOCS = [_ENV_EXAMPLE, _ROOT / "docker" / "README.md", _ROOT / "README.md"]

# Settings whose value is a credential or other secret material.
_SECRET_SUFFIXES = ("_SECRET_KEY", "_API_KEY", "_API_KEYS", "_PASSWORD_HASH")
_JWT_ASSIGNMENT = re.compile(
    r"^[ \t]*(?:export[ \t]+)?IOC_WEB_JWT_SECRET_KEY[ \t]*=[ \t]*(\S*)", re.MULTILINE
)


def test_env_example_leaves_every_secret_empty() -> None:
    values = dotenv_values(_ENV_EXAMPLE)
    secret_keys = [key for key in values if key.endswith(_SECRET_SUFFIXES)]
    assert "IOC_WEB_JWT_SECRET_KEY" in secret_keys
    filled = [key for key in secret_keys if values[key]]
    assert filled == []


def test_env_example_matches_secure_defaults() -> None:
    values = dotenv_values(_ENV_EXAMPLE)
    defaults = WebSettings()
    assert values.get("IOC_WEB_DEBUG") == "false"
    assert defaults.debug is False
    assert values.get("IOC_WEB_ENABLE_DOCS") == ""
    assert defaults.enable_docs is None
    assert values.get("IOC_WEB_DEV_ALLOW_UNAUTHENTICATED") == "false"
    assert defaults.dev_allow_unauthenticated is False


@pytest.mark.parametrize("path", _DOCS, ids=["env-example", "docker-readme", "readme"])
def test_jwt_secret_only_shown_as_a_generator(path: Path) -> None:
    # A value is allowed only as command substitution that generates it.
    text = path.read_text(encoding="utf-8")
    literal_lines = [
        text.count("\n", 0, match.start()) + 1
        for match in _JWT_ASSIGNMENT.finditer(text)
        if match.group(1) and not match.group(1).startswith("$(")
    ]
    assert literal_lines == []
