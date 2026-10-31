"""
Frontend container policy (static checks of docker/nginx.conf,
docker/Dockerfile.frontend and docker/docker-compose.yml).

* The security headers declared once at server level reach every response,
  including /assets/: nginx drops inherited ``add_header`` values in any
  location that declares its own, unless ``add_header_inherit merge`` is in
  effect there.
* nginx runs as an unprivileged user: a port above 1024, pid and temp files
  under /tmp, and the image's EXPOSE, HEALTHCHECK and the compose port
  mapping all point at that same port.
* No ARG/ENV name trips BuildKit's SecretsUsedInArgOrEnv heuristic: public
  build settings carry a "public" token instead of the check being skipped.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
NGINX_CONF = ROOT / "docker" / "nginx.conf"
FRONTEND_DOCKERFILE = ROOT / "docker" / "Dockerfile.frontend"
COMPOSE = ROOT / "docker" / "docker-compose.yml"

_SECURITY_HEADERS = {
    "x-content-type-options", "x-frame-options", "referrer-policy",
    "permissions-policy", "content-security-policy",
}
# BuildKit dockerfile2llb/validations.go: getSecretsRegex().
_SECRET_TOKENS = re.compile(
    r"(?i)(?:_|^)(?:apikey|auth|credential|credentials|key|password|pword|passwd|psw|secret|token)(?:_|$)")
_ALLOW_TOKENS = re.compile(r"(?i)(?:_|^)(?:public|file|version)(?:_|$)")


# ---------------------------------------------------------------------------
# A small nginx config reader: blocks of directives, comments stripped.
# ---------------------------------------------------------------------------

def _tokens(text: str):
    for match in re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\n]*|[{};]|[^\s{};]+', text):
        token = match.group(0)
        if token.startswith("#"):
            continue
        if token[0] in "\"'":
            token = token[1:-1]
        yield token


def _parse(tokens) -> list:
    """[(name, args, children-or-None), ...] for one block level."""
    block, words = [], []
    for token in tokens:
        if token == ";":
            block.append((words[0], words[1:], None))
            words = []
        elif token == "{":
            block.append((words[0], words[1:], _parse(tokens)))
            words = []
        elif token == "}":
            return block
        else:
            words.append(token)
    return block


def _conf() -> list:
    return _parse(iter(_tokens(NGINX_CONF.read_text(encoding="utf-8"))))


def _directives(block, name):
    return [args for n, args, children in block if n == name and children is None]


def _server() -> list:
    [server] = [children for n, _, children in _conf() if n == "server"]
    return server


def _listen_port() -> int:
    [[listen, *_]] = _directives(_server(), "listen")
    return int(listen.rsplit(":", 1)[-1])


# ---------------------------------------------------------------------------
# nginx
# ---------------------------------------------------------------------------

def test_security_headers_are_declared_once_at_server_level_for_every_status():
    headers = {args[0].lower(): args for args in _directives(_server(), "add_header")}
    assert _SECURITY_HEADERS <= headers.keys()
    for name in _SECURITY_HEADERS:
        assert headers[name][-1] == "always", name
    csp = headers["content-security-policy"][1]
    for directive in ("script-src 'self'", "object-src 'none'", "frame-ancestors 'none'"):
        assert directive in csp


def test_locations_with_their_own_headers_still_inherit_the_security_headers():
    server = _server()
    server_mode = (_directives(server, "add_header_inherit") or [["on"]])[-1][0]
    locations = [(args, children) for n, args, children in server if n == "location"]
    assert any(args == ["/assets/"] for args, _ in locations)
    for args, children in locations:
        own = {a[0].lower() for a in _directives(children, "add_header")}
        if not own:
            continue                       # plain inheritance applies
        mode = (_directives(children, "add_header_inherit") or [[server_mode]])[-1][0]
        assert mode == "merge", f"location {args}: add_header drops the server headers"
        assert not own & _SECURITY_HEADERS, f"location {args} repeats a security header"


def test_nginx_listens_on_an_unprivileged_port_with_temp_files_under_tmp():
    assert _listen_port() >= 1024
    top = _conf()                          # http context of the included file
    for name in ("client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
                 "uwsgi_temp_path", "scgi_temp_path"):
        [[path, *_]] = _directives(top, name)
        assert path.startswith("/tmp/"), name


# ---------------------------------------------------------------------------
# Image and compose
# ---------------------------------------------------------------------------

def _runtime_stage() -> str:
    text = FRONTEND_DOCKERFILE.read_text(encoding="utf-8").replace("\\\n", " ")
    return re.split(r"(?im)^FROM\s", text)[-1]


def test_runtime_image_runs_nginx_as_an_unprivileged_numeric_user():
    stage = _runtime_stage()
    users = re.findall(r"(?m)^USER\s+(\S+)", stage)
    assert users, "runtime stage has no USER"
    uid = users[-1].split(":")[0]
    assert uid.isdigit() and int(uid) != 0, users[-1]
    # The stock main config writes its pid to a root-owned directory.
    assert re.search(r"pid\s+/tmp/\S+", stage), "pid file must move under /tmp"


def test_expose_healthcheck_and_compose_mapping_use_the_listen_port():
    port = _listen_port()
    stage = _runtime_stage()
    assert re.findall(r"(?m)^EXPOSE\s+(\d+)", stage) == [str(port)]
    [health] = re.findall(r"(?m)^HEALTHCHECK\s.*", stage)
    assert f"127.0.0.1:{port}/" in health
    frontend = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["frontend"]
    assert [str(p).rsplit(":", 1)[-1] for p in frontend["ports"]] == [str(port)]


def test_build_context_excludes_logs_and_env_files_at_any_depth():
    # .dockerignore patterns match from the context root: "*.log" alone misses
    # frontend/logs/*.log, which `COPY frontend/ ./` would put in a layer.
    patterns = set((ROOT / ".dockerignore").read_text(encoding="utf-8").split())
    assert {"**/*.log", "**/logs/", "**/.env", "**/.env.*"} <= patterns


def test_no_arg_or_env_name_looks_like_a_secret_to_buildkit():
    for dockerfile in sorted((ROOT / "docker").glob("Dockerfile*")):
        text = dockerfile.read_text(encoding="utf-8").replace("\\\n", " ")
        for line in text.splitlines():
            match = re.match(r"\s*(ARG|ENV)\s+(.*)", line)
            if not match:
                continue
            for key in re.findall(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)(?==|\s|$)", match.group(2)):
                flagged = _SECRET_TOKENS.search(key) and not _ALLOW_TOKENS.search(key)
                assert not flagged, f"{dockerfile.name}: {match.group(1)} {key}"
