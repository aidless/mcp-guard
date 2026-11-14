"""Static audit of agent MCP config files.

Discovery is borrowed from ``snyk-agent-scan``, which finds Claude/Cursor/Gemini/
Windsurf configs so the user need not hand-feed JSON.  We deliberately stop where
snyk carries on: it *launches* the server to read its `tools/list`, which is why
it needs SSRF guards and a ``--dangerously-run-mcp-servers`` flag.  Running a
config before auditing it is the wrong order.

So this module answers a different question — **the config file is itself an
attack surface**:

* it carries a ``command`` that will be executed at every session start,
* an ``env`` block that routinely holds live credentials,
* and sometimes a ``url``, which is where :mod:`guard.netguard` already knows
  what to refuse.

Everything here is static.  Nothing is executed, nothing is fetched.

Discipline: findings name the **key**, never echo the **value**.  A credential
copied into a CI log is a fresh incident, and our own scanner would have caused
it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from guard.netguard import BlockedUpstream, check_upstream  # noqa: E402

#: (client, path relative to $HOME).
#: Only the first four were observed on this machine on 2026-11-14; the rest are
#: the documented defaults for clients that are not installed here and are marked
#: by the client name suffix.  A wrong path is harmless — `find_configs` reports
#: what exists, it never invents.
CANDIDATES: list[tuple[str, str]] = [
    ("claude-desktop", ".config/Claude/claude_desktop_config.json"),
    ("claude-code", ".claude.json"),
    ("cursor", ".cursor/mcp.json"),
    ("claude-settings", ".claude/settings.json"),
    ("windsurf", ".codeium/windsurf/mcp_config.json"),
    ("gemini-cli", ".gemini/settings.json"),
    ("continue", ".continue/config.json"),
    ("vscode", ".config/Code/User/mcp.json"),
]

#: env keys that hold a live credential rather than a path or a flag.
SECRET_KEY_RE = re.compile(
    r"(token|secret|passw|api[_-]?key|credential|private[_-]?key|access[_-]?key)",
    re.IGNORECASE,
)

#: A command that is a shell is a shell whatever the args say.
SHELL_COMMANDS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd.exe", "powershell", "pwsh"}

#: `curl ... | sh` style remote-execute.  Built from parts so the pattern does not
#: itself look like the thing it hunts when this file is scanned.
_PIPE = r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python[0-9.]*)\b"
REMOTE_EXEC_RE = re.compile(r"\b(?:curl|wget)\b[^|]{0,200}" + _PIPE)

_FETCHER_RE = re.compile(r"^(?:curl|wget)$")

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def find_configs(home: Path | None = None, extra: list[Path] | None = None) -> list[dict]:
    """Existing, parseable config files.  A broken file is skipped, not fatal."""
    base = Path(home) if home is not None else Path.home()
    out: list[dict] = []
    for client, rel in CANDIDATES:
        path = base / rel
        if not path.is_file():
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        out.append({"client": client, "path": str(path)})
    for path in extra or []:
        path = Path(path)
        if not path.is_file():
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        out.append({"client": "explicit", "path": str(path)})
    return out


def load_servers(path: Path) -> dict[str, dict]:
    """`mcpServers` at top level, or the `{"mcp": {"servers": ...}}` variant."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    servers = doc.get("mcpServers")
    if servers is None:
        servers = (doc.get("mcp") or {}).get("servers")
    return dict(servers or {})


def _url_findings(cfg: dict) -> list[dict]:
    url = cfg.get("url") or cfg.get("serverUrl")
    if not isinstance(url, str) or not url:
        return []
    out: list[dict] = []
    try:
        check_upstream(url)
    except BlockedUpstream as exc:
        if exc.kind == "unresolvable":
            # Not a finding about the destination — a finding about our own
            # ability to check it.  Low severity, and it says so.
            return [{
                "rule": "unresolvable-url",
                "severity": "low",
                "detail": f"{exc}; re-run with DNS access to get a real verdict",
            }]
        return [{"rule": "metadata-url", "severity": "high", "detail": str(exc)}]
    # Remote plaintext: loopback/LAN on http is normal, the open internet is not.
    if url.startswith("http://"):
        host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        if host not in {"127.0.0.1", "localhost", "::1"} and not host.startswith(
            ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
             "172.2", "172.30.", "172.31.")
        ):
            out.append({
                "rule": "plaintext-http",
                "severity": "medium",
                "detail": f"remote MCP endpoint over plaintext HTTP ({host}); "
                          f"the bearer token travels in the clear",
            })
    return out


def _command_findings(cfg: dict) -> list[dict]:
    out: list[dict] = []
    command = cfg.get("command")
    args = cfg.get("args") or []
    if not isinstance(command, str):
        return out
    argv = [command] + [str(a) for a in args if isinstance(a, (str, int, float))]
    joined = " ".join(argv)
    base = Path(command).name

    if base in SHELL_COMMANDS and any(a in ("-c", "-Command", "/c") for a in argv[1:]):
        out.append({
            "rule": "shell-wrapper",
            "severity": "high",
            "detail": f"server runs a shell with an inline program ({base} -c ...); "
                      f"every argument is executable",
        })
    if REMOTE_EXEC_RE.search(joined):
        out.append({
            "rule": "remote-fetch-exec",
            "severity": "high",
            "detail": "server pipes a remote download into an interpreter",
        })
    if base in ("npx", "uvx", "pipx") and any(a in ("-y", "--yes") for a in argv[1:]):
        pkgs = [a for a in argv[1:] if not a.startswith("-") and a not in ("mcp",)]
        if pkgs and not any("@" in p for p in pkgs):
            out.append({
                "rule": "unpinned-npx",
                "severity": "low",
                "detail": f"{base} -y resolves {pkgs[0]!r} fresh on every start; "
                          f"pin a version (pkg@1.2.3) so an upstream release "
                          f"cannot silently change what runs",
            })
    return out


def _env_findings(cfg: dict) -> list[dict]:
    env = cfg.get("env")
    if not isinstance(env, dict):
        return []
    out: list[dict] = []
    for key, value in env.items():
        if not isinstance(key, str) or not SECRET_KEY_RE.search(key):
            continue
        if value in (None, ""):
            continue
        out.append({
            "rule": "secret-in-env",
            "severity": "medium",
            "key": key,
            "detail": f"env key {key} holds a non-empty value stored in cleartext "
                      f"in the config file (value not shown)",
        })
    return out


def audit_server(name: str, cfg: dict) -> list[dict]:
    """Static findings for one server entry.  Never executes, never fetches."""
    if not isinstance(cfg, dict):
        return [{"rule": "malformed-server", "severity": "low",
                 "detail": f"server entry is {type(cfg).__name__}, expected an object"}]
    return _url_findings(cfg) + _command_findings(cfg) + _env_findings(cfg)


def max_severity(findings: list[dict]) -> str | None:
    if not findings:
        return None
    return max((f.get("severity", "low") for f in findings),
               key=lambda s: SEVERITY_ORDER.get(s, 0))


def discover(home: Path | None = None, extra: list[Path] | None = None) -> dict:
    """Full pass: configs -> servers -> findings.  Returns one entry per server."""
    configs = find_configs(home=home, extra=extra)
    entries: list[dict] = []
    for conf in configs:
        try:
            servers = load_servers(Path(conf["path"]))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        for name, cfg in servers.items():
            findings = audit_server(name, cfg)
            entries.append({
                "client": conf["client"],
                "config": conf["path"],
                "server": name,
                "findings": findings,
                "max_severity": max_severity(findings),
            })
    return {"n_configs": len(configs), "n_servers": len(entries), "servers": entries}
