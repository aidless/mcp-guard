# Security Policy

## Supported Versions

This is a personal research project; only the latest commit on the default branch is supported.

## Reporting a Vulnerability

If you discover a security issue, please **open a private GitHub security advisory** via this repository's **Security → Report a vulnerability** button (https://github.com/aidless/mcp-guard/security/advisories/new), or contact the maintainer through their GitHub profile. Please do not open a public issue for exploit details.

You can expect an initial response within 7 days.
Release 资产用此密钥（SIGNING_KEY.asc）签名，验证命令 `gpg --verify <asset>.asc <asset>`。

## Maintainer credential hygiene

Release credentials are kept out of this repository and out of git's plaintext
credential file. What is in place as of 2026-11-14:

- **GitHub auth goes through `gh`**, which stores the token in the OS keyring
  (`~/.config/gh/hosts.yml` holds no token). `git` uses
  `credential.helper = !gh auth git-credential`; `~/.git-credentials` was removed.
- **PyPI uploads use a token that is not stored on disk.** `~/.pypirc` and
  `~/.config/mcp-guard/pypi-token` were both removed after the 0.3.0 release, and
  the systemd timer that held one of them is stopped and disabled.

Known outstanding item, recorded rather than glossed over: the GitHub token in
use is a **classic PAT** whose scopes are far broader than this repository needs
(`admin:enterprise`, `admin:org`, `admin:gpg_key`, `audit_log`, `codespace`,
`copilot`, `write:packages`, …). A fine-grained token scoped to `contents: write`
and `metadata: read` on the three repositories that are actually pushed to would
do the same work. Replacing it is a manual step in the GitHub UI; until then the
breadth of that token is a real, accepted risk, not a closed one.
