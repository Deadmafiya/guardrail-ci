from __future__ import annotations

from pathlib import Path
import subprocess


class GitScopeError(RuntimeError):
    pass


def get_changed_files(root: Path, diff_base: str) -> set[str]:
    cmd = [
        "git",
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        f"{diff_base}...HEAD",
    ]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitScopeError("git is not installed or not available in PATH") from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise GitScopeError(
            f"Failed to resolve changed files from diff base '{diff_base}'. {stderr or 'Check git history and ref availability.'}"
        )

    out = set()
    for line in (proc.stdout or "").splitlines():
        p = line.strip()
        if p:
            out.add(p)
    return out
