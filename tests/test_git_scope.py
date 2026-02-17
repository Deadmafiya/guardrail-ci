from pathlib import Path
from unittest.mock import patch

import pytest

from guardrail_ci.git_scope import GitScopeError, get_changed_files


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@patch("guardrail_ci.git_scope.subprocess.run")
def test_get_changed_files_success(mock_run):
    mock_run.return_value = _Proc(returncode=0, stdout="a.py\nb/c.tf\n")
    out = get_changed_files(Path("."), "origin/main")
    assert out == {"a.py", "b/c.tf"}


@patch("guardrail_ci.git_scope.subprocess.run")
def test_get_changed_files_invalid_ref(mock_run):
    mock_run.return_value = _Proc(returncode=128, stderr="bad revision")
    with pytest.raises(GitScopeError):
        get_changed_files(Path("."), "origin/does-not-exist")


def test_get_changed_files_git_missing():
    with patch("guardrail_ci.git_scope.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(GitScopeError):
            get_changed_files(Path("."), "origin/main")
