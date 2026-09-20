"""Collect roles must have no mutating module surface at all.

Principle 6 says assessment never changes a host. The guarantee that survives
adversarial review is credential scoping -- a collect job template is bound to
credentials that physically cannot write. But role hygiene is the first line,
and it is the one this repository controls, so it is enforced here rather than
left to reviewer memory.

This is a static check over the task files. It cannot prove a collector is
harmless (a `win_powershell` script could do anything), which is exactly why
the security model does not rest on it -- see docs/13-security-model.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from conftest import ROOT

ROLES = ROOT / "collections" / "ansible_collections" / "nobytes" / "compliance" / "roles"

#: Modules that change state. A collect role using any of these is a bug.
MUTATING_MODULES = frozenset(
    {
        "ansible.builtin.command", "ansible.builtin.shell", "ansible.builtin.raw",
        "ansible.builtin.script", "ansible.builtin.file", "ansible.builtin.copy",
        "ansible.builtin.template", "ansible.builtin.lineinfile",
        "ansible.builtin.blockinfile", "ansible.builtin.replace",
        "ansible.builtin.package", "ansible.builtin.dnf", "ansible.builtin.yum",
        "ansible.builtin.apt", "ansible.builtin.service",
        "ansible.builtin.systemd_service", "ansible.builtin.user",
        "ansible.builtin.group", "ansible.builtin.cron", "ansible.builtin.mount",
        "ansible.windows.win_regedit", "ansible.windows.win_file",
        "ansible.windows.win_copy", "ansible.windows.win_command",
        "ansible.windows.win_shell", "ansible.windows.win_service",
        "ansible.windows.win_user", "ansible.windows.win_feature",
        "ansible.windows.win_package", "ansible.windows.win_updates",
        "ansible.windows.win_reboot",
    }
)

#: Read-only PowerShell/script execution is permitted, but every such task must
#: carry `changed_when: false` -- asserted separately below.
READ_ONLY_EXECUTORS = frozenset({"ansible.windows.win_powershell"})


def _collect_role_task_files() -> list:
    if not ROLES.exists():
        return []
    return sorted(
        path
        for role in ROLES.iterdir()
        if role.is_dir() and role.name.startswith("collect_")
        for path in (role / "tasks").glob("*.yml")
    )


def _tasks(path: Path) -> list:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    out = []

    def walk(items):
        for item in items:
            if not isinstance(item, dict):
                continue
            out.append(item)
            for key in ("block", "rescue", "always"):
                if isinstance(item.get(key), list):
                    walk(item[key])

    walk(loaded)
    return out


@pytest.mark.parametrize("path", _collect_role_task_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_collect_roles_use_no_mutating_modules(path: Path) -> None:
    for task in _tasks(path):
        used = MUTATING_MODULES.intersection(task.keys())
        assert not used, (
            f"{path.relative_to(ROOT)}: task {task.get('name')!r} uses {sorted(used)}. "
            f"Collect roles must have no mutating module surface -- move this to a "
            f"remediate_* role."
        )


@pytest.mark.parametrize("path", _collect_role_task_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_read_only_executors_declare_changed_when_false(path: Path) -> None:
    """A collector that reports `changed` is either lying or mutating."""
    for task in _tasks(path):
        executor = READ_ONLY_EXECUTORS.intersection(task.keys())
        if not executor:
            continue
        assert task.get("changed_when") is False, (
            f"{path.relative_to(ROOT)}: task {task.get('name')!r} runs "
            f"{sorted(executor)} without `changed_when: false`"
        )
        assert task.get("check_mode") is False, (
            f"{path.relative_to(ROOT)}: task {task.get('name')!r} should set "
            f"`check_mode: false` so evidence is still gathered during a check run"
        )


def test_collect_roles_exist_and_were_scanned() -> None:
    """Guards the guard: a passing suite must not mean 'nothing was checked'."""
    files = _collect_role_task_files()
    assert files, "no collect_* role task files found -- this test proves nothing"
    assert len(files) >= 2
