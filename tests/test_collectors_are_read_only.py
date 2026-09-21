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

import re
from pathlib import Path
from urllib.parse import urlsplit

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

#: Ansible keywords that are task structure rather than a module. Everything a
#: task declares that is NOT one of these is the module it runs.
TASK_KEYWORDS = frozenset(
    {
        "name", "when", "become", "become_user", "become_method", "register", "vars",
        "loop", "loop_control", "with_items", "with_dict", "with_fileglob", "until",
        "retries", "delay", "changed_when", "failed_when", "check_mode", "ignore_errors",
        "no_log", "tags", "delegate_to", "run_once", "environment", "notify", "listen",
        "block", "rescue", "always", "args", "throttle", "any_errors_fatal",
        "module_defaults", "connection", "timeout", "poll", "async", "collections",
        "debugger", "diff", "port", "remote_user", "vars_files",
    }
)

#: The ONLY modules a collect role may run. Everything else fails.
#:
#: This was a denylist until PR 14, and the difference matters more than it
#: looks. `MUTATING_MODULES.intersection(task.keys())` catches only what someone
#: remembered to enumerate, so its failure mode is to SILENTLY PERMIT anything
#: unlisted -- and the next chunk adds `microsoft.ad`, which brings 23 mutating
#: modules including `domain_controller` (promotes, demotes and reboots domain
#: controllers) and `offline_join`, whose name reads inert while it creates a
#: computer account. A denylist would have admitted every one of them.
#:
#: This repository has now found the same shape in itself five times: a guard
#: structurally unable to see what it was guarding. An allowlist fails closed --
#: adding a module to a collect role is a deliberate, reviewable edit here.
ALLOWED_MODULES = frozenset(
    {
        # Fact gathering and pure reads
        "ansible.builtin.setup",
        "ansible.builtin.slurp",
        "ansible.builtin.stat",
        "ansible.builtin.find",
        "ansible.builtin.uri",
        "ansible.builtin.set_fact",
        "ansible.builtin.assert",
        "ansible.builtin.debug",
        "ansible.builtin.fail",
        "ansible.builtin.include_role",
        "ansible.builtin.include_tasks",
        "ansible.builtin.include_vars",
        "ansible.builtin.import_role",
        "ansible.builtin.import_tasks",
        "ansible.builtin.group_by",
        "ansible.builtin.meta",
        # Windows reads
        "ansible.windows.win_powershell",
        "ansible.windows.win_stat",
        "ansible.windows.win_reg_stat",
        "ansible.windows.win_slurp",
        "ansible.windows.win_find",
    }
)

#: Modules whose safety depends on an ARGUMENT rather than on the module name.
#:
#: Everything in MUTATING_MODULES is mutating by nature and everything else used
#: here is safe by nature. `uri` is neither: it reads with GET and rewrites a
#: conditional access policy with PATCH. Checking the module name alone would
#: pass a Graph collector that could edit the tenant, so the method is asserted.
#: Mapped to the set of methods that are actually read-only.
CONDITIONALLY_MUTATING = {
    "ansible.builtin.uri": frozenset({"GET", "HEAD", "OPTIONS"}),
}

#: The one sanctioned exception, narrow and visible on purpose.
#:
#: Obtaining an OAuth token is a POST, and it changes nothing in the tenant --
#: but "it's only authentication" is exactly the reasoning that would later
#: excuse a second POST. So the exception is pinned to a task file whose only
#: job is to get a token, and any other POST in a collect role fails.
TOKEN_TASK_FILES = frozenset({"authenticate.yml"})
TOKEN_HOST_SUFFIXES = ("login.microsoftonline.com", "login.microsoftonline.us")


def _role_defaults(task_file: Path) -> dict:
    """The role's `defaults/main.yml`, flattened to plain strings."""
    defaults = task_file.parent.parent / "defaults" / "main.yml"
    if not defaults.exists():
        return {}
    loaded = yaml.safe_load(defaults.read_text(encoding="utf-8")) or {}
    return {k: v for k, v in loaded.items() if isinstance(v, (str, int))}


def _resolve_url(url: str, task_file: Path) -> str:
    """Substitute a role's default values into a templated URL.

    A collector's URL is almost always `{{ some_base }}/path`, so parsing it
    raw yields no host and the destination check would silently pass on an
    empty string -- a rule that cannot see its target is not a rule. Resolving
    against the role's declared defaults checks the host this role SHIPS
    pointing at. A deployment that overrides the base is making a deliberate,
    reviewable change; a hardcoded wrong host is not.
    """
    resolved = url
    for name, value in _role_defaults(task_file).items():
        resolved = re.sub(r"{{\s*" + re.escape(name) + r"\s*}}", str(value), resolved)
    # Collapse whitespace introduced by YAML folded scalars.
    resolved = " ".join(resolved.split())

    # Only the DESTINATION has to be establishable. A tenant id or resource id
    # later in the path is supplied per deployment and stays templated; that
    # does not change which host is being contacted. An unresolved scheme or
    # host does, so that fails closed.
    head = resolved.split("/", 3)
    authority = "/".join(head[:3])
    if "{{" in authority or not authority.startswith("https://"):
        return "unresolved://" + resolved
    return authority


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


def _modules_used(task: dict) -> set:
    """The modules a task runs: every key that is not an Ansible task keyword."""
    return {k for k in task if k not in TASK_KEYWORDS}


@pytest.mark.parametrize("path", _collect_role_task_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_collect_roles_use_no_mutating_modules(path: Path) -> None:
    """The named-and-shamed case, kept for its specific message."""
    for task in _tasks(path):
        used = MUTATING_MODULES.intersection(task.keys())
        assert not used, (
            f"{path.relative_to(ROOT)}: task {task.get('name')!r} uses {sorted(used)}. "
            f"Collect roles must have no mutating module surface -- move this to a "
            f"remediate_* role."
        )


@pytest.mark.parametrize("path", _collect_role_task_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_collect_roles_run_only_allowlisted_modules(path: Path) -> None:
    """Fails closed. A module nobody listed is refused, not admitted."""
    for task in _tasks(path):
        for module in sorted(_modules_used(task)):
            assert module in ALLOWED_MODULES, (
                f"{path.relative_to(ROOT)}: task {task.get('name')!r} runs {module!r}, "
                f"which is not in ALLOWED_MODULES. Collect roles are read-only by "
                f"construction: if this module genuinely only reads, add it to the "
                f"allowlist in this file with a one-line justification. If it writes, "
                f"it belongs in a remediate_* role."
            )


def test_the_allowlist_rejects_an_unlisted_module() -> None:
    """Guards the guard.

    The allowlist passes trivially while every collect role happens to comply,
    so prove it fires. `microsoft.ad.domain_controller` is the real example:
    the next chunk adds that collection, and this module promotes, demotes and
    reboots domain controllers.
    """
    task = {"name": "seems harmless", "microsoft.ad.domain_controller": {"dns_domain_name": "x"}}
    assert _modules_used(task) == {"microsoft.ad.domain_controller"}
    assert "microsoft.ad.domain_controller" not in ALLOWED_MODULES
    # And the old denylist would have waved it straight through.
    assert not MUTATING_MODULES.intersection(task.keys())


def test_task_keywords_are_not_mistaken_for_modules() -> None:
    """An allowlist that flagged `when:` as a module would be useless noise."""
    task = {
        "name": "read something",
        "ansible.builtin.slurp": {"src": "/etc/os-release"},
        "register": "out",
        "changed_when": False,
        "check_mode": False,
        "when": "ansible_os_family == 'RedHat'",
        "loop": [1, 2],
        "vars": {"x": 1},
    }
    assert _modules_used(task) == {"ansible.builtin.slurp"}


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


@pytest.mark.parametrize("path", _collect_role_task_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_conditionally_mutating_modules_declare_a_read_only_method(path: Path) -> None:
    """`uri` in a collect role must say GET, not merely avoid being on a list.

    An omitted `method` defaults to GET in Ansible, but relying on that default
    means a later edit adding `method: PATCH` reads as a small change rather
    than as breaking the read-only guarantee. It has to be explicit.
    """
    for task in _tasks(path):
        for module, safe_methods in CONDITIONALLY_MUTATING.items():
            args = task.get(module)
            if args is None:
                continue
            method = str((args or {}).get("method", "")).upper()
            assert method, (
                f"{path.relative_to(ROOT)}: task {task.get('name')!r} uses {module} "
                f"without an explicit `method`. It defaults to GET, but the guarantee "
                f"must be stated rather than inherited."
            )
            if method in safe_methods:
                continue
            # Not a read-only method: only the token exception may proceed.
            url = _resolve_url(str((args or {}).get("url", "")), path)
            host = urlsplit(url).hostname or ""
            assert path.name in TOKEN_TASK_FILES and host.endswith(TOKEN_HOST_SUFFIXES), (
                f"{path.relative_to(ROOT)}: task {task.get('name')!r} calls {module} "
                f"with method {method} against {host or url!r}. A collect role may "
                f"only issue read-only requests; the sole exception is an OAuth token "
                f"request, which must live in {sorted(TOKEN_TASK_FILES)} and target the "
                f"identity platform."
            )


def test_the_conditionally_mutating_rule_actually_rejects_a_write() -> None:
    """Guards the guard: prove the rule fires, without waiting for a real mistake.

    Written because the rule above passes trivially while no collect role uses
    `uri` at all, and a rule that has never rejected anything is a rule nobody
    knows is broken.
    """
    offending = {
        "name": "rewrite a conditional access policy",
        "ansible.builtin.uri": {
            "url": "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/x",
            "method": "PATCH",
        },
    }
    module, safe = next(iter(CONDITIONALLY_MUTATING.items()))
    args = offending[module]
    assert args["method"].upper() not in safe
    host = urlsplit(args["url"]).hostname or ""
    assert not host.endswith(TOKEN_HOST_SUFFIXES), (
        "a Graph host must not satisfy the token exception"
    )


def test_url_resolution_fails_closed_and_still_rejects_a_wrong_host() -> None:
    """The destination check must survive templating without going blind.

    Collector URLs are templated, so a naive parse yields no host and the
    destination check passes on an empty string -- a rule that cannot see its
    target is not a rule. `_resolve_url` substitutes the role's defaults; these
    cases pin the three behaviours that matter.
    """
    token_task = (
        ROLES / "collect_entra_id" / "tasks" / "authenticate.yml"
    )
    if not token_task.exists():
        pytest.skip("no Entra collector present to resolve defaults from")

    # 1. The real token URL resolves to the identity platform, even though the
    #    tenant id later in the path stays templated.
    resolved = _resolve_url(
        "{{ collect_entra_id_login_base }}/{{ collect_entra_id_tenant_id }}/oauth2/v2.0/token",
        token_task,
    )
    assert (urlsplit(resolved).hostname or "").endswith(TOKEN_HOST_SUFFIXES)

    # 2. The same shape pointed at Graph does NOT satisfy the exception.
    graph = _resolve_url("{{ collect_entra_id_graph_base }}/policies/x", token_task)
    assert not (urlsplit(graph).hostname or "").endswith(TOKEN_HOST_SUFFIXES)

    # 3. An unresolvable host fails closed rather than parsing to nothing.
    unknown = _resolve_url("{{ some_undeclared_base }}/token", token_task)
    assert urlsplit(unknown).scheme == "unresolved"
    assert not (urlsplit(unknown).hostname or "").endswith(TOKEN_HOST_SUFFIXES)


def test_collect_roles_exist_and_were_scanned() -> None:
    """Guards the guard: a passing suite must not mean 'nothing was checked'."""
    files = _collect_role_task_files()
    assert files, "no collect_* role task files found -- this test proves nothing"
    assert len(files) >= 2
