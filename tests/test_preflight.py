"""The preflight playbook, and the mistake it nearly shipped with.

`playbooks/preflight.yml` exists so the first run against a real Windows host
produces a specific, actionable message rather than an Ansible traceback. Two
of the four failures it catches were found by actually running the repository
against a Windows host target: `pywinrm` was absent from `requirements.txt`
while both execution environment images carried it, and
`inventory/lab.yml.example` defaulted to Kerberos, which needs a compiler, krb5
system libraries and a realm.

**The load-bearing test here is `test_reachability_guards_use_ignore_errors`.**

The first version of this playbook used `failed_when: false` on the port check
and then asserted on `cca_preflight_port.failed`. `failed_when: false` does not
*ignore* a failure -- it *redefines success*, so `.failed` is always False and
the assert could never fire. A guard structurally unable to see the thing it
guards, in the guard written to prevent exactly that. Caught by running it
against an unreachable host and noticing the intended message never appeared.
"""

from __future__ import annotations

import yaml

from conftest import ROOT

PLAYBOOK = ROOT / "playbooks" / "preflight.yml"
READ_ONLY = ROOT / "tests" / "test_collectors_are_read_only.py"


def _plays() -> list:
    return yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))


def _tasks() -> list:
    out = []
    for play in _plays():
        out.extend(play.get("tasks") or [])
    return out


def _that(spec: dict) -> list:
    """`that:` is a scalar or a list. Iterating the scalar yields characters."""
    clauses = spec.get("that")
    if clauses is None:
        return []
    return clauses if isinstance(clauses, list) else [clauses]


def test_the_playbook_has_tasks_to_check() -> None:
    """A green suite must not be able to mean "nothing was scanned"."""
    tasks = _tasks()
    assert len(tasks) >= 10, f"only {len(tasks)} preflight tasks found"


def test_reachability_guards_use_ignore_errors_not_failed_when() -> None:
    """`failed_when: false` redefines success; it does not preserve `.failed`.

    Any task whose registered result is later tested for `.failed` or
    `.unreachable` must use `ignore_errors` / `ignore_unreachable`. With
    `failed_when: false` the flag is forced False and the assert is dead code.
    """
    body = PLAYBOOK.read_text(encoding="utf-8")
    tasks = _tasks()

    checked_registers = set()
    for task in tasks:
        spec = task.get("ansible.builtin.assert") or {}
        for clause in _that(spec):
            for register in (t.get("register") for t in tasks if t.get("register")):
                if register and register in str(clause) and (
                    ".failed" in str(clause) or ".unreachable" in str(clause)
                ):
                    checked_registers.add(register)

    assert checked_registers, (
        "no assert tests a registered result's .failed/.unreachable -- either the "
        "playbook changed shape or this test has gone blind"
    )

    for task in tasks:
        if task.get("register") not in checked_registers:
            continue
        name = task.get("name", "<unnamed>")
        assert task.get("failed_when") is not False, (
            f"{name!r} registers a result whose .failed is asserted on, but uses "
            f"`failed_when: false`. That forces .failed to False and makes the "
            f"assert unreachable. Use `ignore_errors: true` instead."
        )
        assert task.get("ignore_errors") is True, (
            f"{name!r} registers a result whose .failed is asserted on but does "
            f"not set `ignore_errors: true`, so the play stops before the "
            f"message is printed."
        )

    assert "ignore_errors, NOT failed_when: false" in body, (
        "the reasoning for ignore_errors should stay in the file; it is the "
        "second time this repository has made this class of mistake"
    )


def test_every_assert_explains_how_to_fix_it() -> None:
    """A guard that fails without saying what to do is half a guard."""
    for task in _tasks():
        spec = task.get("ansible.builtin.assert")
        if not spec:
            continue
        name = task.get("name", "<unnamed>")
        assert spec.get("fail_msg"), f"{name!r} asserts with no fail_msg"
        assert len(str(spec["fail_msg"])) > 60, (
            f"{name!r}'s fail_msg is too short to name a remedy: "
            f"{spec['fail_msg']!r}"
        )
        assert "Fix" in str(spec["fail_msg"]) or "See " in str(spec["fail_msg"]), (
            f"{name!r}'s fail_msg does not tell the operator what to do about it"
        )


def test_no_assertion_can_pass_vacuously() -> None:
    """An `or true` in a `that:` clause is an assert that cannot fail.

    The first draft of this playbook contained exactly that, as a placeholder.
    """
    for task in _tasks():
        spec = task.get("ansible.builtin.assert") or {}
        for clause in _that(spec):
            text = str(clause)
            assert " or true" not in text.lower(), (
                f"{task.get('name')!r} has a clause that can never fail: {text!r}"
            )
            assert text.strip() not in ("true", "True"), (
                f"{task.get('name')!r} asserts a literal truth: {text!r}"
            )


def test_the_interpreter_is_overridable_so_the_guard_is_testable() -> None:
    """`ansible_playbook_python` is a magic var that `-e` cannot override.

    Without the indirection there is no way to prove the pywinrm check fires,
    which is how the first version of it passed against an interpreter that
    demonstrably lacked pywinrm.
    """
    control = _plays()[0]
    assert control.get("vars", {}).get("cca_preflight_python") == (
        "{{ ansible_playbook_python }}"
    ), "cca_preflight_python must default to the interpreter running ansible"

    body = PLAYBOOK.read_text(encoding="utf-8")
    assert "{{ cca_preflight_python }}" in body
    assert "{{ ansible_playbook_python }} -c" not in body, (
        "`command` does not use a shell, so a quoted -c program is passed "
        "literally; use the argv form"
    )


def test_the_preflight_only_uses_read_only_modules() -> None:
    """It runs before an assessment, so it must not be able to change a host."""
    allowed = READ_ONLY.read_text(encoding="utf-8")
    module_keys = set()
    for task in _tasks():
        for key in task:
            if "." in key and key.split(".")[0] in {"ansible", "community", "nobytes"}:
                module_keys.add(key)

    assert module_keys, "no modules found in the preflight -- this test proves nothing"
    for module in sorted(module_keys):
        assert f'"{module}"' in allowed, (
            f"{module} is used by preflight.yml but is not in ALLOWED_MODULES in "
            f"tests/test_collectors_are_read_only.py. Assessment paths are "
            f"read-only; add it there with a justification, or do not use it."
        )


def test_it_reports_which_identity_authenticated() -> None:
    """Domain Admin working is not the same claim as a scoped account working.

    `docs/lab/README.md` insists on that distinction and nothing evidenced it
    until this playbook existed.
    """
    body = PLAYBOOK.read_text(encoding="utf-8")
    assert "ansible.windows.win_whoami" in body
    assert "RECORD THIS" in body, (
        "the identity report must tell the operator to record it alongside the "
        "run, or the distinction it exists to draw is lost"
    )
