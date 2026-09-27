# -*- coding: utf-8 -*-
"""Parse what `ansible.windows.win_powershell` actually returns.

This exists because every Windows collector in this collection was consumed as
though `win_powershell`'s `output` held a deserialised object, and it does not.

Each collector script ends `| ConvertTo-Json -Compress`, so its only pipeline
output is a single [string]. `win_powershell` runs `Convert-OutputObject` over
the output pipeline, and that function returns a string unchanged:

    elseif ($InputObject -is [string]) {
        $InputObject.PSObject.BaseObject
    }
        -- ansible/windows/plugins/modules/win_powershell.ps1:528-531

So `output[0]` is the JSON TEXT, not a mapping. Nothing in this collection
called `from_json`. Every `.rows` / `.meta` / `.applications` lookup therefore
resolved to undefined on a real Windows host and was swallowed by
`| default({})`, and the roles' `partial` flags -- computed from
`output | length`, which is 1 because there IS one element -- reported the
resulting emptiness as a successful collection of nothing.

That is why this returns a STATUS rather than just a value. A collector that
could not be read and a host with nothing to find are different outcomes, and
the caller must be able to tell them apart. See ADR 0017.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

try:
    from ansible.errors import AnsibleFilterError
except ImportError:  # pragma: no cover - taken by the in-image test run
    # Inside an execution environment the evaluator suite runs on
    # /usr/bin/python3 (3.9), where ansible-core is NOT installed. A
    # module-level ansible import makes this file uncollectable there. Same
    # reasoning as plugins/filter/redact.py.
    class AnsibleFilterError(Exception):
        """Stand-in used only where ansible-core is not importable."""


def _fail(error):
    return {"ok": False, "error": error, "value": {}}


def ps_object(output, expect="mapping"):
    """Turn a `win_powershell` `output` list into the object the script emitted.

    Returns a mapping with three keys, always present:

      ok     -- True only when a value of the expected shape was recovered
      error  -- '' when ok, else why the collector's output was unusable
      value  -- the parsed object, or an empty one when not ok

    `expect` is 'mapping' (the contract every collector in this collection
    follows) or 'any'.
    """
    if expect not in ("mapping", "any"):
        raise AnsibleFilterError(
            "ps_object: expect must be 'mapping' or 'any', got %r" % (expect,)
        )

    if output is None:
        return _fail("the task registered no output at all")
    if isinstance(output, (dict, str)):
        return _fail(
            "expected win_powershell's `output` list, got %s -- pass "
            "`<register>.output`, not the register itself" % type(output).__name__
        )
    try:
        items = list(output)
    except TypeError:
        return _fail("`output` is not iterable (%s)" % type(output).__name__)

    if not items:
        # The script wrote nothing to the success pipeline. On a real host this
        # means it threw before its final ConvertTo-Json, so the `error` list
        # on the register holds the reason. Never an empty result.
        return _fail("the collector produced no output; check the task's `error`")

    first = items[0]

    # Defensive: if a collector is ever changed to let win_powershell serialise
    # its object graph natively, `first` is already a mapping. Accept it rather
    # than failing on a change that is not itself wrong.
    if isinstance(first, dict):
        parsed = first
    elif isinstance(first, str):
        text = first.strip()
        if not text:
            return _fail("the collector emitted an empty string")
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            return _fail("the collector's output is not valid JSON: %s" % (exc,))
    else:
        return _fail(
            "expected a JSON string or mapping, got %s" % type(first).__name__
        )

    # Historic collectors wrapped their single result as `,@($result)`, which
    # ConvertTo-Json renders as a one-element array. Unwrap it so the contract
    # is uniform, but only for exactly one element -- silently dropping the
    # tail of a longer list is the class of bug this file exists to fix.
    if isinstance(parsed, list):
        if expect == "any":
            return {"ok": True, "error": "", "value": parsed}
        if len(parsed) == 1 and isinstance(parsed[0], dict):
            parsed = parsed[0]
        else:
            return _fail(
                "expected one mapping, got a %d-element array" % (len(parsed),)
            )

    if expect == "mapping" and not isinstance(parsed, dict):
        return _fail("expected a mapping, got %s" % type(parsed).__name__)

    return {"ok": True, "error": "", "value": parsed}


class FilterModule(object):
    def filters(self):
        return {"ps_object": ps_object}
