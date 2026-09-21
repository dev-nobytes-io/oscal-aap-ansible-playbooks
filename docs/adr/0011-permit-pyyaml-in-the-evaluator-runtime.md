# ADR 0011: Permit PyYAML in the evaluator runtime

## Context

[ADR 0007](0007-evaluator-is-a-plain-python-package.md) constrains the evaluator
to the standard library, and to Python 3.9 syntax, so it runs under whatever
`python3` an environment provides — on RHEL 9 and CentOS Stream 9 that is the
3.9 system interpreter, and in an air-gapped enclave often the only one
available.

The check registry is YAML. Contributors author one registry entry and one
evaluator function; making them hand-write JSON instead would be hostile for no
security benefit, and YAML is what the rest of an Ansible repository speaks.

Three options:

1. Keep the registry in JSON. Stdlib-pure, unpleasant to author, and
   inconsistent with every other file in the repo.
2. Compile YAML to JSON in a build step and have the evaluator read the
   compiled artefact. Stdlib-pure at runtime, but adds a generated file that
   can drift from its source.
3. Permit PyYAML.

The deciding fact, verified rather than assumed:

```
ansible-core requires: jinja2>=3.1.0, PyYAML>=5.1, cryptography, packaging, resolvelib
```

**PyYAML is a hard dependency of `ansible-core` itself.** Every execution
environment contains it by construction — there is no image that can run an
Ansible playbook and cannot import `yaml`.

## Decision

The evaluator's runtime dependency set is **the standard library plus PyYAML**.
Nothing else. `jsonschema`, `regex`, `pytest` and the reporting libraries remain
test-time or tooling-layer only.

The Python 3.9 syntax constraint from ADR 0007 is unchanged.

## Status

Accepted. Amends ADR 0007 rather than reversing it.

## Consequences

The constraint that actually mattered is preserved: the evaluator still runs in
both execution environments with nothing to install, because the one dependency
added is already there. The point of ADR 0007 was never purity for its own sake
— it was that the evaluator must not require anything an execution environment
lacks. That test is still met.

The bar for any further dependency is now explicit and high: it must already be
present in every execution environment by construction. Nothing else qualifies
today. "It's only one small package" does not.

Tests still enforce the rest: no network, no subprocess, and an import contract
over the check modules.
