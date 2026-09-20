# Python tooling

The OSCAL half of the project: ingest, validation, evaluation and emission.

## Why this is a plain Python package, not an Ansible plugin

The obvious design is to ship the evaluator as collection action/lookup
plugins so AAP calls it "natively". That is the wrong mechanism:

- Plugins run inside the execution environment's Ansible interpreter, which
  version-couples the evaluator to `ansible-core`.
- They are awkward to unit test, and the evaluator is where nearly all the
  logic — and therefore nearly all the risk — lives.
- Evaluating a thousand-plus controls across thousands of hosts inside a
  `module_utils` import graph is the wrong place to do that work.

So the evaluator is an ordinary Python package, vendored into both execution
environments and invoked from a thin role via `ansible.builtin.command`. A
small filter plugin covers cheap pure helpers only (id derivation, catalog
lookups). One implementation, two entrypoints, nothing to drift.

## Constraints on the evaluator

- **Standard library only at runtime.** `jsonschema`, `pytest` and friends are
  test-time dependencies. This lets the evaluator run inside `ee-legacy` as
  well as `ee-current`, which matters in an air-gapped enclave where the
  legacy image may be the only one that made it through.
- **Python 3.9 syntax.** Same reason.
- **Pure functions.** No network, no subprocess. Enforced by a test that
  monkeypatches `socket.socket` and `subprocess.Popen` to raise, and by running
  the suite with networking disabled in CI.

Purity is what makes evidence re-evaluatable: given the same fact bundle, the
evaluator must produce byte-identical OSCAL. That property is also what makes
golden-file testing possible, and it is worth more than any individual check.

## Planned contents

Ingest and pinning of upstream ISM releases · OSCAL schema validation ·
the check registry loader · the evaluator · deterministic UUIDv5 derivation ·
assessment-plan, assessment-results and POA&M emitters · the coverage ledger
generator.
