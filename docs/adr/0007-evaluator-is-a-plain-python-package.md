# ADR 0007: Ship the evaluator as a plain Python package, not an Ansible plugin

## Context

AAP runs playbooks, so the natural instinct is to ship the evaluator as
collection action or lookup plugins and have job templates call it "natively".

Against that: plugins run inside the execution environment's Ansible
interpreter and version-couple the evaluator to `ansible-core`; they are awkward
to unit test, and the evaluator holds nearly all the logic and therefore nearly
all the risk; and evaluating a thousand-plus controls across thousands of hosts
inside a `module_utils` import graph is the wrong place for that work.

## Decision

The evaluator is an ordinary Python package, vendored into both execution
environments and invoked from a thin role via `command`. A small filter plugin
covers cheap pure helpers only. The same package exposes a CLI for CI and local
use — one implementation, two entrypoints.

Two runtime constraints:

- **Standard library only.** `jsonschema` and `pytest` are test-time
  dependencies.
- **Python 3.9 syntax**, so the evaluator runs inside `ee-legacy` as well as
  `ee-current`.

## Status

Accepted.

## Consequences

The evaluator is testable without Ansible and survives an `ansible-core` upgrade
untouched. It runs in an enclave where the legacy image may be the only one that
got through.

Purity is enforced rather than hoped for: the suite runs with `socket.socket` and
`subprocess.Popen` patched to raise, with networking disabled, and with an import
contract over `checks.*`. Adding an import there requires architecture sign-off.

Cost: no third-party conveniences in evaluator code, and a `command` invocation
is slightly less idiomatic in a playbook than a module. Both are cheap next to
reproducibility — same facts in, byte-identical OSCAL out, which is what makes
golden-file testing and independent auditor re-derivation possible.
