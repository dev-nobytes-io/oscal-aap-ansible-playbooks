# nobytes.compliance

The project's Ansible collection: evidence collectors, the evaluator bridge,
filters and reporting.

Planned layout — each directory is created by the pull request that fills it,
rather than sitting empty:

```
plugins/
  modules/       # fact-bundle emit, artefact store I/O
  action/        # thin wrappers; the evaluator itself is NOT a plugin (see tools/)
  filter/        # cheap pure helpers only (id derivation, catalog lookups)
  callback/      # capture run provenance
  module_utils/  # shared contract helpers
roles/
  collect_*/     # one per platform family. READ-ONLY, always.
  evaluate/      # applies control assertions to collected facts
  report/        # renders reports from assessment results
  remediate_*/   # opt-in, per-control, never called by assessment
```

Two rules hold across every role here:

1. **`collect_*` roles never mutate a target.** No mutating module surface at
   all — the guarantee is structural, not a promise in a comment.
2. **Collectors gather facts; they do not judge.** Verdicts are the evaluator's
   job, off-host, so that evidence can be re-evaluated when ASD revises control
   text without touching production again.
3. **Read-only is enforced by the credential, not only by the role.** Collect
   job templates are bound to credentials that physically cannot write — a
   read-only vSphere role, a Graph app registration holding only `*.Read.All`,
   an unprivileged SSH account with a narrow sudoers allowlist. Role hygiene is
   the first line; credential scoping is the one that survives adversarial
   review.
