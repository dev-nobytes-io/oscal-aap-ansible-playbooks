# ADR 0018: Redaction must reach identifiers inside lists

## Context

[ADR 0016](0016-apply-the-redaction-policy.md) made the redaction policy run.
It did not make it **arrive**.

`redact_facts` selected the action from a mapping **key**:

```python
def walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            action = policy.get(str(key).lower(), default)
            if isinstance(value, (dict, list)):
                out[key] = walk(value)          # <-- action discarded here
            else:
                out[key] = _apply(action, value, salt)
    if isinstance(node, list):
        return [walk(item) for item in node]    # <-- no key, no action
    return node                                 # <-- scalar returned unchanged
```

Three consequences, and the third is the live one:

1. A bare scalar reached **inside a list** has no key to match on, so the final
   `return node` handed it back verbatim.
2. The enclosing key's action was **dropped at every container boundary**, so
   even `sid: hash` left a list of SIDs untouched.
3. The shipped policy names `sid`, `username`, `upn`, `email` — but the
   collectors emit SIDs under `allow_write_sids`, `deny_write_sids`
   (`Get-UserWritableExecutionPaths.ps1:86-87,122-123`) and
   `meta.profiles_unloaded` (`Get-BrowserPolicy.ps1:232`). **None of those names
   matched anything**, and their values are bare strings in lists.

Measured against the committed fixture corpus, the shipped filter left **five
paths** carrying a personal SID:

| Fixture | Path |
|---|---|
| `wks-0042-partial.json` | `windows.office.macro_policy.meta.profiles_unloaded[0]` |
| `wks-0044-applocker.json` | `windows.appcontrol.writable_paths.value.probes[2..5].allow_write_sids[0]` |

Stated precisely, because the defect is narrower than it first looks: a SID under
a literal `sid` key **was** redacted — `wks-0043-failing.json`'s
`macro_policy.value[0].sid` came out hashed. What never worked is a bare
identifier inside a list.

Those bundles still stamped `redaction_policy: "1.0"`.

**Twelfth instance of the recurring shape**, and the second time the shape has
appeared in the redaction layer specifically. PR 16's own load-bearing test
asserted the *wiring* — that `finalise.yml` calls the filter — which is exactly
what was missing then and is still true now. It could not see that the filter,
once called, does not reach everything it claims to.

## Decision

**1. The enclosing key's action propagates into lists, and resets at every dict
boundary.**

A **list** under a named key holds instances of the thing the key names:
`allow_write_sids` is a list of SIDs, so the action travels into it. A
**sub-mapping** does not — its child keys name different fields, and
`{"sid": {"nested": ..., "count": 3}}` must not hash the count. That distinction
is not a nicety: `test_a_container_is_recursed_not_hashed_whole` has asserted it
since PR 16, and the first version of this fix broke it. Hashing a whole subtree
destroys the evidence the bundle exists to carry.

**2. SIDs are additionally detected by shape, not only by key name.**

```python
_SID_RE = re.compile(r"^S-1-\d+(-\d+){2,}$", re.IGNORECASE)
```

A value that **is** a SID is a SID whatever it is filed under. This is the
backstop for the key names nobody thought of, and it is what makes the next
collector's `some_new_sids` field safe by default rather than by remembering.

**3. Shape detection applies to SIDs only — deliberately not to email or UPN.**

`S-1-<n>-<n>-…` is unambiguous; nothing else in a fact bundle looks like it. An
`@` is not: proxy exception lists, ADMX policy strings and administrator contact
notes all legitimately contain one, and hashing those would destroy evidence to
protect nobody. Email and UPN continue to rely on their key name, which now
propagates into containers.

Asymmetry is the right answer here rather than a compromise. A redaction rule
broad enough to catch every conceivable identifier shape would mangle
configuration values, and a bundle full of opaque digests fails the control it
was collected for while protecting no one in particular.

## Consequences

No verdict moves and coverage is unchanged at **15 of 46 (32.6%)**: redaction
runs between collection and persistence, after the facts the evaluators read.

The scope boundary from ADR 0016 **stands unchanged**: `subject.asset_id` is
still not redacted, because it is the correlation key that gives a POA&M item
continuity across runs. `subject.description` likewise still embeds
`inventory_hostname`, which is the same class of estate identifier as
`asset_id` and is retained for the same reason. A deployment needing either
pseudonymous sets `cca_asset_id` in inventory. Both remain outside the `facts`
subtree this filter walks.

**Bundles collected before this change carry raw domain SIDs in list-valued
facts**, regardless of the `redaction_policy` stamp. As with ADR 0016, this
cannot be fixed retrospectively — that is the whole reason redaction happens
before persistence.

`tests/test_redaction.py` gains an end-to-end assertion that runs the policy over
the **real fixture corpus** and fails on any surviving RID ≥ 1000. The fixtures
deliberately *contain* realistic SIDs — that is how the truncation carve-out gets
tested — so the assertion is that none *survives*, not that none exists.

Seven tests were verified to fail against the filter as it shipped, including
the corpus scan, which found the `wks-0042` leak that was not in the original
defect report.

## Status

Accepted.
