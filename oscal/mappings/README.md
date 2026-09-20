# Crosswalks

Two kinds of mapping, both authored, both requiring citation and an explicit
confidence rating:

**Obligation to ISM** — which ISM controls produce evidence toward a PSPF
requirement, an Australian Privacy Principle, or a SOCI CIRMP obligation. These
mappings say *contributes evidence toward*. They never say *proves compliance
with*: a statutory obligation is not discharged by a passing host check.

**ISM to STIG / CIS** — where ISM prose genuinely matches a rule in maintained
open-source hardening content, so that content can be delegated to rather than
reimplemented. Every entry records an equivalence rating:

| Rating | Meaning |
|---|---|
| `equivalent` | The rule tests the same condition the ISM control requires |
| `partial` | The rule tests part of it; the remainder is uncovered and stated |
| `related` | Same topic, different requirement. Supporting evidence only. |

Treating a STIG rule as identical to an ISM control is the single most likely
way this repository becomes quietly, confidently wrong. Hence the rating is
mandatory and CI rejects any entry lacking one.
