"""Lab validation: establishing that a collector has actually read a real host.

Fourteen of the fifteen automated controls have never had their collector
executed against the platform it reads. PR 18 established what that costs: the
entire Windows collection path had never populated a fact on a real host, and
the failure surfaced as one confident false red and one false `satisfied` at
`direct` confidence.

This package turns a bundle collected in a lab into something that can be
compared against what the fixtures assume and what the evaluators read, WITHOUT
carrying estate data out of the lab. See ADR 0020.
"""

from __future__ import annotations
