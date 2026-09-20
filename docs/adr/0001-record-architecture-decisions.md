# ADR 0001: Record architecture decisions

## Context

This project encodes judgements about how Australian government security controls
should be interpreted and evidenced. Those judgements will be questioned — by
reviewers, by auditors, and by us in a year when the reasoning has faded.

In most projects "why was it built this way" is useful context. Here it is
closer to audit evidence: an assessor asking why a control is evidenced by a
registry read rather than a runtime test deserves a written answer that predates
the question.

## Decision

Record significant architectural and interpretive decisions as ADRs in
`docs/adr/NNNN-short-title.md`, numbered sequentially and never renumbered.
Standard shape: Context, Decision, Status, Consequences.

ADRs are **immutable once merged**. A reversed decision gets a new ADR that
supersedes the old one; the original stays so the history survives.

An ADR is warranted when a decision is hard to reverse, constrains future work,
or would otherwise be re-litigated. Routine choices belong in commit messages.

## Status

Accepted.

## Consequences

Some decisions get written up twice — once as an ADR and once in a document.
Accepted: the ADR records *why at the time*, documentation records *what is true
now*, and they diverge legitimately as the project evolves.
