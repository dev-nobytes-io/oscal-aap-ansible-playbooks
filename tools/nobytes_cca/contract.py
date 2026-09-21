"""The check contract.

Every check, on every platform -- a Windows registry read, an sshd_config
parse, a vSphere API call, an Entra ID Graph query, a Splunk search -- produces
this same shape. That is what lets a dozen platform families coexist without the
OSCAL emitters knowing anything about any of them.

The invariants encoded here are the ones from docs/ASSURANCE-PRINCIPLES.md that
can be enforced in code rather than in review.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    """The outcome of evaluating one check against one subject.

    Note what OSCAL 1.1.2 can and cannot carry. `finding-target.status.state`
    permits only `satisfied` and `not-satisfied`; there is no way to express
    "we did not determine this" in a finding. UNASSESSED and ERROR therefore
    emit an observation but NO finding, and the control's presence in
    `reviewed-controls` (generated from the assessment plan) is what makes the
    absence mean "no determination" rather than "out of scope". See ADR 0006.
    """

    SATISFIED = "satisfied"
    NOT_SATISFIED = "not-satisfied"
    NOT_APPLICABLE = "not-applicable"
    UNASSESSED = "unassessed"
    ERROR = "error"

    @property
    def emits_finding(self) -> bool:
        return self in (Status.SATISFIED, Status.NOT_SATISFIED, Status.NOT_APPLICABLE)


class Confidence(str, Enum):
    """How closely the check observes what the control actually requires.

    Ordered. A check declares a ceiling in its registry entry; an evaluator may
    lower it at runtime but may never raise it. Reading a registry value that
    *implements* a control is not the same as observing the control's effect,
    and flattening that distinction is how a policy read becomes "macros are
    blocked".
    """

    DIRECT = "direct"
    PROXY = "proxy"
    PARTIAL = "partial"
    ATTESTED = "attested"

    @property
    def rank(self) -> int:
        # Lower rank == stronger claim. Used to enforce the ceiling.
        return {"direct": 0, "proxy": 1, "partial": 2, "attested": 3}[self.value]

    def capped_by(self, ceiling: Confidence) -> Confidence:
        """Return whichever is the weaker claim. Never strengthens."""
        return self if self.rank >= ceiling.rank else ceiling


class Assessability(str, Enum):
    """Whether a control can be judged by a tool AT ALL.

    This is a different axis from `Confidence`, and conflating them is how a
    coverage figure starts lying. Confidence asks "how closely does our
    observation match the control?"; assessability asks "is there anything
    observable here in the first place?"

    `ATTESTED` is for controls where the answer is structurally no -- not "not
    yet", not "hard". ism-1679 requires multi-factor authentication on
    THIRD-PARTY online services: an organisation cannot see another
    organisation's authentication configuration from its own tenant, and no
    amount of engineering changes that. ism-1507 requires that privileged
    access requests were validated when first made, which lives in an approval
    record, not in any system's state.

    Declaring those explicitly is worth more than leaving them in the
    undifferentiated "no check" pile, because "nobody has built this yet" and
    "this is not observable by any tool" call for completely different
    responses from the person reading the report. They are deliberately NOT
    counted as automated coverage -- see `coverage_summary`.
    """

    AUTOMATED = "automated"
    ATTESTED = "attested"


class Method(str, Enum):
    """OSCAL assessment method."""

    TEST = "TEST"
    EXAMINE = "EXAMINE"
    INTERVIEW = "INTERVIEW"


class Scope(str, Enum):
    """Whether a check judges one subject or a population.

    Controls like ism-1689 ("Privileged user accounts cannot be used to log on
    to unprivileged operating environments") are statements about a *set*.
    Answering them from per-host facts alone and reporting satisfied is the most
    likely way this project becomes quietly wrong.
    """

    SUBJECT = "subject"
    AGGREGATE = "aggregate"


class EvidenceTier(str, Enum):
    """Whether obtaining the evidence has side effects."""

    PASSIVE = "passive"
    ACTIVE = "active"
    MUTATING = "mutating"


class UnassessedReason(str, Enum):
    """Why no determination was made. Never conflated with failure."""

    NOT_IMPLEMENTED = "not-implemented"
    OUT_OF_SCOPE = "out-of-scope"
    UNREACHABLE = "unreachable"
    INSUFFICIENT_PRIVILEGE = "insufficient-privilege"
    INSUFFICIENT_HISTORY = "insufficient-history"
    PARTIAL_POPULATION = "partial-population"
    UNSUPPORTED_PLATFORM = "unsupported-platform"
    COLLECTION_ERROR = "collection-error"
    REQUIRES_ATTESTATION = "requires-attestation"
    #: A check exists and works, but no subject it applies to was in the
    #: assessed set -- an Entra tenant check in a run covering only
    #: workstations, say. Distinct from EVALUATION_ERROR, which blames our own
    #: code, and from NOT_IMPLEMENTED, which says nobody has built it. Telling
    #: an operator their tooling failed when they simply did not include the
    #: platform sends them debugging the wrong thing.
    NO_SUBJECT_IN_SCOPE = "no-subject-in-scope"
    EVALUATION_ERROR = "evaluation-error"
    REQUIRES_INTERVIEW = "requires-interview"
    REQUIRES_EXTERNAL_SYSTEM = "requires-external-system"
    EVIDENCE_EXPIRED = "evidence-expired"
    DEFERRED_BY_POLICY = "deferred-by-policy"


@dataclass(frozen=True)
class Fact:
    """One raw observation about a subject. A fact is never a verdict."""

    key: str
    value: Any
    collected: dt.datetime
    source: str = ""
    #: True when collection succeeded but is known to be incomplete -- e.g. two
    #: of three user profile hives were readable. A partial fact must never
    #: produce `satisfied`; the missing part could be the failing one.
    partial: bool = False
    meta: dict[str, Any] = field(default_factory=dict)


class FactBundle:
    """Raw facts collected from one subject at one time.

    This is the durable, auditor-facing artefact. Verdicts are derived from it,
    off-host, by a pure function -- so evidence can be re-evaluated when ASD
    revises control text (111 statements were reworded in one quarter) without
    touching production again.
    """

    def __init__(
        self,
        subject: dict[str, Any],
        facts: dict[str, Fact],
        collected: dt.datetime,
        run_id: str = "",
        provenance: dict[str, Any] | None = None,
    ) -> None:
        self.subject = subject
        self._facts = facts
        self.collected = collected
        self.run_id = run_id
        self.provenance = provenance or {}

    def fact(self, key: str) -> Fact | None:
        """Return a fact, or None if it was never collected.

        Returning None rather than raising is deliberate: a missing fact is a
        normal condition that must produce `unassessed`, not an exception that
        might be caught somewhere unhelpful.
        """
        return self._facts.get(key)

    def require(self, *keys: str) -> CheckResult | None:
        """Guard for the common case: bail to unassessed if facts are missing.

        Returns None when every key is present and complete, otherwise the
        CheckResult the evaluator should return immediately.
        """
        missing = [k for k in keys if self._facts.get(k) is None]
        if missing:
            return CheckResult.unassessed(
                reason=UnassessedReason.COLLECTION_ERROR,
                detail="missing required fact(s): " + ", ".join(sorted(missing)),
            )
        incomplete = [k for k in keys if self._facts[k].partial]
        if incomplete:
            return CheckResult.unassessed(
                reason=UnassessedReason.PARTIAL_POPULATION,
                detail="incomplete fact(s): " + ", ".join(sorted(incomplete)),
            )
        return None

    @property
    def keys(self) -> list[str]:
        return sorted(self._facts)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FactBundle subject={self.subject.get('asset_id')!r} facts={len(self._facts)}>"


class FactHistory:
    """Read-only window over prior fact bundles for the same subject.

    Roughly a quarter of Essential Eight ML1 is temporal rather than stateful:
    ism-1690/1691/1694/1695/1876/1877 (patch windows) and
    ism-1698/1699/1701/1702/1807 (scan cadence). "Applied within 48 hours of
    release" cannot be answered by any single point-in-time observation, so the
    evaluator is given history rather than being left to fake it.
    """

    def __init__(self, bundles: Sequence[FactBundle], window_days: int = 0) -> None:
        self._bundles = sorted(bundles, key=lambda b: b.collected)
        self.window_days = window_days

    def __len__(self) -> int:
        return len(self._bundles)

    def spans(self, days: int) -> bool:
        """True when history actually covers `days`.

        A check whose window is not satisfiable must return
        `unassessed / insufficient-history` -- never `not-satisfied`. Absence of
        history is not evidence of non-compliance.
        """
        if days <= 0:
            return True
        if not self._bundles:
            return False
        span = self._bundles[-1].collected - self._bundles[0].collected
        return span >= dt.timedelta(days=days)

    def series(self, key: str) -> list[Fact]:
        """Every recorded value of one fact key, oldest first."""
        out = []
        for bundle in self._bundles:
            fact = bundle.fact(key)
            if fact is not None:
                out.append(fact)
        return out

    @classmethod
    def empty(cls) -> FactHistory:
        return cls([])


@dataclass(frozen=True)
class CheckResult:
    """The verdict for one check against one subject.

    Construct via the classmethods, never directly -- they are what keep the
    invariants true. In particular there is deliberately no way to produce
    `satisfied` without passing evidence.
    """

    status: Status
    detail: str
    confidence: Confidence | None = None
    reason: UnassessedReason | None = None
    facts: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def satisfied(
        cls,
        detail: str,
        facts: dict[str, Any],
        confidence: Confidence = Confidence.DIRECT,
    ) -> CheckResult:
        """Assert the control is met.

        `facts` is required and must be non-empty. Principle 1: no control is
        reported satisfied without a recorded observation supporting it. "The
        check did not error" is not evidence.
        """
        if not facts:
            raise ValueError(
                "CheckResult.satisfied() requires supporting facts: a verdict "
                "without a recorded observation is an assertion, not assurance"
            )
        return cls(status=Status.SATISFIED, detail=detail, confidence=confidence, facts=facts)

    @classmethod
    def not_satisfied(
        cls,
        detail: str,
        facts: dict[str, Any],
        confidence: Confidence = Confidence.DIRECT,
    ) -> CheckResult:
        if not facts:
            raise ValueError("CheckResult.not_satisfied() requires supporting facts")
        return cls(status=Status.NOT_SATISFIED, detail=detail, confidence=confidence, facts=facts)

    @classmethod
    def not_applicable(
        cls, detail: str, facts: dict[str, Any] | None = None
    ) -> CheckResult:
        """The control does not apply to this subject. Requires a justification."""
        if not detail.strip():
            raise ValueError("not_applicable() requires a justification")
        return cls(status=Status.NOT_APPLICABLE, detail=detail, facts=facts or {})

    @classmethod
    def unassessed(
        cls,
        reason: UnassessedReason,
        detail: str,
        facts: dict[str, Any] | None = None,
    ) -> CheckResult:
        """No determination was made, and why.

        This is the honest answer to an unreachable host, a missing privilege,
        an unsatisfiable history window or a partially-readable population.
        Reporting any of those as `not-satisfied` turns an operational failure
        into a compliance failure and trains people to ignore red.
        """
        return cls(
            status=Status.UNASSESSED, detail=detail, reason=reason, facts=facts or {}
        )

    @classmethod
    def error(cls, detail: str, facts: dict[str, Any] | None = None) -> CheckResult:
        return cls(
            status=Status.ERROR,
            detail=detail,
            reason=UnassessedReason.EVALUATION_ERROR,
            facts=facts or {},
        )

    def with_confidence_ceiling(self, ceiling: Confidence) -> CheckResult:
        """Apply the registry-declared ceiling. Can only weaken the claim."""
        if self.confidence is None:
            return self
        capped = self.confidence.capped_by(ceiling)
        if capped is self.confidence:
            return self
        return CheckResult(
            status=self.status,
            detail=self.detail,
            confidence=capped,
            reason=self.reason,
            facts=self.facts,
        )
