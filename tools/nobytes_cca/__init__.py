"""nobytes_cca -- continuous compliance assessment evaluator and OSCAL emitters.

Runtime dependencies: the standard library plus PyYAML, which ansible-core
itself requires and is therefore present in every execution environment by
construction (ADR 0011). Python 3.9 syntax, so this runs inside ee-legacy as
well as ee-current (ADR 0007).

Evaluators are pure functions. No network, no subprocess -- enforced by tests,
not by convention. That purity is what makes evidence re-evaluatable and OSCAL
output byte-deterministic.
"""

__version__ = "0.1.0"
