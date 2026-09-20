"""OSCAL 1.1.2 emitters.

Documents are built as plain dictionaries rather than through a typed model
library. That is deliberate (ADR 0010): it keeps output byte-deterministic, so
the same facts always produce identical OSCAL and an auditor can re-derive a
published document and compare it.
"""

OSCAL_VERSION = "1.1.2"

#: Our extension namespace. Vocabulary is documented in docs/oscal-extensions.md.
#: OSCAL 1.1.2 cannot express "no determination was made", among other things.
NS = "https://nobytes.io/ns/oscal/cca/1.0"
