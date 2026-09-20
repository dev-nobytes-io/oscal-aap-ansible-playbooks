# Derived OSCAL profiles

Baseline selections authored by this project.

ASD already publishes profiles **and pre-resolved profile catalogs** for every
classification (NON_CLASSIFIED, OFFICIAL_SENSITIVE, PROTECTED, SECRET,
TOP_SECRET) and every Essential Eight maturity level (ML1/ML2/ML3). Those ship
in `../upstream/` and are used directly — this project does not re-derive them.

Only genuinely new selections belong here: scope-narrowed baselines, an
estate-specific subset, or an intersection ASD does not publish.

Worth knowing: intersecting the Essential Eight with a classification is a
no-op. All 46 ML1 controls carry applicability for every classification from
NON_CLASSIFIED to TOP SECRET, so "ML1 for OFFICIAL" is simply ML1.
