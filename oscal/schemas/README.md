# NIST OSCAL JSON schemas (pinned)

Vendored copies of the OSCAL **1.1.2** JSON schemas, so validation works with
no internet egress — the normal condition for government build environments.

Upstream publishes these as GitHub **release assets**:
`https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_<model>_schema.json`
(the `raw.githubusercontent.com/.../json/schema/` and `pages.nist.gov` paths
return 404; do not wire those into CI).

**A trap worth knowing before debugging it:** these schemas use `\p{...}`
Unicode-property regexes, which Python's stdlib `re` cannot compile. Stock
`jsonschema` does not fail cleanly on them — it raises
`re.error: bad escape \p` and crashes. The validator in `tools/` overrides the
`pattern` keyword to use the `regex` module instead.
