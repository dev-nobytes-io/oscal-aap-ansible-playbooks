"""Human-readable reports derived from the emitted OSCAL documents.

The OSCAL is the substrate; this is what people actually read. Standard library
only, like the rest of the package (ADR 0007) -- Markdown and HTML need nothing
else, and keeping it here means a report can be produced inside an execution
environment in an enclave with no extra wheels.

Document formats that DO need third-party libraries -- the SSP Annex xlsx, the
Essential Eight docx -- are a separate concern and do not live here.
"""
