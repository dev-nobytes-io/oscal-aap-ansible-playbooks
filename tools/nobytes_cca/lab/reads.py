"""What key names do the evaluators actually read off a fact value?

This is the third leg of the lab comparison, and the one nothing in the
repository extracted before. PR 17 shipped `browsers.py` reading `display_name`
where `Get-InstalledApplications.ps1` emits `name`: every real host would have
found zero browsers forever, while the tests passed because the fixtures had
been written from the same wrong assumption as the code.

Comparing a lab digest against the fixtures cannot catch that -- both sides
would be missing `display_name` equally, and a diff of two artefacts written
from one assumption is exactly the defect. So the evaluators' own read set has
to be a third, independent input.

A plain scrape of every `.get("x")` in the package would be useless: the
evaluators also read params (`in_scope_apps`), build their own facts dicts
(`office_installed`) and index unrelated mappings. So this walks the AST and
tracks which expressions are derived from `bundle.fact(...)`, reporting only the
keys read off THOSE. One level of helper-function propagation is handled,
because the real code does `_applocker(fact.value)`.

Stdlib only, Python 3.9 compatible -- it is vendored into both execution
environments with the rest of the package. See ADR 0007.
"""

from __future__ import annotations

import ast
from pathlib import Path


def _literal(node) -> str:
    """The string constant a subscript or .get() argument names, or ''."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


class _FactReadVisitor(ast.NodeVisitor):
    """Collect key names read off values derived from `bundle.fact(...)`."""

    def __init__(self, fact_derived_params=None):
        # Names in this scope known to hold a fact, a fact value, or something
        # reached from one.
        self.derived = set(fact_derived_params or ())
        self.reads = set()
        #: every `bundle.fact("...")` literal seen in this scope. Reads are
        #: attributed to these, so the diff can scope a hard failure to facts
        #: the lab digest actually carries: an Entra key read off an Entra fact
        #: is not a finding against a Windows domain controller.
        self.fact_keys = set()
        #: helper function name -> the argument positions that received a
        #: fact-derived expression at some call site in this module.
        self.helper_args = {}

    # -- recognising fact-derived expressions ------------------------------

    def _is_derived(self, node) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.derived
        if isinstance(node, ast.Call):
            func = node.func
            # bundle.fact("...")
            if isinstance(func, ast.Attribute) and func.attr == "fact":
                return True
            # <derived>.get("...") returns something still fact-derived
            if isinstance(func, ast.Attribute) and func.attr == "get":
                return self._is_derived(func.value)
            return False
        if isinstance(node, ast.Attribute):
            # fact.value / fact.meta stay derived; anything else off a derived
            # base does too, which is deliberately generous.
            return self._is_derived(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_derived(node.value)
        if isinstance(node, (ast.BoolOp, ast.IfExp)):
            parts = node.values if isinstance(node, ast.BoolOp) else [node.body, node.orelse]
            return any(self._is_derived(p) for p in parts)
        return False

    # -- traversal ---------------------------------------------------------

    def visit_Assign(self, node) -> None:
        if self._is_derived(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.derived.add(target.id)
                elif isinstance(target, ast.Tuple):
                    # fact, failure = _guard(bundle)  -- the repo's guard idiom
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.derived.add(elt.id)
        self.generic_visit(node)

    def visit_For(self, node) -> None:
        # `for row in policy.value:` makes `row` fact-derived.
        if self._is_derived(node.iter) and isinstance(node.target, ast.Name):
            self.derived.add(node.target.id)
        self.generic_visit(node)

    def visit_comprehension(self, node) -> None:  # pragma: no cover - via generic_visit
        if self._is_derived(node.iter) and isinstance(node.target, ast.Name):
            self.derived.add(node.target.id)
        self.generic_visit(node)

    def _note_comprehension_targets(self, node) -> None:
        for gen in getattr(node, "generators", []):
            if self._is_derived(gen.iter) and isinstance(gen.target, ast.Name):
                self.derived.add(gen.target.id)

    def visit_ListComp(self, node) -> None:
        self._note_comprehension_targets(node)
        self.generic_visit(node)

    def visit_SetComp(self, node) -> None:
        self._note_comprehension_targets(node)
        self.generic_visit(node)

    def visit_DictComp(self, node) -> None:
        self._note_comprehension_targets(node)
        self.generic_visit(node)

    def visit_GeneratorExp(self, node) -> None:
        self._note_comprehension_targets(node)
        self.generic_visit(node)

    def visit_Call(self, node) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "fact" and node.args:
            literal = _literal(node.args[0])
            if literal:
                self.fact_keys.add(literal)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and node.args
            and self._is_derived(func.value)
        ):
            key = _literal(node.args[0])
            if key:
                self.reads.add(key)
        # Record which helper functions receive fact-derived arguments, so a
        # second pass can treat those parameters as derived.
        if isinstance(func, ast.Name):
            for index, arg in enumerate(node.args):
                if self._is_derived(arg):
                    self.helper_args.setdefault(func.id, set()).add(index)
        self.generic_visit(node)

    def visit_Subscript(self, node) -> None:
        if self._is_derived(node.value):
            key = _literal(node.slice)
            if key:
                self.reads.add(key)
        self.generic_visit(node)


def reads_in_source(source: str):
    """Return (reads, fact_keys) for one module's source.

    `reads` is the set of key names read off fact-derived values. `fact_keys` is
    the set of fact keys the module reaches for. They are related at MODULE
    granularity, not per read: attributing a read to one specific fact would
    need real dataflow, and over-claiming precision here would be worse than
    stating the coarser truth.
    """
    tree = ast.parse(source)

    # Pass one: module- and function-level, learning which helpers are handed a
    # fact-derived argument.
    first = _FactReadVisitor()
    first.visit(tree)
    reads = set(first.reads)
    fact_keys = set(first.fact_keys)
    helper_args = dict(first.helper_args)

    # Pass two: re-walk each helper that received a fact-derived argument, with
    # the matching parameters seeded as derived. One level only -- enough for
    # `_applocker(fact.value)` and `_wdac(fact.value)`, which is what the code
    # actually does, and shallow enough to stay predictable.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        positions = helper_args.get(node.name)
        if not positions:
            continue
        params = [a.arg for a in node.args.args]
        seeded = {params[i] for i in positions if i < len(params)}
        if not seeded:
            continue
        inner = _FactReadVisitor(fact_derived_params=seeded)
        for stmt in node.body:
            inner.visit(stmt)
        reads |= inner.reads
        fact_keys |= inner.fact_keys

    return reads, fact_keys


def reads_in_package(checks_dir: Path) -> dict:
    """key name -> {"files": [...], "facts": [...]}.

    `facts` lists the fact keys the reading module reaches for, so a consumer
    can scope a finding to the facts a given lab run actually carries.
    """
    out: dict = {}
    for path in sorted(Path(checks_dir).rglob("*.py")):
        if path.name == "__init__.py":
            continue
        reads, fact_keys = reads_in_source(path.read_text(encoding="utf-8"))
        for key in reads:
            entry = out.setdefault(key, {"files": set(), "facts": set()})
            entry["files"].add(path.name)
            entry["facts"] |= fact_keys
    return {
        key: {"files": sorted(v["files"]), "facts": sorted(v["facts"])}
        for key, v in sorted(out.items())
    }
