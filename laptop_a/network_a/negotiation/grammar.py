"""Question grammar: the closed allowlist of predicates Network B may ask.

Loaded from config/grammar.yaml. A query that fails validation here must be
rejected at the boundary without touching evidence or the budget; an answer
that fails validation here must never leave Network A.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "grammar.yaml"

# Sentinel arg type for caller-supplied names (slice/DNN identifiers).
IDENTIFIER = "identifier"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

ResponderName = Literal["trend", "anomaly", "behavioral"]


class GrammarError(ValueError):
    """A query or answer falls outside the grammar."""


class PredicateSpec(BaseModel):
    name: str
    args: dict[str, list[str] | Literal["identifier"]] = Field(default_factory=dict)
    answers: list[str] = Field(min_length=2)
    cost: int = Field(gt=0)
    responder: ResponderName


class Grammar(BaseModel):
    version: int
    budget_total: int = Field(gt=0)
    budget_window_sec: int = Field(gt=0)
    predicates: dict[str, PredicateSpec]

    def validate_query(self, predicate: str, args: dict[str, str]) -> PredicateSpec:
        """Check a query against the grammar; return its spec or raise GrammarError."""
        spec = self.predicates.get(predicate)
        if spec is None:
            raise GrammarError(f"unknown predicate '{predicate}'")

        missing = spec.args.keys() - args.keys()
        if missing:
            raise GrammarError(f"missing args for '{predicate}': {sorted(missing)}")
        unexpected = args.keys() - spec.args.keys()
        if unexpected:
            raise GrammarError(f"unexpected args for '{predicate}': {sorted(unexpected)}")

        for arg_name, allowed in spec.args.items():
            value = args[arg_name]
            if allowed == IDENTIFIER:
                if not _IDENTIFIER_RE.match(value):
                    raise GrammarError(f"arg '{arg_name}' is not a valid identifier")
            elif value not in allowed:
                raise GrammarError(f"arg '{arg_name}' must be one of {allowed}, got '{value}'")

        return spec

    def validate_answer(self, predicate: str, answer: str) -> None:
        """Egress check: an answer must be in the predicate's declared domain."""
        spec = self.predicates.get(predicate)
        if spec is None:
            raise GrammarError(f"unknown predicate '{predicate}'")
        if answer not in spec.answers:
            raise GrammarError(
                f"'{answer}' is not a valid answer for '{predicate}' "
                f"(domain: {spec.answers})"
            )


@functools.lru_cache(maxsize=1)
def load_grammar(config_path: Path | None = None) -> Grammar:
    """Load and validate the grammar from config (cached per process)."""
    path = config_path or _CONFIG_PATH
    with open(path) as f:
        cfg = yaml.safe_load(f)

    predicates = {
        name: PredicateSpec(name=name, **body)
        for name, body in cfg["predicates"].items()
    }
    return Grammar(
        version=cfg["version"],
        budget_total=cfg["budget"]["total"],
        budget_window_sec=cfg["budget"]["window_sec"],
        predicates=predicates,
    )
