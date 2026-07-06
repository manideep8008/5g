"""Tests for the negotiation question grammar."""

import pytest

from network_a.negotiation.grammar import Grammar, GrammarError, load_grammar


@pytest.fixture()
def grammar() -> Grammar:
    return load_grammar()


def test_default_grammar_loads(grammar):
    assert grammar.version == 1
    assert grammar.budget_total == 100
    assert grammar.budget_window_sec == 3600
    assert len(grammar.predicates) == 8


def test_every_predicate_is_well_formed(grammar):
    for name, spec in grammar.predicates.items():
        assert spec.name == name
        assert spec.cost > 0
        assert len(spec.answers) >= 2, f"{name} must have a closed multi-outcome domain"
        assert len(set(spec.answers)) == len(spec.answers)
        assert spec.responder in {"trend", "anomaly", "behavioral"}


def test_validate_query_returns_spec(grammar):
    spec = grammar.validate_query("trend", {"facet": "auth_failures"})
    assert spec.cost == 10
    assert spec.responder == "trend"


def test_validate_query_no_arg_predicate(grammar):
    spec = grammar.validate_query("anomaly_status", {})
    assert spec.cost == 25


def test_unknown_predicate_rejected(grammar):
    with pytest.raises(GrammarError, match="unknown predicate"):
        grammar.validate_query("raw_features", {})


def test_bad_enum_arg_rejected(grammar):
    with pytest.raises(GrammarError, match="facet"):
        grammar.validate_query("trend", {"facet": "imsi"})


def test_missing_arg_rejected(grammar):
    with pytest.raises(GrammarError, match="missing"):
        grammar.validate_query("trend", {})


def test_unexpected_arg_rejected(grammar):
    with pytest.raises(GrammarError, match="unexpected"):
        grammar.validate_query("anomaly_status", {"facet": "auth_failures"})


def test_identifier_arg_accepted(grammar):
    spec = grammar.validate_query("resource_novelty", {"kind": "slice", "value": "eMBB"})
    assert spec.cost == 20


@pytest.mark.parametrize("value", ["", "has spaces", "semi;colon", "x" * 33])
def test_bad_identifier_rejected(grammar, value):
    with pytest.raises(GrammarError, match="value"):
        grammar.validate_query("resource_novelty", {"kind": "slice", "value": value})


def test_validate_answer_in_domain(grammar):
    grammar.validate_answer("trend", "decreasing")


def test_validate_answer_out_of_domain(grammar):
    with pytest.raises(GrammarError, match="not a valid answer"):
        grammar.validate_answer("trend", "0.42")


def test_validate_answer_unknown_predicate(grammar):
    with pytest.raises(GrammarError, match="unknown predicate"):
        grammar.validate_answer("raw_features", "anything")


def test_free_text_never_validates(grammar):
    """The egress property: no predicate accepts arbitrary text as an answer."""
    leak = "auth_failure_rate=0.2, imsi=001010000000001"
    for name in grammar.predicates:
        with pytest.raises(GrammarError):
            grammar.validate_answer(name, leak)
