"""Tests for HMAC pseudonymisation."""

from network_a.identity.identity_mapper import pseudonymise_imsi, verify_pseudonym


class TestUeHasher:
    def test_deterministic(self):
        p1 = pseudonymise_imsi("208950000000031")
        p2 = pseudonymise_imsi("208950000000031")
        assert p1 == p2

    def test_different_imsis_different_pseudonyms(self):
        p1 = pseudonymise_imsi("208950000000031")
        p2 = pseudonymise_imsi("208950000000032")
        assert p1 != p2

    def test_format(self):
        p = pseudonymise_imsi("208950000000031")
        assert p.startswith("UE_HASH_")
        assert len(p) == 20

    def test_verify_correct(self):
        p = pseudonymise_imsi("208950000000031")
        assert verify_pseudonym("208950000000031", p) is True

    def test_verify_wrong(self):
        p = pseudonymise_imsi("208950000000031")
        assert verify_pseudonym("208950000000032", p) is False
