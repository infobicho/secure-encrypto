"""
Tests for secure_encrypto.utils.password_strength
===================================================
Covers:
  - Common passwords get penalised
  - Entropy grows with length and charset
  - Score 0-100 bounds
  - Short / empty passwords
  - Repeated characters penalty
  - Sequential patterns penalty
  - generate_password produces a strong password
"""

import math
import pytest

from secure_encrypto.utils.password_strength import (
    check_strength,
    generate_password,
    COMMON_PASSWORDS,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _score(pw: str) -> int:
    return check_strength(pw).score


def _entropy(pw: str) -> float:
    return check_strength(pw).entropy


# ─── Empty / short ────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_password_score_zero(self):
        r = check_strength("")
        assert r.score == 0
        assert r.level == "Vide"

    def test_single_char_very_weak(self):
        r = check_strength("a")
        assert r.score <= 10

    def test_short_password_feedback(self):
        r = check_strength("abc")
        assert any("court" in f.lower() or "12" in f for f in r.feedback)

    def test_score_clamp_min(self):
        assert _score("") == 0

    def test_score_clamp_max(self):
        # Even a perfect password must not exceed 100
        assert _score("Xk#9mP!qLz@7wRv$2nJc") <= 100


# ─── Common passwords ─────────────────────────────────────────────────────────

class TestCommonPasswords:
    @pytest.mark.parametrize("pw", ["password", "123456", "qwerty", "azerty", "letmein"])
    def test_common_password_penalised(self, pw):
        r = check_strength(pw)
        assert r.score < 30, f"Expected low score for common password '{pw}', got {r.score}"
        assert any("commun" in f.lower() or "⚠️" in f for f in r.feedback)

    def test_common_password_case_insensitive(self):
        # "PASSWORD" should match "password" in the common set
        r_lower = check_strength("password")
        r_upper = check_strength("PASSWORD")
        assert r_lower.score < 30
        assert r_upper.score < 30


# ─── Entropy ──────────────────────────────────────────────────────────────────

class TestEntropy:
    def test_longer_password_higher_entropy(self):
        short = _entropy("aA1!")
        long  = _entropy("aA1!" * 5)
        assert long > short

    def test_wider_charset_higher_entropy(self):
        lower_only   = _entropy("aaaaaaaaaaaaaaaa")
        mixed        = _entropy("aA1!aA1!aA1!aA1!")
        assert mixed > lower_only

    def test_entropy_positive(self):
        assert _entropy("SomePassword1!") > 0

    def test_entropy_formula(self):
        # All lowercase: charset=26
        pw = "abcdefghij"
        expected = len(pw) * math.log2(26)
        assert abs(_entropy(pw) - expected) < 1e-6


# ─── Diversity scoring ────────────────────────────────────────────────────────

class TestDiversity:
    def test_all_four_types_no_missing_feedback(self):
        r = check_strength("Abc1!Xyz2@def3#ghi4$")
        missing = [f for f in r.feedback if "Ajoutez" in f]
        assert missing == []

    def test_missing_upper_feedback(self):
        r = check_strength("abc1!xyz2@")
        assert any("majuscules" in f for f in r.feedback)

    def test_missing_lower_feedback(self):
        r = check_strength("ABC1!XYZ2@")
        assert any("minuscules" in f for f in r.feedback)

    def test_missing_digit_feedback(self):
        r = check_strength("AbcXyz!@#")
        assert any("chiffres" in f for f in r.feedback)

    def test_missing_special_feedback(self):
        r = check_strength("AbcXyz123")
        assert any("spéciaux" in f or "speciaux" in f.lower() or "spéc" in f for f in r.feedback)


# ─── Penalties ────────────────────────────────────────────────────────────────

class TestPenalties:
    def test_repeated_chars_penalty(self):
        normal = _score("Abc1!XyzWqr2")
        repeat = _score("Abc1!aaaaaaa")
        assert repeat < normal

    def test_sequential_pattern_penalty(self):
        normal     = _score("Xm9@Bv7!Wd5#")
        sequential = _score("abcABC123!!!")
        assert sequential < normal

    def test_feedback_for_repeated_chars(self):
        r = check_strength("aaaaaaBBBBB1!")
        assert any("répét" in f.lower() or "consécutif" in f.lower() for f in r.feedback)

    def test_feedback_for_sequential(self):
        r = check_strength("abcdefg12345!X")
        assert any("séquence" in f.lower() or "prévisible" in f.lower() for f in r.feedback)


# ─── Score levels ─────────────────────────────────────────────────────────────

class TestScoreLevels:
    def test_very_strong_level(self):
        r = check_strength("Xk#9mP!qLz@7wRv$2nJc")
        assert r.score >= 80
        assert "fort" in r.level.lower()

    def test_very_weak_level(self):
        r = check_strength("a")
        assert r.score <= 20
        assert "faible" in r.level.lower()

    def test_color_is_hex(self):
        r = check_strength("Test1!")
        assert r.color.startswith("#")
        assert len(r.color) == 7


# ─── Feedback deduplication ───────────────────────────────────────────────────

class TestFeedbackDedup:
    def test_no_duplicate_feedback(self):
        r = check_strength("abcabcabcabc123")
        assert len(r.feedback) == len(set(r.feedback))


# ─── generate_password ────────────────────────────────────────────────────────

class TestGeneratePassword:
    def test_generates_strong_password(self):
        pw = generate_password()
        assert _score(pw) >= 80

    def test_default_length(self):
        pw = generate_password()
        assert len(pw) >= 20

    def test_custom_length(self):
        pw = generate_password(length=32)
        assert len(pw) == 32

    def test_no_special_chars(self):
        pw = generate_password(length=20, use_special=False)
        import string
        allowed = set(string.ascii_letters + string.digits)
        assert all(c in allowed for c in pw)

    def test_multiple_calls_differ(self):
        pws = {generate_password() for _ in range(5)}
        assert len(pws) >= 4, "Expected passwords to be unique across calls"
