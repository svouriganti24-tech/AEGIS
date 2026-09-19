"""Tests for the password security analyzer."""

from __future__ import annotations

import unittest

from tests.helpers import PROJECT_ROOT  # noqa: F401  (path setup)
from security.password.password_analyzer import PasswordAnalyzer


class PasswordScoringTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def analyze(self, password):
        return self.analyzer.analyze(password)

    # ------------------------------------------------------------ boundaries

    def test_empty_password_is_critical(self):
        result = self.analyze("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.verdict, "CRITICAL")
        self.assertTrue(result.recommendations)

    def test_score_within_bounds(self):
        for password in ("a", "abcdefgh", "Str0ng!Passphrase#2026", "x" * 64):
            result = self.analyze(password)
            self.assertTrue(0 <= result.score <= 100, f"score out of bounds for {password!r}")

    def test_monotonic_length_bonus(self):
        # No sequences / repeats in either string so only structure differs.
        short = self.analyze("G7k!p").score
        longer = self.analyze("G7k!p9Wm#x").score
        self.assertGreater(longer, short)

    # ----------------------------------------------------------- detection

    def test_common_password_flagged(self):
        result = self.analyze("qwerty")
        self.assertTrue(result.is_common)
        self.assertLessEqual(result.score, 5)
        codes = {f.code for f in result.findings}
        self.assertIn("common", codes)

    def test_leetspeak_common_detected(self):
        result = self.analyze("p@ssw0rd")
        codes = {f.code for f in result.findings}
        self.assertIn("leet-common", codes)

    def test_sequence_detection(self):
        result = self.analyze("Xabc123Q")
        codes = {f.code for f in result.findings}
        self.assertIn("sequence", codes)

    def test_keyboard_walk_detection(self):
        result = self.analyze("Myqwerty9")
        codes = {f.code for f in result.findings}
        self.assertIn("keyboard", codes)

    def test_repetition_detection(self):
        result = self.analyze("ZaaaaaQ7")
        codes = {f.code for f in result.findings}
        self.assertIn("repeat-chars", codes)

    def test_date_year_detection(self):
        result = self.analyze("Summer2024!")
        codes = {f.code for f in result.findings}
        self.assertIn("date-year", codes)

    # ---------------------------------------------------------- verdicts

    def test_weak_password_low_score(self):
        self.assertLess(self.analyze("password1").score, 30)

    def test_strong_passphrase_high_score(self):
        result = self.analyze("Mango-Vanilla-Turbine-88!")
        self.assertGreaterEqual(result.score, 70)
        self.assertIn(result.verdict, ("GOOD", "STRONG"))
        self.assertFalse(result.is_common)

    def test_verdict_severity_mapping(self):
        self.assertEqual(self.analyze("").verdict_severity.value, "CRITICAL")
        self.assertEqual(self.analyze("Mango-Vanilla-Turbine-88!").verdict_severity.value, "LOW")

    # ------------------------------------------------------- rich metadata

    def test_criteria_checklist_present(self):
        result = self.analyze("Abcdef1!")
        for key in ("has_upper", "has_digit", "has_special", "not_common", "length_8_plus"):
            self.assertIn(key, result.criteria)

    def test_recommendations_always_present(self):
        for password in ("", "x", "Str0ng!Passphrase#2026"):
            result = self.analyze(password)
            self.assertTrue(result.recommendations)

    def test_crack_time_format(self):
        result = self.analyze("Abcdef1!")
        self.assertTrue(result.crack_time_offline)
        self.assertTrue(result.crack_time_online)
        self.assertNotEqual(result.crack_time_offline, "")

    def test_entropy_scales_with_charset(self):
        low = self.analyze("aaaaaaaaaaaa")     # single class
        high = self.analyze("Aa1!aaaaaaaaaa")  # four classes
        self.assertGreater(high.entropy_bits, low.entropy_bits)

    def test_analysis_never_contains_password(self):
        secret = "SuperSecret#2026"
        dump = repr(self.analyze(secret).to_dict())
        self.assertNotIn(secret, dump)


if __name__ == "__main__":
    unittest.main()
