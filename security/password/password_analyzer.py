"""Password security analyzer — heuristic engine, pure standard library.

The analyzer scores a candidate password from 0 to 100 using layered
heuristics and returns a rich report: component scores, detected weaknesses,
estimated offline/online crack times, a criteria checklist (for the GUI) and
actionable recommendations.

Scoring model
-------------
* **Structure** — length and character-class diversity (up to 64 pts).
* **Entropy bonus** — estimated bits of entropy add up to +8.
* **Penalties** — dictionary/common passwords, leetspeak variants, keyboard
  walks, ascending/descending sequences, repeated characters and repeated
  blocks, date patterns, common suffixes.
* A password on the common list is capped at a very low score regardless of
  its other properties ("correct horse battery staple" style exceptions do
  not apply to the *embedded* list).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from core.constants import Severity
from core.utils import humanize_duration

# ---------------------------------------------------------------------------
# Embedded corpus — top passwords + frequent base words (small, dependency-free)
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = frozenset({
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567890",
    "1234567", "111111", "123123", "abc123", "1234", "password1", "iloveyou",
    "000000", "qwerty123", "1q2w3e4r", "admin", "qwertyuiop", "654321", "555555",
    "lovely", "7777777", "888888", "princess", "dragon", "sunshine", "master",
    "monkey", "shadow", "football", "baseball", "letmein", "welcome", "login",
    "solo", "flower", "hottie", "loveme", "zaq12wsx", "password123", "trustno1",
    "batman", "superman", "michael", "jennifer", "hunter", "buster", "soccer",
    "harley", "ranger", "buster1", "tigger", "purple", "george", "joshua",
    "summer", "ashley", "bailey", "passw0rd", "freedom", "whatever", "qazwsx",
    "starwars", "london", "gandalf", "matrix", "internet", "samsung", "corvette",
    "mercedes", "jackson", "daniel", "thomas", "hannah", "amanda", "cookie",
    "pepper", "chicken", "chocolate", "maggie", "diamond", "tigger1", "snoopy",
    "maverick", "compaq", "doctor", "dolphins", "nascar", "hockey", "fishing",
    "computer", "microsoft", "access", "bear", "johnny", "brandon", "william",
    "test123", "guest", "root", "toor", "changeme", "secret", "ninja", "azerty",
    "asdfgh", "zxcvbnm", "qwe123", "abcdef", "pussy", "696969", "apeshit",
    "hello", "hello123", "helloworld", "keyboard", "qwerty12", "google", "google1",
    "iphone", "samsung1", "pokemon", "minecraft", "fortnite", "gaming", "player1",
    "a1b2c3d4", "q1w2e3r4", "1qaz2wsx", "abcd1234", "1234qwer", "pass123",
    "admine", "administrateur", "administrator", "admin123",
    "admin@123", "root123", "toor123", "postgres", "oracle", "mysql", "mongo",
})

COMMON_BASE_WORDS = frozenset({
    "pass", "word", "admin", "user", "login", "welcome", "test", "abcd", "qwer",
    "asdf", "zxcv", "love", "star", "king", "queen", "cool", "fire", "water",
    "earth", "wind", "snow", "moon", "gold", "silver", "iron", "super", "mega",
    "cyber", "secure", "secret", "money", "house", "school", "work", "game",
})

KEYBOARD_ROWS = (
    "`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
    "~!@#$%^&*()_+", "1qaz2wsx3edc", "qazwsxedc", "zaq1xsw2", "1q2w3e4r5t",
)

COMMON_SUFFIXES = ("!", "!!", "?", ".", "123", "1234", "2023", "2024", "2025", "2026", "#1")

SEQUENCE_ALPHABETS = ("abcdefghijklmnopqrstuvwxyz", "0123456789")


@dataclass
class Finding:
    code: str
    message: str
    penalty: int

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "penalty": self.penalty}


@dataclass
class PasswordAnalysis:
    """Full analysis result for one password (never contains the password)."""

    score: int = 0
    verdict: str = "CRITICAL"
    verdict_severity: Severity = Severity.CRITICAL
    length: int = 0
    charset_pool: int = 0
    entropy_bits: float = 0.0
    char_classes: dict = field(default_factory=dict)
    component_scores: dict = field(default_factory=dict)
    criteria: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    crack_time_offline: str = ""
    crack_time_online: str = ""
    is_common: bool = False

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "verdict_severity": self.verdict_severity.value,
            "length": self.length,
            "charset_pool": self.charset_pool,
            "entropy_bits": round(self.entropy_bits, 1),
            "char_classes": self.char_classes,
            "component_scores": self.component_scores,
            "criteria": self.criteria,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
            "crack_time_offline": self.crack_time_offline,
            "crack_time_online": self.crack_time_online,
            "is_common": self.is_common,
        }


class PasswordAnalyzer:
    """Stateless analyzer — one instance can be shared across threads."""

    OFFLINE_GUESSES_PER_SECOND = 10_000_000_000    # strong offline attack (GPU rig)
    ONLINE_GUESSES_PER_SECOND = 1_000              # throttled online attacks

    # --------------------------------------------------------------- public

    def analyze(self, password: str) -> PasswordAnalysis:
        result = PasswordAnalysis(length=len(password or ""))

        if not password:
            result.verdict = "CRITICAL"
            result.findings.append(Finding("empty", "The password is empty.", 100))
            result.recommendations.append("Choose a password of at least 12 characters mixing all character types.")
            return result

        classes = self._char_classes(password)
        result.char_classes = classes
        pool = self._charset_pool(classes)
        result.charset_pool = pool
        result.entropy_bits = len(password) * (math.log2(pool) if pool > 1 else 0.0)
        result.is_common = password.lower() in COMMON_PASSWORDS

        findings: list[Finding] = []
        findings += self._check_common(password)
        findings += self._check_sequences(password)
        findings += self._check_keyboard(password)
        findings += self._check_repetition(password)
        findings += self._check_dates(password)
        findings += self._check_suffix(password)
        findings += self._check_composition(password, classes)
        result.findings = findings

        structure = self._structure_score(len(password), classes)
        entropy_bonus = self._entropy_bonus(result.entropy_bits)
        penalty = sum(f.penalty for f in findings)
        score = int(max(0, min(100, structure + entropy_bonus - penalty)))
        if result.is_common:
            score = min(score, 5)
        result.component_scores = {
            "structure": structure,
            "entropy_bonus": entropy_bonus,
            "penalties": penalty,
        }
        result.score = score

        result.verdict, result.verdict_severity = self._verdict(score)
        result.criteria = self._criteria(password, classes, findings)
        result.crack_time_offline = self._crack_time(pool, len(password), self.OFFLINE_GUESSES_PER_SECOND)
        result.crack_time_online = self._crack_time(pool, len(password), self.ONLINE_GUESSES_PER_SECOND)
        result.recommendations = self._recommendations(result, findings)
        return result

    # ----------------------------------------------------------- components

    @staticmethod
    def _char_classes(password: str) -> dict[str, int]:
        return {
            "lower": sum(1 for c in password if c.islower()),
            "upper": sum(1 for c in password if c.isupper()),
            "digits": sum(1 for c in password if c.isdigit()),
            "special": sum(1 for c in password if not c.isalnum()),
        }

    @staticmethod
    def _charset_pool(classes: dict[str, int]) -> int:
        pool = 0
        if classes["lower"]:
            pool += 26
        if classes["upper"]:
            pool += 26
        if classes["digits"]:
            pool += 10
        if classes["special"]:
            pool += 33
        return max(pool, 1)

    def _structure_score(self, length: int, classes: dict[str, int]) -> int:
        length_score = min(30, length * 2.5)
        diversity = 0
        diversity += 7 if classes["lower"] else 0
        diversity += 9 if classes["upper"] else 0
        diversity += 8 if classes["digits"] else 0
        diversity += 10 if classes["special"] else 0
        used = sum(1 for v in classes.values() if v > 0)
        if used >= 3:
            diversity += 5
        if used == 4:
            diversity += 3
        return int(min(64, length_score + min(34, diversity)))

    @staticmethod
    def _entropy_bonus(bits: float) -> int:
        if bits >= 80:
            return 8
        if bits >= 60:
            return 6
        if bits >= 45:
            return 3
        return 0

    # ------------------------------------------------------------ detectors

    def _check_common(self, password: str) -> list[Finding]:
        findings = []
        lowered = password.lower()
        if lowered in COMMON_PASSWORDS:
            findings.append(Finding("common", "This password appears on the common-password list.", 60))
            return findings
        stripped = re.sub(r"[0-9!@#$%^&*._-]+", "", lowered)
        if stripped in COMMON_PASSWORDS and len(stripped) >= 4:
            findings.append(Finding(
                "common-base", f"Based on the common password '{stripped}'.", 30))
        elif stripped in COMMON_BASE_WORDS and len(stripped) <= 8 and len(lowered) <= 12:
            findings.append(Finding(
                "weak-word", f"Built around the predictable word '{stripped}'.", 15))
        if self._is_leet(lowered):
            plain = self._deleet(lowered)
            if plain in COMMON_PASSWORDS:
                findings.append(Finding(
                    "leet-common",
                    f"Leetspeak variant of the common password '{plain}' — easily cracked.", 35))
        return findings

    @staticmethod
    def _is_leet(text: str) -> bool:
        return any(ch in text for ch in "@$!0317") and any(ch.isdigit() for ch in text)

    @staticmethod
    def _deleet(text: str) -> str:
        table = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                               "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
        return text.translate(table)

    def _check_sequences(self, password: str) -> list[Finding]:
        lowered = password.lower()
        findings = []
        for alphabet in SEQUENCE_ALPHABETS:
            runs = self._find_runs(lowered, alphabet, min_run=3)
            for run in runs:
                findings.append(Finding(
                    "sequence",
                    f"Contains the {'descending' if run[2] else 'ascending'} sequence '{run[0]}'.",
                    12))
        return findings

    @staticmethod
    def _find_runs(text: str, alphabet: str, min_run: int = 3) -> list[tuple[str, int, bool]]:
        runs = []
        n = len(text)
        i = 0
        while i < n:
            if text[i] in alphabet:
                # ascending run
                j = i + 1
                while j < n and j - i < 8 and text[j] in alphabet and \
                        alphabet.index(text[j]) == alphabet.index(text[j - 1]) + 1:
                    j += 1
                if j - i >= min_run:
                    runs.append((text[i:j], j - i, False))
                    i = j
                    continue
                # descending run
                j = i + 1
                while j < n and j - i < 8 and text[j] in alphabet and \
                        alphabet.index(text[j]) == alphabet.index(text[j - 1]) - 1:
                    j += 1
                if j - i >= min_run:
                    runs.append((text[i:j], j - i, True))
                    i = j
                    continue
            i += 1
        return runs

    def _check_keyboard(self, password: str) -> list[Finding]:
        lowered = password.lower()
        findings = []
        for row in KEYBOARD_ROWS:
            for size in (4, 3):
                for start in range(0, len(row) - size + 1):
                    chunk = row[start:start + size]
                    if chunk in lowered:
                        findings.append(Finding(
                            "keyboard",
                            f"Follows a keyboard walk pattern ('{chunk}').", 14))
                        size = 0
                        break
                if size == 0:
                    break
        return findings

    def _check_repetition(self, password: str) -> list[Finding]:
        findings = []
        # repeated single characters: 'aaa'
        for match in re.finditer(r"(.)\1{2,}", password):
            findings.append(Finding(
                "repeat-chars", f"Character '{match.group(1)}' repeated {len(match.group(0))} times.", 8))
        # repeated blocks: 'abcabc' or '121212'
        lowered = password.lower()
        for block_size in range(1, 5):
            for start in range(0, len(lowered) - block_size * 2 + 1):
                block = lowered[start:start + block_size]
                if block_size == 1 and block in ("_", "-"):
                    continue
                rest = lowered[start + block_size:]
                count = 0
                cursor = 0
                while rest[cursor:cursor + block_size] == block:
                    count += 1
                    cursor += block_size
                if count >= 1 and (count + 1) * block_size >= max(4, block_size * 2):
                    findings.append(Finding(
                        "repeat-block",
                        f"Block '{block}' repeats {count + 1} times in a row.", 12))
                    break
        return findings

    def _check_dates(self, password: str) -> list[Finding]:
        findings = []
        for match in re.finditer(r"(19|20)\d{2}", password):
            year = match.group(0)
            if 1900 <= int(year) <= 2030:
                findings.append(Finding(
                    "date-year", f"Contains a year ('{year}') — a very predictable pattern.", 8))
                break
        return findings

    def _check_suffix(self, password: str) -> list[Finding]:
        lowered = password.lower()
        findings: list[Finding] = []
        if lowered in COMMON_PASSWORDS:
            return findings
        for suffix in COMMON_SUFFIXES:
            base = lowered[: -len(suffix)] if lowered.endswith(suffix) and len(lowered) > len(suffix) else None
            if base and base in COMMON_BASE_WORDS | {"admin", "root", "login", "pass", "welcome"}:
                findings.append(Finding(
                    "predictable-suffix",
                    f"Ends with the predictable '{suffix}'.", 10))
                break
        return findings

    def _check_composition(self, password: str, classes: dict[str, int]) -> list[Finding]:
        findings = []
        if len(password) < 8:
            findings.append(Finding("short", "Shorter than the 8-character minimum.", 25))
        elif len(password) < 12:
            findings.append(Finding(
                "short-ish", "Under 12 characters — length is the strongest defence.", 8))
        used = sum(1 for v in classes.values() if v > 0)
        if used <= 2:
            findings.append(Finding(
                "low-diversity", "Uses only two character types or fewer.", 12))
        if classes["lower"] == len(password):
            findings.append(Finding("all-lower", "Entirely lowercase letters.", 10))
        return findings

    # ------------------------------------------------------------- verdicts

    @staticmethod
    def _verdict(score: int) -> tuple[str, Severity]:
        if score < 20:
            return "CRITICAL", Severity.CRITICAL
        if score < 40:
            return "WEAK", Severity.HIGH
        if score < 60:
            return "FAIR", Severity.MEDIUM
        if score < 80:
            return "GOOD", Severity.LOW
        return "STRONG", Severity.INFO

    @staticmethod
    def _criteria(password: str, classes: dict[str, int], findings: list[Finding]) -> dict[str, bool]:
        codes = {f.code for f in findings}
        return {
            "length_12_plus": len(password) >= 12,
            "length_8_plus": len(password) >= 8,
            "has_lower": classes["lower"] > 0,
            "has_upper": classes["upper"] > 0,
            "has_digit": classes["digits"] > 0,
            "has_special": classes["special"] > 0,
            "no_sequences": "sequence" not in codes,
            "no_repeats": not ({"repeat-chars", "repeat-block"} & codes),
            "not_common": not ({"common", "common-base", "leet-common"} & codes),
            "no_keyboard_patterns": "keyboard" not in codes,
        }

    def _crack_time(self, pool: int, length: int, guesses_per_second: int) -> str:
        if length == 0 or pool <= 1:
            return "instantly"
        combinations = pool ** length
        seconds = combinations / 2 / guesses_per_second
        return humanize_duration(seconds)

    @staticmethod
    def _recommendations(result: PasswordAnalysis, findings: list[Finding]) -> list[str]:
        recs = []
        codes = {f.code for f in findings}
        if result.length < 12:
            recs.append("Increase length to 12+ characters — every extra character multiplies the attack cost.")
        if result.char_classes.get("upper", 0) == 0 or result.char_classes.get("special", 0) == 0 \
                or result.char_classes.get("digits", 0) == 0:
            recs.append("Mix uppercase, digits and symbols with lowercase letters.")
        if {"sequence", "keyboard"} & codes:
            recs.append("Avoid keyboard walks and letter/number sequences — crackers try them first.")
        if {"repeat-chars", "repeat-block"} & codes:
            recs.append("Remove repeated characters or repeated blocks.")
        if {"common", "common-base", "leet-common", "weak-word"} & codes:
            recs.append("Choose a phrase nobody has used before; consider a 4-word passphrase.")
        if "date-year" in codes or "predictable-suffix" in codes:
            recs.append("Drop years and predictable endings — attackers append and substitute them automatically.")
        if result.entropy_bits < 45:
            recs.append("Target 60+ bits of entropy: a long, varied passphrase beats a short complex word.")
        if not recs:
            recs.append("Excellent. Keep it unique per site and store it in a password manager; "
                        "enable multi-factor authentication where possible.")
        return recs
