"""
core/entropy.py
Mathematical computation engine for Shannon Entropy evaluations.
"""

import math
from collections import Counter


class EntropyCalculator:
    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Calculates the Shannon Entropy of a given string.
        Formula: H(X) = -sum(P(x_i) * log2(P(x_i)))
        Returns a float representing randomness (typically 0.0 to ~4.5+).
        """
        if not text:
            return 0.0

        length = len(text)
        counts = Counter(text)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)