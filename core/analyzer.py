"""
core/analyzer.py
Domain tokenization, heuristic evaluation, and threat classification engine.
"""

from typing import Dict, Any, Optional
from core.entropy import EntropyCalculator


class DomainAnalyzer:
    def __init__(
        self,
        entropy_threshold: float = 3.8,
        tunneling_length_threshold: int = 25
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.tunneling_length_threshold = tunneling_length_threshold

    def evaluate_domain(self, fqdn: str) -> Optional[Dict[str, Any]]:
        """
        Analyzes a Fully Qualified Domain Name (FQDN) for tunneling and DGA patterns.
        """
        cleaned_domain = fqdn.strip().lower().rstrip(".")
        if not cleaned_domain:
            return None

        labels = cleaned_domain.split(".")
        if len(labels) < 2:
            return None

        # Extract SLD (Second Level Domain) and Subdomains
        sld = labels[-2]
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""

        sld_entropy = EntropyCalculator.calculate_shannon_entropy(sld)
        subdomain_entropy = (
            EntropyCalculator.calculate_shannon_entropy(subdomain)
            if subdomain
            else 0.0
        )

        threat_type = None
        details = {}

        # 1. DNS Tunneling Check: Long subdomain with high entropy
        if (
            len(subdomain) >= self.tunneling_length_threshold
            and subdomain_entropy >= self.entropy_threshold
        ):
            threat_type = "DNS Tunneling / Data Exfiltration"
            details = {
                "metric": "Subdomain Randomness & Length",
                "subdomain_length": len(subdomain),
                "entropy": subdomain_entropy,
            }

        # 2. DGA Check: High randomness in the core domain (SLD)
        elif sld_entropy >= (self.entropy_threshold - 0.2) and len(sld) >= 8:
            threat_type = "Domain Generation Algorithm (DGA)"
            details = {
                "metric": "SLD Randomness",
                "sld_length": len(sld),
                "entropy": sld_entropy,
            }

        # 3. Suspicious Subdomain Length (Data payload staging)
        elif len(subdomain) >= (self.tunneling_length_threshold + 15):
            threat_type = "High-Volume DNS Query Anomaly"
            details = {
                "metric": "Excessive Subdomain Length",
                "subdomain_length": len(subdomain),
                "entropy": subdomain_entropy,
            }

        if threat_type:
            return {
                "domain": cleaned_domain,
                "threat_type": threat_type,
                "sld": sld,
                "subdomain": subdomain,
                "sld_entropy": sld_entropy,
                "subdomain_entropy": subdomain_entropy,
                "details": details,
            }

        return None