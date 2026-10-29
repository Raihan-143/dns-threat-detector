"""
main.py
CLI entry point for the Passive DNS Tunneling & DGA Anomaly Detector.
"""

import argparse
import json
import sys
from pathlib import Path
from core.analyzer import DomainAnalyzer
from utils.logger import ConsoleLogger


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Passive DNS Tunneling & DGA Anomaly Detector Engine"
    )
    parser.add_argument(
        "-f", "--file",
        dest="domain_file",
        required=True,
        help="Path to file containing domain queries (one per line)"
    )
    parser.add_argument(
        "-e", "--entropy",
        dest="entropy_threshold",
        type=float,
        default=3.8,
        help="Entropy threshold for flagging randomness (Default: 3.8)"
    )
    parser.add_argument(
        "-l", "--length",
        dest="length_threshold",
        type=int,
        default=25,
        help="Subdomain length threshold for exfiltration checks (Default: 25)"
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default=None,
        help="Optional destination path for structured JSON threat report"
    )

    args = parser.parse_args()
    file_path = Path(args.domain_file).resolve()

    if not file_path.exists():
        ConsoleLogger.failure(f"Input file not found: {file_path}")
        sys.exit(1)

    ConsoleLogger.header("DNS Tunneling & DGA Anomaly Detection Engine")
    ConsoleLogger.info(f"Target Domain Stream : {file_path}")
    ConsoleLogger.info(f"Entropy Threshold    : {args.entropy_threshold}")
    ConsoleLogger.info(f"Subdomain Len Limit  : {args.length_threshold}")

    analyzer = DomainAnalyzer(
        entropy_threshold=args.entropy_threshold,
        tunneling_length_threshold=args.length_threshold
    )

    total_queries = 0
    threat_incidents = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            query = line.strip()
            if not query or query.startswith("#"):
                continue

            total_queries += 1
            result = analyzer.evaluate_domain(query)
            if result:
                threat_incidents.append(result)
                ConsoleLogger.failure(
                    f"[{result['threat_type']}] FQDN: {result['domain']} | "
                    f"Entropy: {result['details']['entropy']} | "
                    f"Metric: {result['details']['metric']}"
                )

    # Forensic Summary telemetry
    print()
    ConsoleLogger.info("Threat Hunting Summary:")
    ConsoleLogger.info(f"Total DNS Queries Analyzed : {total_queries}")

    if threat_incidents:
        ConsoleLogger.warning(f"Malicious Anomalies Flagged : {len(threat_incidents)}")
    else:
        ConsoleLogger.success("Zero Anomalies Detected. Clean DNS Baseline.")

    # Export structured JSON report
    if args.output_file:
        report = {
            "source_file": str(file_path),
            "total_queries": total_queries,
            "anomalies_flagged": len(threat_incidents),
            "incidents": threat_incidents
        }
        try:
            with open(args.output_file, "w", encoding="utf-8") as out:
                json.dump(report, out, indent=4)
            ConsoleLogger.success(f"Threat report exported to: {args.output_file}")
        except OSError as err:
            ConsoleLogger.failure(f"Failed to export report: {err}")


if __name__ == "__main__":
    main()