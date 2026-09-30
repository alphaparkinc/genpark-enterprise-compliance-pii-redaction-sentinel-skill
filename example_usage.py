"""Example usage for EnterpriseCompliancePIIRedactionSentinel."""
import json
from client import EnterpriseCompliancePIIRedactionSentinel

def main():
    print("=== Enterprise Regulatory Compliance & PII Redaction Sentinel Demo ===")
    sentinel = EnterpriseCompliancePIIRedactionSentinel()

    sensitive_log = """
    Tencent Meeting & Financial Sync Log:
    - Director Alice Vance (alice.vance@megacorp.internal) approved payroll batch.
    - Employee SSN: 123-45-6789 verified for direct deposit.
    - Vendor payment card: 4111111111111111 charged for $15,000.
    - Temporary AWS Token: ghp_1111222233334444555566667777888899990000.
    """

    print("\n--- 1. Scanning Compliance Violations ---")
    scan = sentinel.scan_compliance_violations(sensitive_log)
    print(f"Total Violations: {scan['total_violations']}")
    print("Breakdown:", json.dumps(scan["violation_counts"], indent=2))

    print("\n--- 2. Deterministic PII Sanitization Stream ---")
    sanitized = sentinel.sanitize_text_stream(sensitive_log)
    print(sanitized["sanitized_text"])

    print("\n--- 3. Cryptographic Compliance Certificate ---")
    cert = sentinel.generate_compliance_certificate(sanitized)
    print(json.dumps(cert, indent=2))

if __name__ == "__main__":
    main()
