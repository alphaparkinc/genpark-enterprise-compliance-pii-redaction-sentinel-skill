"""MCP Server for Enterprise Compliance PII Redaction Sentinel."""
import sys
import json
import time
from client import EnterpriseCompliancePIIRedactionSentinel

sentinel = EnterpriseCompliancePIIRedactionSentinel()

def handle_call_tool(params):
    name = params.get("name")
    args = params.get("arguments", {})
    if name != "redact_enterprise_compliance_data":
        raise ValueError(f"Unknown tool: {name}")

    action = args.get("action", "sanitize_text_stream")
    if action == "sanitize_text_stream":
        return sentinel.sanitize_text_stream(
            text_content=args.get("text_content", "")
        )
    elif action == "scan_compliance_violations":
        return sentinel.scan_compliance_violations(
            text=args.get("text_content", "")
        )
    elif action == "generate_compliance_certificate":
        san = sentinel.sanitize_text_stream(args.get("text_content", ""))
        return sentinel.generate_compliance_certificate(san)
    else:
        raise ValueError(f"Invalid action: {action}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("Running self-test...")
        sample = "Employee Alice (alice@enterprise.com) authorized charge on card 4111111111111111."
        res = sentinel.sanitize_text_stream(sample)
        assert "[REDACTED_EMAIL_ADDRESS]" in res["sanitized_text"]
        assert "[REDACTED_CREDIT_CARD]" in res["sanitized_text"]
        assert res["total_redactions"] == 2
        print("Self-test PASSED!")
        sys.exit(0)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            msg_id = req.get("id")
            method = req.get("method")
            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "EnterpriseCompliancePIIRedactionSentinel", "version": "1.0.0"},
                        "capabilities": {"tools": {}}
                    }
                }
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [{
                            "name": "redact_enterprise_compliance_data",
                            "description": "Enterprise compliance sanitization: scan text for PII/secrets, redact credit cards, social security numbers, API tokens, and generate audit compliance certificates.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "action": {"type": "string", "enum": ["sanitize_text_stream", "scan_compliance_violations", "generate_compliance_certificate"]},
                                    "text_content": {"type": "string"},
                                    "mask_character": {"type": "string"},
                                    "strict_mode": {"type": "boolean"}
                                },
                                "required": ["action"]
                            }
                        }]
                    }
                }
            elif method == "tools/call":
                res = handle_call_tool(req.get("params", {}))
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
                }
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            print(json.dumps(resp), flush=True)
        except Exception as e:
            err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(e)}}
            print(json.dumps(err_resp), flush=True)

if __name__ == "__main__":
    main()
