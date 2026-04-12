#!/usr/bin/env python3
"""
Example Sieve policy script: Project X

This policy allows an AI agent to:
- Read emails related to "Project X" from anyone at @client.com
- Draft replies (held for approval before sending)
- No access to unrelated emails
"""
import json
import sys

req = json.load(sys.stdin)
op = req["operation"]
meta = req.get("metadata", {})


def is_project_related():
    """Check if the email is related to Project X."""
    subject = meta.get("subject", "").lower()
    from_addr = meta.get("from", "").lower()
    return "project x" in subject or "project-x" in subject or "@client.com" in from_addr


# List emails: always allow (filtering happens at read time)
if op == "list_emails":
    print(json.dumps({"action": "allow"}))

# Read operations: only project-related emails
elif op in ("read_email", "read_thread"):
    if is_project_related():
        print(json.dumps({"action": "allow"}))
    else:
        print(json.dumps({
            "action": "deny",
            "reason": "Email not related to Project X"
        }))

# Drafts are fine
elif op in ("create_draft", "update_draft"):
    print(json.dumps({"action": "allow"}))

# Sends always need approval
elif op in ("send_email", "reply", "send_draft"):
    print(json.dumps({
        "action": "approval_required",
        "reason": "All outbound email requires human approval"
    }))

# Labels and list_labels are read-only-ish, allow
elif op in ("list_labels", "add_label"):
    print(json.dumps({"action": "allow"}))

# Deny everything else
else:
    print(json.dumps({
        "action": "deny",
        "reason": f"Operation '{op}' is not permitted by this policy"
    }))
