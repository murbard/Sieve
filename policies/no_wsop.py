#!/usr/bin/env python3
"""
Policy: filter out any email containing "WSOP".

Two-phase evaluation:
- Pre-execution (phase != "post"): allow all operations
- Post-execution (phase == "post"): scan response for WSOP, deny if found

For list_emails, this means the entire result is blocked if any email
contains WSOP. A more sophisticated version could filter individual
emails from the list.
"""
import json
import sys

req = json.load(sys.stdin)
meta = req.get("metadata", {})
phase = meta.get("phase", "pre")

# Pre-execution: allow everything through
if phase != "post":
    print(json.dumps({"action": "allow"}))
    sys.exit(0)

# Post-execution: check the response content for WSOP
response = meta.get("response", "")
if "wsop" in response.lower():
    # For list operations, filter individual emails
    try:
        data = json.loads(response)
        # Handle list_emails response format: {"emails": [...]}
        if "emails" in data and isinstance(data["emails"], list):
            filtered = [
                e for e in data["emails"]
                if "wsop" not in json.dumps(e).lower()
            ]
            removed = len(data["emails"]) - len(filtered)
            data["emails"] = filtered
            if "total" in data:
                data["total"] = len(filtered)
            # Return allow with modified response
            print(json.dumps({
                "action": "allow",
                "rewrite": json.dumps(data),
                "reason": f"Filtered {removed} email(s) containing 'WSOP'"
            }))
            sys.exit(0)
    except (json.JSONDecodeError, KeyError):
        pass

    # For single email reads, just deny
    print(json.dumps({
        "action": "deny",
        "reason": "Response contains 'WSOP' — filtered by policy"
    }))
else:
    print(json.dumps({"action": "allow"}))
