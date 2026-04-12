#!/usr/bin/env python3
"""
Example Sieve policy script: Redact Sensitive Content

This policy allows all operations but redacts sensitive patterns
from email content before it reaches the agent.
"""
import json
import re
import sys

req = json.load(sys.stdin)

# Always allow the operation
result = {"action": "allow"}

# Check if there's body content to scan for sensitive data
body = req.get("metadata", {}).get("body", "")
if body:
    redactions = []

    # SSN pattern: XXX-XX-XXXX
    for m in re.finditer(r'\b\d{3}-\d{2}-\d{4}\b', body):
        redactions.append({"field": "body", "start": m.start(), "end": m.end()})

    # Credit card numbers (basic: 16 digits)
    for m in re.finditer(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', body):
        redactions.append({"field": "body", "start": m.start(), "end": m.end()})

    # Phone numbers (US format)
    for m in re.finditer(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', body):
        redactions.append({"field": "body", "start": m.start(), "end": m.end()})

    if redactions:
        result["redactions"] = redactions

print(json.dumps(result))
