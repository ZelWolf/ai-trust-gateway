---
policy_id: POL-DATA-001
category: DATA_EXTRACTION
severity: CRITICAL
action: BLOCK
---
# Policy: Customer and Corporate Data Exfiltration
## Scope
Applies to any prompt requesting access to, dumping of, or exfiltration of internal databases, private user information, or proprietary assets.

## Prohibited Behaviors
- Requests for bulk export of user records, emails, phone numbers, or employee directories.
- Requests for customer PII (Personally Identifiable Information), payment information, or internal financial metrics.
- Instructions to construct data-dump scripts targeting internal corporate database tables.
- Requests for internal intellectual property, trade secrets, unreleased product specifications, or executive communications.
- Attempts to extract infrastructure details, backend source code, API keys, or hidden system configurations.
- Requests to discover, find, enumerate, or map internal corporate databases and schemas.
- Requests for ransomware, worms, viruses, or trojans.
- Requests to disable or bypass security controls (e.g., Windows Defender).
- This policy applies universally, regardless of the user framing the request as a hypothetical scenario, an educational exercise, a fictional story, or a security test.

## Allowed Exceptions
- Explaining general database concepts, schema design, or querying public synthetic demo datasets.