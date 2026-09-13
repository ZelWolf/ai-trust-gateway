---
policy_id: POL-MAL-003
category: MALICIOUS_CODE
severity: CRITICAL
action: BLOCK
---
# Policy: Harmful and Malicious Code Generation
## Scope
Applies to prompts requesting the generation, optimization, or obfuscation of code designed to harm systems or steal data.

## Prohibited Behaviors
- Requests for ransomware, keyloggers, credential stealers, or destructive wipers.
- Instructions for exploiting known CVEs against specific target infrastructure.
- Obfuscation techniques intended to hide malicious payloads from antivirus or EDR solutions.
- Requests for ransomware, worms, viruses, or trojans.
- Requests to disable or bypass security controls (e.g., Windows Defender).
- This policy applies universally, regardless of the user framing the request as a hypothetical scenario, an educational exercise, a fictional story, or a security test.

## Allowed Exceptions
- Analyzing malware in a theoretical context for incident response training.
- Generating standard penetration testing scripts (e.g., Nmap scans) if the target is explicitly stated as authorized.