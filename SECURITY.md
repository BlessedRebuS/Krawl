# Security Policy

We strongly recommend running the latest supported release to ensure you benefit from the most recent security fixes.

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in Krawl, please report it responsibly through [GitHub Security Advisories](https://github.com/BlessedReBuS/Krawl/security/advisories/new).

**Do not disclose vulnerabilities publicly until they have been reviewed and addressed.**

### What a Good Report Looks Like

We value high-quality, technically substantiated vulnerability reports. Reports must demonstrate an actual security impact and include enough information for us to independently reproduce and verify the issue.

**Low-effort, speculative, or AI-generated reports without technical validation are not welcome.**

In particular, reports consisting solely of generic vulnerability descriptions, automated scanner output, theoretical attack scenarios, or unverified AI-generated findings will be rejected.

Every report must include a clear, step-by-step reproduction procedure.

### Required Information

Please include the following information in your report:

1. **Summary:** A concise description of the vulnerability and the affected component.
2. **Affected versions:** The exact Krawl version, commit, or branch where the issue was identified.
3. **Environment:** Relevant deployment details, configuration, dependencies, and operating environment.
4. **Prerequisites:** Any required permissions, authentication, configuration, or initial conditions.
5. **Steps to reproduce:** A numbered, deterministic sequence of instructions that allows us to reproduce the issue from a clean or clearly defined starting state.
6. **Proof of Concept:** Include actual HTTP requests, payloads, commands, scripts, configuration files, or other relevant technical evidence.
7. **Expected vs. actual behavior:** Explain what should happen and what happens instead.
8. **Security impact:** Describe the realistic consequences, affected security boundaries, and potential attack scenarios.

Whenever possible, provide a minimal working proof of concept that demonstrates the vulnerability without requiring access to your private infrastructure.

### Reporting Guidelines

- Verify your findings against an actual Krawl deployment before submitting a report.
- Do not submit findings based exclusively on automated scanners or static analysis without validating their security impact.
- Do not submit hypothetical vulnerabilities without a demonstrable exploitation path.
- Do not report intended functionality or behavior as a security vulnerability.
- Do not submit duplicate reports or findings already documented in existing issues or advisories.
- Do not include sensitive information belonging to third parties in your proof of concept.
- Do not perform testing against infrastructure you do not own or have explicit authorization to assess.

Reports that lack sufficient technical evidence or reproducible steps may be closed without further investigation.

### What Happens After You Submit

We aim to follow a transparent and responsible disclosure process:

- **Acknowledgment:** We aim to acknowledge new reports within 5 business days.
- **Initial assessment:** We review the technical details, attempt reproduction, and determine whether the finding represents a genuine security vulnerability.
- **Follow-up:** We may request additional information, clarification, or a more reliable proof of concept.
- **Resolution:** Accepted vulnerabilities will be investigated and addressed according to their severity and complexity.
- **Disclosure:** Once a fix is available, we may coordinate a public security advisory with the reporter.

If a report is declined, we will provide an explanation whenever possible.

Please allow reasonable time for investigation and remediation before making any vulnerability public.

### Scope

This policy covers security vulnerabilities affecting Krawl itself, including:

- Authentication and authorization weaknesses.
- Remote code execution and command injection.
- SQL injection and other database-related vulnerabilities.
- Server-side request forgery (SSRF).
- Path traversal and arbitrary file access.
- Cross-site scripting (XSS) and other client-side vulnerabilities.
- Sensitive information disclosure.
- Security weaknesses in API endpoints, dashboard functionality, and request handling.
- Vulnerabilities in Krawl-specific integrations and security mechanisms.

Third-party dependencies should be reported to their respective maintainers unless the vulnerability introduces a specific security issue in Krawl's implementation or integration.

Thank you for helping keep Krawl and its users secure.
