# AuditX
### AI Compliance Gap Scanner for Indian Startups

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Gemini API](https://img.shields.io/badge/Gemini-2.5_Flash-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## What it does
AuditX is a powerful local-first Python CLI tool that scans a startup's backend codebase using AST parsing (tree-sitter). It leverages the Gemini 2.5 Flash API to identify codebase vulnerabilities and maps findings to crucial Indian regulatory frameworks such as the **DPDP Act 2023, RBI Guidelines, PCI-DSS v4.0, and CERT-In Directions 2022**. The tool generates a standalone, interactive HTML report detailing exact code locations, severities, legal obligations, and actionable remediation steps—all without ever sending raw source code to external servers.

## Quick Start

```bash
git clone https://github.com/Yatharth-Bhavsar/AuditX.git
cd AuditX
pip install -e .
cp .env.example .env

# Add your Gemini API key to .env
# Run the scan using the CLI command:
auditx scan ./demo_repo --profile fintech

# Note for Windows users: If the 'auditx' command is not recognized, run:
# python -m auditx scan ./demo_repo --profile fintech
```

## Demo
*(Placeholder for Loom video link demonstrating the AuditX CLI and resulting HTML report)*

## Compliance Profiles
- **`fintech`**: Comprehensive scan covering DPDP + RBI + PCI-DSS + CERT-In.
- **`saas`**: General B2B/B2C scan covering DPDP + CERT-In.

## Limitations
- Prototype is currently tested on Python and JavaScript/TypeScript backend codebases.
- LLM reasoning may occasionally produce false positives — treat the generated report as a starting point for human review and engineering remediation, not as a legal compliance certificate.
- Free tier Gemini API constraints: max 500 scans/day, rate limited to 3 API calls per scan payload with 12-second delays.

## V2 Roadmap
- **Automated VAPT analysis:** (OWASP Top 10 taint analysis) natively integrated into AST parsing.
- **Delta scanning:** Scan autonomously on Git commit hooks via CI/CD.
- **Expanded Profiles:** Dedicated setups for Edtech (handling minors' data) and E-commerce.
