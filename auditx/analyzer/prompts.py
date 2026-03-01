SYSTEM_PROMPT = """
You are a compliance auditor specializing in Indian regulatory
frameworks for technology startups. You analyze structured code
extraction data (never raw code) and identify specific compliance
gaps. You respond ONLY in valid JSON. You are precise, conservative,
and never hallucinate regulatory requirements. If you are uncertain
about a finding, omit it rather than guess.
"""

USER_PROMPT_1 = """
Analyze this structured extraction from a {profile} startup codebase
and identify compliance gaps related to the DPDP Act 2023 and general
data handling obligations.

Codebase summary:
{codebase_summary_json}

For each compliance gap you identify, return a JSON object with:
- finding_id: sequential string e.g. "F001"
- severity: "CRITICAL", "HIGH", "MEDIUM", or "LOW"
- regulation_key: one of "DPDP", "RBI", "PCIDSS", "CERTIN"
- behavior_observed: plain English description of what the code
  does (1-2 sentences, no jargon, readable by a non-developer)
- location_hint: the route path or model name where observed
- remediation: specific, actionable fix in 1-2 sentences

Return a JSON array of finding objects. No preamble, no markdown,
no explanation outside the JSON array.
"""

USER_PROMPT_2 = """
Analyze this payment and financial data handling summary from a
{profile} startup codebase. Identify compliance gaps against
RBI tokenization requirements, PCI-DSS data storage rules, and
CERT-In incident reporting obligations.

Payment-related extraction:
{payment_summary_json}

Return a JSON array of finding objects using the same schema as
instructed. No preamble, no markdown, only the JSON array.
"""

USER_PROMPT_3 = """
Analyze this infrastructure, logging, and authentication summary.
Identify compliance gaps related to CERT-In Directions 2022
(log retention, incident detection, 6-hour reporting), DPDP Act
breach notification obligations, and general authentication
security requirements for a {profile} startup.

Infrastructure extraction:
{infra_summary_json}

Return a JSON array of finding objects using the same schema.
No preamble, no markdown, only the JSON array.
"""
