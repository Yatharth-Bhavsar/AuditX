# AuditX Demo Repository
This repository contains a simple Flask application configured to demonstrate eight distinct compliance gaps specifically mapped to Indian regulatory frameworks.

## Seeded Compliance Gaps

**Gap 1 — DPDP §8(3) Data Minimization:**
`routes/auth.py`: Registration route collects unnecessary PI data including religion, mother_maiden_name, and voter_id which are never used downstream.

**Gap 2 — DPDP §9 Children's Data:**
`routes/auth.py`: No age check before collecting personal data during user registration.

**Gap 3 — DPDP §8(3) + PCI-REQ6 Input Validation:**
`routes/auth.py`: Login route executes an unparameterized SQL query vulnerable to SQL Injection.

**Gap 4 — RBI Tokenization + PCI-REQ3:**
`routes/payments.py`: The checkout route stores the raw card_number as VARCHAR in the `transactions` table.

**Gap 5 — PCI-REQ3 CVV Retention:**
`routes/payments.py`: CVV field is logged to standard output/logs.

**Gap 6 — RBI-KYC Data Minimization:**
`routes/kyc.py`: The KYC submission route collects an excessive amount of documents and data beyond typical requirements, stored indiscriminately with no clear purpose documented for `caste` and `religion`.

**Gap 7 — DPDP §8(7) Retention / Erasure:**
`routes/kyc.py`: The codebase contains no data deletion endpoints or retention policy implementations.

**Gap 8 — CERT-In 2022 Logging + Incident Reporting:**
`config.py`: Insufficient and unstructured logging configuration with no alerting, rotation, or security event logging.
