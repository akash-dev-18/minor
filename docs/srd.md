# SOFTWARE REQUIREMENTS DOCUMENT (SRD)
# SENTINEL — Intelligent Email Spam & Phishing Detection Platform

**Project Type:** AI/ML-based Cybersecurity Application  
**Version:** 1.0  
**Status:** Development Specification  
**Primary Backend:** Python + FastAPI  
**Frontend:** React + TypeScript  
**Machine Learning:** Scikit-learn + NLP  
**Database:** PostgreSQL  
**Cache & Background Jobs:** Redis + Celery  
**Deployment:** Docker + Docker Compose

---

# 1. PROJECT OVERVIEW

## 1.1 Project Description

Sentinel is an intelligent email security analysis platform designed to identify spam, phishing attempts, suspicious email content, malicious URLs, suspicious sender domains, email authentication failures and potentially malicious attachments.

The platform accepts an email file (`.eml`) or supported raw email input, extracts its components, and passes the extracted information through multiple independent security analysis modules.

Each module performs a specialized analysis and returns structured findings.

The results are then processed by a central Risk Scoring Engine, which combines security findings with Machine Learning predictions to generate an explainable security assessment.

## 1.2 Project Objectives

- Detect legitimate, spam and phishing emails.
- Identify malicious and suspicious URLs.
- Analyze sender identity and domain reputation.
- Inspect email headers and authentication mechanisms.
- Detect suspicious email content and social engineering patterns.
- Analyze attachments for potentially malicious characteristics.
- Implement an actual trained ML classification model.
- Generate explainable risk scores.
- Provide a professional cybersecurity analysis dashboard.
- Maintain an analysis history with detailed findings.

## 1.3 Target Users

1. Security analysts.
2. Students and cybersecurity researchers.
3. General users who want to verify suspicious emails.
4. Organizations interested in basic email threat analysis.

---

# 2. TECHNOLOGY STACK

The following stack is mandatory unless a genuine technical limitation requires a documented alternative.

| Layer | Technology |
|---|---|
| Frontend | React + TypeScript |
| Build Tool | Vite |
| Styling | Tailwind CSS |
| UI Components | shadcn/ui with custom styling |
| Icons | Lucide |
| Charts | Recharts |
| Backend | Python + FastAPI |
| API Validation | Pydantic |
| Database | PostgreSQL |
| ORM | SQLAlchemy 2.x |
| Migrations | Alembic |
| Background Processing | Celery |
| Message Broker | Redis |
| ML | Scikit-learn |
| NLP | NLTK / spaCy |
| Data Processing | Pandas, NumPy |
| URL Parsing | urllib / tldextract |
| Email Parsing | Python email package |
| DNS Analysis | dnspython |
| Attachment Scanning | ClamAV |
| Testing | Pytest + Vitest |
| API Documentation | OpenAPI / Swagger |
| Containerization | Docker + Docker Compose |

Use compatible, stable package versions and pin dependencies. Do not blindly install incompatible latest versions.

---

# 3. SYSTEM ARCHITECTURE

The application must follow a modular architecture.

Each security functionality must have its own independent module, implementation and tests.

## 3.1 High-Level Architecture

```text
                 USER
                   |
                   v
            REACT FRONTEND
                   |
                   v
              FASTAPI
                   |
                   v
             EMAIL PARSER
                   |
          Extract Email Data
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
    URL         DOMAIN       HEADER
  ANALYSIS     ANALYSIS     ANALYSIS
       |           |           |
       +-----------+-----------+
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
    CONTENT    ATTACHMENT      ML
   ANALYSIS     ANALYSIS   CLASSIFIER
       |           |           |
       +-----------+-----------+
                   |
                   v
           RISK SCORING ENGINE
                   |
                   v
           FINAL CLASSIFICATION
                   |
                   v
            REPORT GENERATOR
                   |
                   v
            POSTGRESQL
                   |
                   v
             DASHBOARD
```

## 3.2 Architectural Rules

- Every analysis module must be independently executable.
- Modules must not directly depend on each other's internal implementation.
- Modules must communicate through defined input/output schemas.
- The central analysis orchestrator coordinates all modules.
- A failure in one module must not crash the entire analysis.
- Every module must return findings, execution status and processing metadata.
- The Risk Scoring Engine must be independent of the ML classifier.
- No hardcoded fake results or fabricated threat intelligence.
- External APIs must be configurable and optional.

---

# 4. FUNCTIONAL REQUIREMENTS — CORE ANALYSIS MODULES

## FR-01: EMAIL PARSER MODULE

**Responsibility:** Parse incoming emails and extract structured email information.

### Input
- `.eml` file.
- Supported raw email content.

### Functionalities

1. Parse MIME email structures.
2. Extract sender address.
3. Extract recipient addresses.
4. Extract subject.
5. Extract plain-text body.
6. Extract HTML body.
7. Extract email headers.
8. Extract attachments.
9. Extract URLs from the body and HTML.
10. Normalize extracted information.
11. Handle multipart emails.
12. Handle malformed emails safely.

### Output

A normalized email object containing:

```json
{
  "sender": "example@domain.com",
  "recipients": ["user@example.com"],
  "subject": "Account Verification",
  "body_text": "Please verify your account.",
  "body_html": null,
  "headers": {},
  "urls": [],
  "attachments": []
}
```

### Important

Use Python's standard email parsing libraries. Do not build a custom MIME parser unnecessarily.

---

## FR-02: URL ANALYSIS MODULE

**Responsibility:** Detect suspicious and malicious URLs inside emails.

### Functionalities

1. Extract URLs from plain text.
2. Extract URLs from HTML attributes.
3. Normalize URLs for analysis without changing the original evidence.
4. Detect shortened URLs.
5. Detect IP-address-based URLs.
6. Detect suspicious URL encoding.
7. Detect misleading domain names.
8. Detect typosquatting indicators.
9. Identify suspicious subdomains.
10. Inspect redirect chains using a controlled HTTP client.
11. Check URL reputation using VirusTotal or Google Safe Browsing where configured.
12. Identify known malicious URLs.
13. Detect suspicious URL patterns.

### Example indicators

- URL containing an IP address instead of a domain.
- Suspiciously long or encoded URL.
- Domain resembling a popular banking website.
- Unexpected redirect to another domain.
- URL found in a threat intelligence database.

### Output

```json
{
  "module": "url_analysis",
  "status": "completed",
  "urls_analyzed": 2,
  "findings": [
    {
      "type": "suspicious_url",
      "severity": "high",
      "evidence": "Suspicious redirect detected",
      "url": "https://example.invalid"
    }
  ]
}
```

### Security Requirements

- Never automatically execute JavaScript from URLs.
- Never download arbitrary content without restrictions.
- Protect against SSRF and access to private/internal IP ranges.
- Validate every redirect destination.
- Apply request timeouts and response-size limits.
- Do not expose internal infrastructure to URL scanning.

---

## FR-03: SENDER & DOMAIN REPUTATION MODULE

**Responsibility:** Analyze sender identity and domain reputation.

### Functionalities

1. Extract sender email domain.
2. Extract Reply-To domain.
3. Check domain existence using DNS.
4. Retrieve domain registration information where available.
5. Analyze domain age where registration data is available.
6. Detect disposable email domains.
7. Check known malicious domain lists.
8. Detect suspicious domain characteristics.
9. Detect brand impersonation and typosquatting.
10. Analyze sender-domain mismatches.
11. Check SPF-related DNS records.
12. Integrate external domain reputation services.

### Integrations

- VirusTotal.
- WHOIS/RDAP providers.
- DNS records.
- Configurable threat intelligence feeds.

### Example indicators

- Newly registered domain.
- Known malicious domain.
- Disposable email provider.
- Sender using a lookalike domain.
- Suspicious mismatch between sender and Reply-To.

### Output

```json
{
  "module": "domain_reputation",
  "status": "completed",
  "domain": "example.com",
  "findings": [
    {
      "type": "domain_reputation",
      "severity": "medium",
      "evidence": "Domain reputation could not be established"
    }
  ]
}
```

Unknown reputation must be represented as unknown, not automatically malicious.

---

## FR-04: EMAIL HEADER ANALYSIS MODULE

**Responsibility:** Inspect email metadata and authentication information.

### Functionalities

1. Parse From.
2. Parse Reply-To.
3. Parse Return-Path.
4. Analyze Received headers.
5. Inspect Message-ID.
6. Analyze sender identity mismatches.
7. Extract SPF authentication results.
8. Extract DKIM authentication results.
9. Extract DMARC authentication results.
10. Identify suspicious routing information.
11. Identify malformed or suspicious header patterns.
12. Inspect authentication alignment where sufficient evidence exists.

### Authentication checks

**SPF:** Determines whether the sending IP is authorized by the sender domain's SPF policy.

**DKIM:** Checks whether the message contains a valid cryptographic signature, where verification can be performed using the original message and appropriate DNS information.

**DMARC:** Evaluates the relationship between the visible From domain and authenticated SPF/DKIM identities, along with the domain's DMARC policy.

### Important

Do not claim SPF, DKIM or DMARC verification merely because an email contains an `Authentication-Results` header. Treat untrusted headers as claims unless their authenticity is established.

### Output

```json
{
  "module": "header_analysis",
  "status": "completed",
  "authentication": {
    "spf": "pass",
    "dkim": "fail",
    "dmarc": "fail"
  },
  "findings": []
}
```

Supported status values: `pass`, `fail`, `neutral`, `none`, `unknown`, `not_verified`.

---

## FR-05: EMAIL CONTENT ANALYSIS MODULE

**Responsibility:** Identify suspicious language and social engineering indicators.

### Functionalities

1. Analyze subject and email body.
2. Detect urgency-related language.
3. Detect requests for credentials.
4. Detect requests for OTPs.
5. Detect payment-related fraud patterns.
6. Detect account suspension threats.
7. Detect suspicious financial instructions.
8. Identify impersonation attempts.
9. Detect suspicious HTML forms.
10. Detect hidden HTML elements.
11. Detect suspicious HTML links and mismatched anchor text.
12. Analyze HTML content safely.
13. Generate content-based security findings.

### Examples of suspicious indicators

- "Your account will be suspended."
- "Verify your password immediately."
- "Send your OTP to continue."
- "Your payment has failed."
- "Click immediately to avoid account closure."

These patterns must be treated as indicators, not definitive proof of phishing.

### Output

```json
{
  "module": "content_analysis",
  "status": "completed",
  "findings": [
    {
      "type": "credential_request",
      "severity": "high",
      "evidence": "Email requests password verification"
    }
  ]
}
```

---

## FR-06: ATTACHMENT ANALYSIS MODULE

**Responsibility:** Identify potentially dangerous email attachments.

### Functionalities

1. Extract attachments.
2. Extract original filenames.
3. Identify MIME types.
4. Verify actual file signatures.
5. Detect extension mismatches.
6. Calculate SHA-256 hashes.
7. Check file hashes against VirusTotal where configured.
8. Scan attachments using ClamAV.
9. Identify suspicious file extensions.
10. Enforce attachment size limits.
11. Record scan status and findings.

### Suspicious file categories

- Executables.
- Scripts.
- Macro-enabled documents.
- Archive files.
- Files with misleading extensions.

### Output

```json
{
  "module": "attachment_analysis",
  "status": "completed",
  "attachments_analyzed": 1,
  "findings": []
}
```

### Security Requirements

- Never execute uploaded attachments.
- Never open attachments in the host operating system.
- Perform scanning in an isolated environment.
- Apply size limits and archive extraction limits.
- Prevent archive bombs and path traversal.
- Quarantine suspicious files where appropriate.

---

## FR-07: MACHINE LEARNING CLASSIFICATION MODULE

**Responsibility:** Classify emails using a trained ML model.

### Classification Categories

1. LEGITIMATE
2. SPAM
3. PHISHING

### ML Pipeline

```text
EMAIL DATASET
     |
     v
DATA CLEANING
     |
     v
TEXT PREPROCESSING
     |
     v
FEATURE EXTRACTION
     |
     v
TF-IDF VECTORIZATION
     |
     v
MODEL TRAINING
     |
     v
MODEL EVALUATION
     |
     v
MODEL SAVING
     |
     v
FASTAPI INFERENCE
```

### Dataset Requirements

Use genuine, publicly available email datasets with documented sources and licensing.

Potential sources:

- SpamAssassin Public Corpus.
- Enron Email Dataset.
- Nazario Phishing Corpus, subject to availability and usage terms.
- Other documented phishing and spam datasets.

Do not invent training samples or claim fabricated dataset sizes.

### Models to Implement

1. Multinomial Naive Bayes.
2. Logistic Regression.
3. Linear SVM.
4. Random Forest as an additional comparison.

### Feature Engineering

- TF-IDF.
- Word n-grams.
- Character n-grams.
- Subject-based features.
- Email text features.
- Optional structural email features.

### Evaluation Metrics

- Accuracy.
- Precision.
- Recall.
- F1-score.
- Confusion matrix.
- Per-class metrics.
- Cross-validation where appropriate.

Use a stratified train/test split and prevent data leakage. Evaluate class imbalance carefully.

### Model Selection

Select the final model based on meaningful evaluation, especially phishing recall and precision.

Do not choose a model based only on overall accuracy.

### Model Requirements

- Save the complete preprocessing and model pipeline.
- Version trained models.
- Store training metadata.
- Support model loading during FastAPI startup.
- Provide a clear error when no trained model is available.
- Do not silently replace missing models with random predictions.
- Keep training scripts separate from inference code.

### Prediction Output

```json
{
  "module": "ml_classification",
  "status": "completed",
  "prediction": "PHISHING",
  "confidence": 0.94,
  "probabilities": {
    "LEGITIMATE": 0.02,
    "SPAM": 0.04,
    "PHISHING": 0.94
  },
  "model_version": "1.0"
}
```

Confidence must be based on a model that provides appropriate calibrated probabilities. If the model cannot provide calibrated probabilities, do not invent them.

---

# 5. RISK SCORING ENGINE

**Responsibility:** Combine the findings of all security modules and generate a final explainable risk assessment.

This component must be independent of the ML classifier.

### Risk Score

Range: 0–100.

Suggested initial risk categories:

| Score | Risk Level |
|---|---|
| 0–19 | Low |
| 20–39 | Guarded |
| 40–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

### Initial scoring design

Each finding has:
- Severity.
- Evidence.
- Source module.
- Confidence or verification status.
- Configurable risk contribution.

Suggested severity weights:

| Severity | Weight |
|---|---:|
| Informational | 0 |
| Low | 10 |
| Medium | 25 |
| High | 45 |
| Critical | 60 |

Use a documented aggregation algorithm with a score cap of 100.

Avoid blindly adding every finding because multiple modules may detect the same underlying problem.

### ML Contribution

ML predictions should be an independent signal.

The final risk engine should consider:
- ML classification.
- ML confidence.
- Verified malicious URLs.
- Sender reputation.
- Authentication failures.
- Content indicators.
- Attachment findings.

### Critical Rule

A legitimate ML prediction must never override a verified malicious URL or confirmed malware finding.

Missing module data must not be interpreted as safe.

### Final Classification

The final output should contain:

- Final classification.
- Risk score.
- Risk level.
- ML prediction.
- Security findings.
- Positive security checks.
- Unknown or unavailable checks.
- Recommended actions.
- Explanation of why the email received that score.

---

# 6. ANALYSIS ORCHESTRATION ENGINE

**Responsibility:** Coordinate all analysis modules.

### Workflow

1. Receive uploaded email.
2. Validate file type and size.
3. Store the original email securely.
4. Parse email.
5. Start independent module analysis.
6. Run ML inference.
7. Collect module results.
8. Handle failed or unavailable modules.
9. Pass results to the Risk Scoring Engine.
10. Generate final report.
11. Store analysis results.
12. Notify the frontend when the report is ready.

### Execution Requirements

- Run independent modules concurrently where practical.
- Use background workers for time-consuming operations.
- Apply individual module timeouts.
- Implement retry policies for transient external API failures.
- Do not retry deterministic validation errors.
- Record execution status.
- Support partial analysis reports.

Each module should support the following statuses:

`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `SKIPPED`, `UNAVAILABLE`.

---

# 7. BACKEND API REQUIREMENTS

Base URL: `/api/v1`

### Email Analysis

| Method | Endpoint | Description |
|---|---|---|
| POST | `/analyses` | Upload and submit an email |
| GET | `/analyses/{id}` | Retrieve analysis status and results |
| GET | `/analyses` | Retrieve analysis history |
| DELETE | `/analyses/{id}` | Delete an analysis |

### Module Information

| Method | Endpoint | Description |
|---|---|---|
| GET | `/modules` | List available analysis modules |
| GET | `/health` | Application health |
| GET | `/ready` | Application readiness |

### ML Management

| Method | Endpoint | Description |
|---|---|---|
| GET | `/ml/status` | Current model status |
| GET | `/ml/metrics` | Model evaluation metrics |

### API Requirements

- Use Pydantic schemas.
- Validate every request.
- Return consistent error responses.
- Use UUID identifiers.
- Implement pagination for history.
- Never expose internal stack traces.
- Support CORS with explicit allowed origins.
- Provide OpenAPI documentation.

### Analysis Submission Response

```json
{
  "analysis_id": "uuid",
  "status": "PENDING",
  "message": "Email submitted for security analysis"
}
```

### Analysis Result Response

```json
{
  "analysis_id": "uuid",
  "status": "COMPLETED",
  "classification": "PHISHING",
  "risk_score": 87,
  "risk_level": "CRITICAL",
  "ml_prediction": {
    "label": "PHISHING",
    "confidence": 0.94
  },
  "modules": {
    "url_analysis": {},
    "domain_reputation": {},
    "header_analysis": {},
    "content_analysis": {},
    "attachment_analysis": {}
  },
  "findings": [],
  "recommendations": []
}
```

The API must return actual module results rather than static example data.

---

# 8. DATABASE DESIGN

Use PostgreSQL.

Implement migrations through Alembic.

### Table 1: analyses

- id (UUID, primary key)
- original_filename
- sender
- subject
- classification
- risk_score
- risk_level
- status
- created_at
- completed_at

### Table 2: analysis_modules

- id
- analysis_id (foreign key)
- module_name
- execution_status
- execution_duration
- error_message
- result (JSONB)
- created_at

### Table 3: security_findings

- id
- analysis_id (foreign key)
- module_name
- finding_type
- severity
- confidence
- evidence
- description
- risk_contribution
- created_at

### Table 4: attachments

- id
- analysis_id (foreign key)
- filename
- mime_type
- file_size
- sha256_hash
- scan_status
- scan_result

### Table 5: ml_model_versions

- id
- model_name
- model_version
- algorithm
- dataset_reference
- metrics (JSONB)
- is_active
- created_at

### Database Requirements

- Define proper foreign keys.
- Add indexes for frequently queried fields.
- Use JSONB for structured analysis results.
- Use transactions for related writes.
- Do not store unnecessary sensitive email data.
- Implement configurable data retention and deletion.

---

# 9. FRONTEND — USER INTERFACE REQUIREMENTS

**This is a critical part of the project.**

The interface must look like a professionally designed cybersecurity SaaS product, not a generic AI-generated dashboard.

## 9.1 Visual Direction

Design inspiration:

- Professional enterprise security products.
- Modern SOC dashboards.
- Dark cybersecurity analysis interfaces.
- Clean, functional data-heavy interfaces.

### Design Language

- Default theme: Dark.
- Background: Deep charcoal / near-black.
- Surfaces: Subtle dark gray.
- Primary accent: Restrained electric blue.
- Success: Muted green.
- Warning: Amber.
- Critical: Red.
- Typography: Inter or Geist.
- Icons: Lucide.
- Border radius: Consistent and restrained.
- Shadows: Minimal.
- Animations: Subtle and purposeful.

Avoid:
- Excessive gradients.
- Purple/pink AI-style gradients.
- Glassmorphism everywhere.
- Random decorative circles.
- Oversized headings.
- Unnecessary animated backgrounds.
- Excessive cards.
- Fake terminal animations.
- Fake statistics.
- Placeholder charts presented as real data.

The UI must prioritize readability, information hierarchy and usability.

## 9.2 Required Pages

### PAGE 1: Dashboard

Display:

- Total analyzed emails.
- Phishing detected.
- Spam detected.
- Legitimate emails.
- Critical risk detections.
- Recent analysis activity.
- Risk distribution.
- Classification distribution.
- Module health/status.
- Quick action to analyze an email.

All metrics must come from actual backend data.

### PAGE 2: Email Analysis

Provide:

- Drag-and-drop upload area.
- File selection.
- `.eml` format support.
- File size validation.
- Analysis submission.
- Loading/progress state.
- Error handling.

During analysis, display actual module execution progress.

### PAGE 3: Analysis Results

This is the most important screen.

Display:

**A. Overall Security Assessment**
- Classification.
- Risk score.
- Risk level.
- ML prediction.
- Confidence.

**B. Module Results**

Separate sections for:

- URL analysis.
- Sender/domain reputation.
- Header analysis.
- Content analysis.
- Attachment analysis.
- ML classification.

**C. Security Findings**

Each finding should show:

- Severity.
- Finding name.
- Explanation.
- Evidence.
- Source module.
- Recommended action.

**D. Email Information**

Display:
- Sender.
- Recipient.
- Subject.
- Timestamp.
- Attachments.
- Extracted URLs.

**E. Authentication Results**

Display SPF, DKIM and DMARC individually with clear statuses.

Use expandable sections for technical evidence so the interface remains readable.

### PAGE 4: Analysis History

Features:

- Search by sender or subject.
- Filter by classification.
- Filter by risk level.
- Sort by date.
- Pagination.
- View previous reports.
- Delete analysis.

### PAGE 5: Model Information

Display:

- Active ML model.
- Algorithm.
- Model version.
- Training dataset reference.
- Accuracy.
- Precision.
- Recall.
- F1-score.
- Confusion matrix.
- Class-wise performance.

Never display fabricated model metrics.

### PAGE 6: Settings

Display:

- Threat intelligence API configuration.
- Analysis configuration.
- File size limits.
- Retention settings.
- External service availability.
- Application information.

Never return API secrets to the frontend. Sensitive configuration must remain server-side.

## 9.3 UI Functionality Requirements

- Every button must perform a real action.
- Every filter must work.
- Tables must support pagination.
- Search must use actual backend data.
- Loading states must be implemented.
- Empty states must be designed.
- Error states must be meaningful.
- Responsive layouts are mandatory.
- Keyboard navigation must work.
- Forms must have proper validation.
- Use accessible contrast and semantic HTML.

## 9.4 Professional UI Quality

The design should resemble a product that could be presented to a security engineering team.

Prioritize:
- Consistent spacing.
- Alignment.
- Typography hierarchy.
- High-quality data tables.
- Clean technical detail panels.
- Clear severity indicators.
- Useful charts.
- Well-designed upload interactions.
- Fast navigation.

Do not use the same generic card layout for every section.

---

# 10. SECURITY REQUIREMENTS

Since Sentinel is itself a cybersecurity product, its implementation must follow secure development practices.

### File Upload Security

- Validate file extensions and actual content.
- Apply strict upload size limits.
- Generate server-side filenames.
- Store uploaded files outside the public web directory.
- Prevent path traversal.
- Do not trust user-provided MIME types.
- Do not execute uploaded files.

### URL Scanning Security

- Prevent SSRF.
- Block loopback and private network destinations.
- Validate DNS resolution and redirect destinations.
- Restrict protocols to HTTP and HTTPS.
- Apply timeouts and response-size limits.

### API Security

- Validate all incoming data.
- Avoid leaking internal errors.
- Apply request rate limits.
- Protect secrets using environment variables.
- Restrict CORS.
- Use secure HTTP configuration in deployment.

### Attachment Security

- Use ClamAV where configured.
- Isolate scanning.
- Restrict archive extraction.
- Never execute attachments.

### Privacy

- Never send complete private email contents to third-party APIs by default.
- Send only the minimum required URL, domain or file hash when integrating external services.
- Make external lookups configurable.
- Do not log passwords, tokens or unnecessary email contents.

---

# 11. EXTERNAL SERVICE INTEGRATIONS

Integrate the following services through independent service adapters.

| Service | Function |
|---|---|
| VirusTotal | URL, domain and file reputation |
| Google Safe Browsing | URL threat detection |
| AbuseIPDB | IP reputation |
| RDAP / WHOIS | Domain registration information |
| DNS | DNS and authentication records |
| ClamAV | Attachment scanning |

### Integration Requirements

- Each service must have its own adapter.
- API keys must come from environment variables.
- Implement timeouts.
- Handle rate limits.
- Handle unavailable services.
- Cache results where appropriate.
- Record data source and lookup timestamp.
- Do not treat unavailable results as safe.

The application must still support core local analysis without external API credentials.

---

# 12. PROJECT DIRECTORY STRUCTURE

Use a clean monorepo.

```text
sentinel/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   │
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── router.py
│   │   │       └── endpoints/
│   │   │
│   │   ├── modules/
│   │   │   ├── email_parser/
│   │   │   ├── url_analysis/
│   │   │   ├── domain_reputation/
│   │   │   ├── header_analysis/
│   │   │   ├── content_analysis/
│   │   │   ├── attachment_analysis/
│   │   │   └── ml_classification/
│   │   │
│   │   ├── services/
│   │   │   ├── analysis_orchestrator.py
│   │   │   ├── risk_scoring.py
│   │   │   ├── threat_intelligence.py
│   │   │   └── report_service.py
│   │   │
│   │   ├── workers/
│   │   ├── database/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── core/
│   │   └── utils/
│   │
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── security/
│   │
│   ├── migrations/
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── layouts/
│   │   ├── features/
│   │   │   ├── dashboard/
│   │   │   ├── analysis/
│   │   │   ├── history/
│   │   │   ├── reports/
│   │   │   └── settings/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── types/
│   │   ├── utils/
│   │   └── App.tsx
│   │
│   ├── public/
│   ├── package.json
│   └── Dockerfile
│
├── ml/
│   ├── datasets/
│   ├── preprocessing/
│   ├── training/
│   ├── evaluation/
│   ├── inference/
│   └── artifacts/
│
├── infrastructure/
│   ├── docker/
│   └── configs/
│
├── docs/
│   ├── architecture.md
│   ├── api.md
│   └── model_report.md
│
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
└── LICENSE
```

Every module should have its own internal files for implementation, schemas, and tests where appropriate.

Do not put all business logic in `main.py`.

---

# 13. TESTING REQUIREMENTS

Testing is mandatory.

### Unit Tests

Test each module independently:

- Email parsing.
- URL extraction.
- URL normalization.
- Domain reputation.
- Header analysis.
- SPF/DKIM/DMARC interpretation.
- Content analysis.
- Attachment identification.
- ML inference.
- Risk scoring.

### Integration Tests

Test:

- Complete email upload workflow.
- Module orchestration.
- Database persistence.
- Background processing.
- External service failures.
- Report generation.

### Security Tests

Test:

- Malformed email files.
- Oversized uploads.
- Path traversal attempts.
- SSRF attempts.
- Malicious redirect destinations.
- Suspicious archive files.
- Invalid MIME types.
- Unexpected external API responses.

### ML Tests

Test:

- Model loading.
- Prediction output.
- Class labels.
- Preprocessing consistency.
- Model versioning.
- Evaluation metrics.

### Frontend Tests

Test:

- Upload workflow.
- Form validation.
- Analysis result rendering.
- History filters.
- API error handling.
- Loading and empty states.

---

# 14. DEPLOYMENT REQUIREMENTS

Provide a complete Docker Compose environment.

Required services:

1. Frontend.
2. Backend API.
3. PostgreSQL.
4. Redis.
5. Celery worker.
6. ClamAV, if enabled.

### Deployment Features

- Dockerfiles.
- Docker Compose configuration.
- Health checks.
- Persistent database volume.
- Environment configuration.
- Database migrations.
- Proper service dependencies.
- Restart policies.
- Centralized application logging.

The project must start using documented commands.

Example:

```bash
cp .env.example .env

docker compose up --build
```

The README must explain:
- Prerequisites.
- Installation.
- Environment variables.
- Running migrations.
- Starting services.
- Training the ML model.
- Running tests.
- Accessing the frontend.
- Accessing Swagger documentation.

Do not commit real API keys or credentials.

---

# 15. DEVELOPMENT PHASES

Implement the project in the following order.

### Phase 1 — Project Foundation

- Create monorepo.
- Configure FastAPI.
- Configure React.
- Configure PostgreSQL.
- Configure Docker Compose.
- Set up migrations.
- Establish shared schemas.

### Phase 2 — Email Processing

- Implement `.eml` upload.
- Implement email parser.
- Implement MIME handling.
- Extract headers, body, URLs and attachments.

### Phase 3 — Independent Detection Modules

Implement separately:

1. URL analysis.
2. Domain reputation.
3. Header analysis.
4. Content analysis.
5. Attachment analysis.

Write tests for each module before integration.

### Phase 4 — Machine Learning

- Acquire and document datasets.
- Clean data.
- Preprocess text.
- Train multiple models.
- Evaluate models.
- Select the best model.
- Save the pipeline.
- Implement inference service.

### Phase 5 — Risk Engine

- Implement finding aggregation.
- Implement risk scoring.
- Implement final classification.
- Implement explainable reports.

### Phase 6 — Frontend

- Build dashboard.
- Build upload interface.
- Build analysis progress view.
- Build results page.
- Build history.
- Build model metrics page.
- Build settings.

### Phase 7 — Integration

- Connect frontend to actual APIs.
- Integrate background processing.
- Persist results.
- Implement failure handling.
- Verify complete workflows.

### Phase 8 — Testing and Finalization

- Run all automated tests.
- Fix security issues.
- Test Docker deployment.
- Verify every frontend action.
- Complete README.
- Verify the application from a clean installation.

---

# 16. DEFINITION OF DONE / ACCEPTANCE CRITERIA

The project is not considered complete until all the following requirements are satisfied.

## Core Functionality

- [ ] User can upload a valid `.eml` file.
- [ ] Email parser extracts the required fields.
- [ ] URLs are extracted and analyzed.
- [ ] Sender domain is analyzed.
- [ ] Email headers are analyzed.
- [ ] SPF, DKIM and DMARC findings are reported with appropriate verification status.
- [ ] Email content is analyzed.
- [ ] Attachments are identified and scanned where configured.
- [ ] ML model performs actual inference.
- [ ] ML model distinguishes all three categories.
- [ ] Risk scoring engine generates a final assessment.
- [ ] Each finding contains an explanation.
- [ ] Analysis history is persisted.

## Frontend

- [ ] Dashboard uses real backend metrics.
- [ ] Upload workflow works.
- [ ] Analysis progress is displayed.
- [ ] Results page displays module-specific findings.
- [ ] History search and filters work.
- [ ] Model metrics come from actual evaluation.
- [ ] Responsive design works.
- [ ] No dead buttons or fake data.

## Engineering

- [ ] Modules are independently testable.
- [ ] API documentation is available.
- [ ] Database migrations work.
- [ ] Docker Compose starts successfully.
- [ ] Unit and integration tests pass.
- [ ] Security protections are implemented.
- [ ] README provides complete setup instructions.
- [ ] No secrets are committed.

---

# 17. INSTRUCTIONS FOR THE AI CODING AGENT

**These instructions are mandatory.**

You are acting as a senior full-stack engineer, ML engineer, cybersecurity engineer and UI/UX designer.

Your responsibility is to implement the complete Sentinel platform described in this document.

### Implementation Rules

1. Read and understand the entire SRD before starting.
2. Create the actual project files, not just architectural explanations.
3. Implement working backend and frontend code.
4. Implement every independent analysis module.
5. Keep business logic separated from API endpoints.
6. Use typed schemas and consistent interfaces.
7. Use real ML training and inference.
8. Do not fabricate datasets, predictions, metrics or threat intelligence results.
9. Do not use hardcoded mock responses as production functionality.
10. Do not leave TODO placeholders for mandatory functionality.
11. External services must have proper adapters and graceful failure handling.
12. Every frontend control must be functional.
13. Maintain professional UI quality throughout the project.
14. Implement automated tests.
15. Run the application and verify its major workflows.
16. Fix implementation and integration errors rather than merely documenting them.
17. Maintain an updated README.
18. Document any functionality that genuinely requires unavailable credentials or external infrastructure.

### Execution Strategy

Do not generate the entire application in one enormous source file.

Work incrementally:

- First establish the project structure.
- Then implement the database and shared schemas.
- Implement each independent module.
- Write and run module tests.
- Integrate modules using the orchestrator.
- Implement ML training and inference.
- Implement risk scoring.
- Build the frontend.
- Connect everything.
- Run end-to-end verification.

Before finishing, inspect the repository for:

- Missing imports.
- Broken API integrations.
- Incorrect schemas.
- Unused or dead components.
- Missing tests.
- Security vulnerabilities.
- Hardcoded mock data.
- Incomplete features.

If the environment does not provide external API keys, implement the integration adapters and report the missing configuration honestly. Do not pretend those services were tested.

### Final Deliverables

The final repository must contain:

1. Complete backend source code.
2. Complete frontend source code.
3. Independent security analysis modules.
4. ML training and evaluation pipeline.
5. Trained model artifact when dataset acquisition and training are possible.
6. PostgreSQL schema and migrations.
7. Docker Compose environment.
8. Automated tests.
9. `.env.example`.
10. Complete README.
11. Architecture documentation.
12. API documentation.
13. ML evaluation report.

**Final instruction:** Prioritize a fully working, secure and professionally designed application over a visually impressive but non-functional prototype. Build real functionality first and make the interface reflect the quality of the underlying engineering.

---

# END OF SOFTWARE REQUIREMENTS DOCUMENT
