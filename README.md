# SAIFGuard

TLDR; SAIFGuard is a unified AI Security Auditor (IDE Skill, CLI, and ADK Agent with Mesop UI) that audits local code, Terraform IaC, and live GCP projects against Google's Secure AI Framework (SAIF) and OWASP LLM Top 10, generating actionable `SAIF_AUDIT_REPORT.md` deliverables.

## Context
### The Problem: The AI Deployment Bottlenecks

In the race to innovate, businesses face a critical roadblock. Deploying AI applications is slow and risky. Traditional security reviews, not designed for the novel threats introduced by AI, create bottlenecks that delay projects for months. As stated by Thiébaut Meyer, Director in the Office of the CISO, "Customers need to tackle security risks in their application deployments and don’t have the right tool to do so”. This friction slows innovation and puts applications at risk.

### Our Solution: An AI-Powered Security Agent
SAIFGuard is an intelligent security agent designed to secure your AI applications and ensure a smooth path to production. We leverage AI to automate and accelerate security validation, embedding Google's Secure AI Framework (SAIF) directly into the development lifecycle. With SAIFGuard, moving AI to production is finally faster AND safer.

#### Key Capabilities
SAIFGuard provides a comprehensive security overview by analyzing your entire AI application lifecycle:
* Design Document Analysis : Inspects your technical design documents (TDDs) and architecture diagrams to generate recommendations and ensure SAIF compliance before development begins.
* GCP Project Analyzer : Connects to your production deployment to validate that your application is following all SAIF recommendations.
* Discrepancy Detection: Identifies critical gaps between your intended design and the actual cloud implementation, preventing vulnerabilities from ever reaching production.

#### The SAIFGuard Advantage
* Accelerate Deployment: Slash security review times from months to hours, giving your organization a critical speed-to-market advantage in the competitive AI landscape.
* Enhance Security: Achieve full compliance with Google's Secure AI Framework, systematically mitigating unique AI risks like prompt injection, data poisoning, and model evasion.
* Empower Teams: Provide developers, cloud architects, and security architects with immediate, actionable feedback through an interactive dashboard and chat interface, making security an accessible and integrated part of the development process.

---

## SAIFGuard IDE Skill & CLI (For FDEs & Developers)

Audit local application code (Python, Go, JS/TS), Terraform IaC (`*.tf`, `*.tfvars`), Dockerfiles, RAG pipelines, agentic tools, architecture design documents, and **live Google Cloud Platform (GCP) projects** directly inside your IDE (Antigravity, Cursor, Windsurf, Claude Code) or terminal against the **Google Secure AI Framework (SAIF)** and **OWASP Top 10 for LLMs**.

All audits generate a standardized, customer-ready [`SAIF_AUDIT_REPORT.md`](SAIF_AUDIT_REPORT.md) deliverable containing an Executive 6-Pillar Scorecard, Audit Coverage Map, clickable Google Cloud Console deep-links, production-ready GA `gcloud` remediation commands, unified git diffs, and a CISO sign-off block.

---

### 1. Install the Skill into Any Workspace

**From this repository (Zero dependencies required):**
```bash
# Install into the current repository (.agents/skills/saifguard/):
python3 src/saifguard/cli.py init

# Install into another project repository:
python3 src/saifguard/cli.py init --target /path/to/your/project

# Or via Node.js CLI:
node cli/bin/saifguard.js init --target /path/to/your/project
```

---

### 2. IDE Chat Examples (`/saifguard` & `@saifguard`)

Once installed in your workspace, invoke the skill directly in your IDE chat window (uses your IDE's built-in LLM + local deterministic Python scanners):

#### Example A: Audit a Live GCP Project (+ Cloud-to-Code Drift)
First, ensure your terminal session is authenticated (`gcloud auth login`), then ask in chat:
```text
@saifguard audit my GCP project "ale-test-network" and generate SAIF_AUDIT_REPORT.md
```
*or use the shorthand command:*
```text
/saifguard gcp ale-test-network
```
**What happens:**
1. Runs [`gcp_scan.py`](src/saifguard/skills/saifguard/scripts/gcp_scan.py) against Cloud Asset Inventory (`search-all-resources` & `search-all-iam-policies`) and `modelarmor.googleapis.com`.
2. Evaluates 6 deterministic cloud rules (`GCP_CLOUD_ARMOR_MISSING`, `GCP_CMEK_MISSING`, `GCP_IAM_PRIMITIVE_OR_PUBLIC`, `GCP_SA_USER_KEY_EXPOSED`, `GCP_VERTEX_PUBLIC_ENDPOINT`, `GCP_MODEL_ARMOR_MISSING`).
3. Gracefully handles `403 PERMISSION_DENIED` or disabled APIs by generating an **Audit Coverage & API Visibility** table (`GCP_AUDIT_VISIBILITY_GAP`).
4. Cross-checks live GCP assets against local `*.tf` and `*.py` files to detect **Shadow AI / ClickOps drift** and writes [`SAIF_AUDIT_REPORT.md`](SAIF_AUDIT_REPORT.md).

#### Example B: Audit Local Application Code, RAG & Agentic Tools
```text
/saifguard
```
*or scoped to specific domains:*
```text
/saifguard iac     # Audit only Terraform (*.tf, variables.tf, *.tfvars), KMS CMEK, Cloud Armor, VPC-SC, and IAM
/saifguard rag     # Audit only RAG & Vector Search pipelines (tenant isolation filters, document ACLs, Cloud DLP)
/saifguard agent   # Audit only Agent tools (@tool Pydantic schemas, HITL approvals, max_iterations loop limits)
```

#### Example C: Audit an Architecture / Design Document (Markdown, PDF, or Google Docs)
```text
# Local Markdown or PDF (inspects both text and embedded architecture diagrams):
@saifguard audit docs/architecture_design.pdf against Google SAIF principles

# Google Docs URL (uses `gcloud auth login --enable-gdrive-access` for private corporate docs):
@saifguard audit https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/edit
```

---

### 3. Terminal CLI & CI/CD Examples (`saifguard scan` & `saifguard audit`)

You can run SAIFGuard from any terminal or CI/CD pipeline via [`src/saifguard/cli.py`](src/saifguard/cli.py) (or `node cli/bin/saifguard.js`):

#### A. Deterministic Fast Scans (100% Deterministic, Zero LLM Calls)
```bash
# 1. Scan local repository (Python AST, Terraform variables/locals, Dockerfile) and output Markdown report
python3 src/saifguard/cli.py scan --dir . --output SAIF_AUDIT_REPORT.md

# 2. Scan a live GCP project deterministically and output SAIF_AUDIT_REPORT.md
python3 src/saifguard/cli.py scan --gcp-project ale-test-network --output SAIF_AUDIT_REPORT.md

# 3. Export SARIF 2.1.0 for GitHub Advanced Security / CodeQL integration
python3 src/saifguard/cli.py scan --dir . --format sarif --output results.sarif
python3 src/saifguard/cli.py scan --gcp-project ale-test-network --format sarif --output gcp-results.sarif

# 4. Scan local Terraform with a compiled Terraform plan JSON (terraform show -json plan.out > plan.json)
python3 src/saifguard/skills/saifguard/scripts/fast_scan.py . --tf-plan plan.json --format markdown
```

#### B. Full Hybrid AI Audit (Deterministic Scanners + ADK Agent Reasoning)
Runs `fast_scan.py` / `gcp_scan.py`, compresses payloads by 70%–95%, and invokes the standalone ADK Agent (`MODEL` in [`src/saifguard/config.py`](src/saifguard/config.py)):
```bash
# Hybrid audit on a live GCP project + local repo drift detection
python3 src/saifguard/cli.py audit --gcp-project ale-test-network --dir . --output SAIF_AUDIT_REPORT.md
```

#### C. Git Pre-Commit Security Gate
Prevent developers from committing Critical/High SAIF violations (hardcoded API keys, missing CMEK, unvalidated agent tools):
```bash
python3 src/saifguard/cli.py install-hook
```

---

### 4. Running the Offline Test Suite

The repository includes a 29-test offline suite in [`tests/`](tests/) covering `gcp_scan.py`, Terraform variable resolution (`var.*` / `.tfvars`), context budgeting, and dual-mode report delivery:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## Local Setup

Configure environment constants in `src/saifguard/config.py` (such as `MODEL` and `DEFAULT_REPORT_FILENAME="SAIF_AUDIT_REPORT.md"`).

### Run Backend (FastAPI)
```bash
cd src
poetry install
poetry run uvicorn app:app --host 0.0.0.0 --port 8080 --reload
```

Health check endpoint:
```bash
curl -X GET "http://127.0.0.1:8080/healthcheck"
```

Invoke analysis endpoint:
```bash
curl -N -X POST "http://127.0.0.1:8080/invoke" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test-user-1",
    "message": "Analyze the document at gs://[YOUR_BUCKET]/[YOUR_FILE].pdf"
  }'
```

### Run Frontend (Mesop UI)
```bash
cd src
poetry install
poetry run mesop front.py
```

### Run Built-in ADK Web UI (Inspect Tool Calls & Traces)
```bash
cd src
poetry install
poetry run python run_adk_web.py
# Or directly using adk CLI:
poetry run adk web . --port 8080
```
Open `http://127.0.0.1:8080` in your browser to inspect sessions, tool calls, and execution traces.


---

## Troubleshooting

#### Google Auth Refresh Error
If you encounter `google.auth.exceptions.RefreshError: Reauthentication is needed`:
- Run `gcloud auth application-default login` to refresh credentials.
- Ensure Vertex AI API is enabled: `gcloud services enable aiplatform.googleapis.com --project [YOUR_PROJECT_ID]`.

#### Cloud Build Source Storage / Artifact Registry 403 Forbidden
If Cloud Build fails with `Error 403: ... compute@developer.gserviceaccount.com does not have storage.objects.get` or `artifactregistry.repositories.downloadArtifacts`:
- Ensure both default compute and Cloud Build service accounts have the required read/write roles:
```bash
PROJECT_NUMBER=$(gcloud projects describe "YOUR_PROJECT_ID" --format="value(projectNumber)")

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"
```

#### Cloud Run URL Returns 403 Forbidden in Browser
Standard browsers do not attach GCP Bearer tokens when navigating to Cloud Run URLs.
- **Option A (Proxy)**: Run `gcloud run services proxy saifguard-ui --region=YOUR_REGION --project=YOUR_PROJECT_ID` and navigate to `http://localhost:8080`.
- **Option B (Direct IAP)**: Enable Direct IAP (`gcloud run services update saifguard-ui --iap`) and assign `roles/iap.httpsResourceAccessor` to your account or domain.

#### Vertex AI Model 404 / Invalid Region Error
If you encounter `Publisher model ... was not found`:
- Set `VERTEX_LOCATION="global"` (or pass `VERTEX_LOCATION=global` in `--set-env-vars`) so global models route to the global multi-region endpoint instead of single-region endpoints.

---

## Google Cloud Run Deployment

SAIFGuard includes a containerized deployment configuration for Google Cloud Run using a unified Docker container capable of serving the **Mesop UI**, the **FastAPI backend**, or the **built-in ADK Web UI (`adk-web`)**.

### Deployment Files
* `src/Dockerfile`: Multi-stage Python container executing as non-root `appuser`.
* `src/entrypoint.sh`: Router script to select Mesop UI, FastAPI backend, or ADK Web UI execution mode.
* `src/run_front.py`: Bypasses Mesop localhost binding to support Cloud Run `0.0.0.0` TCP startup probes.
* `src/run_adk_web.py`: Launches the built-in ADK Web UI (`adk web .`).
* `src/cloudbuild.yaml`: Google Cloud Build pipeline supporting Artifact Registry layer caching.
* `src/requirements.txt`: Dependency lock compiled from `pyproject.toml`.
* `src/.dockerignore`: Excludes cache files and virtual environments.

### Prerequisites & Setup

Ensure the required APIs, Artifact Registry repository, and IAM roles are configured prior to submitting builds:

#### 1. Enable Required APIs
```bash
gcloud services enable \
  aiplatform.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  cloudasset.googleapis.com \
  bigquery.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iap.googleapis.com \
  --project="YOUR_PROJECT_ID"
```

#### 2. Create Artifact Registry Repository
```bash
gcloud artifacts repositories create saifguard-registry \
  --repository-format=docker \
  --location="YOUR_REGION" \
  --description="Artifact Registry for SAIFGuard images" \
  --project="YOUR_PROJECT_ID"
```

#### 3. Create Service Account & Grant IAM Permissions
```bash
# Create service account for SAIFGuard
gcloud iam service-accounts create saifguard-sa \
  --display-name="SAIFGuard Service Account" \
  --project="YOUR_PROJECT_ID"

# Grant SAIFGuard application roles
gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:saifguard-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:saifguard-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudasset.viewer"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:saifguard-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataEditor"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:saifguard-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/bigquery.jobUser"

# Grant Cloud Build service accounts storage access, registry, logging & deployment permissions
PROJECT_NUMBER=$(gcloud projects describe "YOUR_PROJECT_ID" --format="value(projectNumber)")

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/logging.logWriter"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role="roles/logging.logWriter"

gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
  --member="serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role="roles/run.admin"

gcloud iam service-accounts add-iam-policy-binding "saifguard-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --member="serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser" \
  --project="YOUR_PROJECT_ID"
```

### How to Deploy

#### 1. Deploy the Interactive Mesop UI
```bash
cd src
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT_ID="YOUR_PROJECT_ID",_REGION="YOUR_REGION",_AR_REPO="YOUR_AR_REPOSITORY",_SERVICE_NAME="saifguard-ui",_APP_TYPE="mesop",_ENABLE_IAP="true"
```

#### 2. Deploy the FastAPI Backend API
```bash
cd src
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT_ID="YOUR_PROJECT_ID",_REGION="YOUR_REGION",_AR_REPO="YOUR_AR_REPOSITORY",_SERVICE_NAME="saifguard-api",_APP_TYPE="api",_ENABLE_IAP="false"
```

#### 3. Deploy the Built-in ADK Web UI (adk-web)
Deploy the built-in [adk-web](https://github.com/google/adk-web) UI to inspect tool calls, execution traces, session histories, and evaluations:
```bash
cd src
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT_ID="YOUR_PROJECT_ID",_REGION="YOUR_REGION",_AR_REPO="YOUR_AR_REPOSITORY",_SERVICE_NAME="saifguard-adk-ui",_APP_TYPE="adk-web",_ENABLE_IAP="true"
```
Example for deploying to `saifguard-test`:
```bash
cd src
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --project=saifguard-test \
  --substitutions=_PROJECT_ID="saifguard-test",_REGION="europe-west1",_AR_REPO="saifguard-registry",_SERVICE_NAME="saifguard-adk-ui",_APP_TYPE="adk-web",_ENABLE_IAP="true"
```
**Accessing the Deployed ADK Web UI on Cloud Run:**
By default, Cloud Run services require IAM authentication. Standard browsers do not attach GCP Bearer tokens automatically. To securely access the UI:
- **Using Direct IAP (Recommended):** Open the Cloud Run URL directly in your browser. Users authenticate via Google SSO.
- **Using gcloud proxy:**
  ```bash
  gcloud run services proxy saifguard-adk-ui --project=YOUR_PROJECT_ID --region=europe-west1
  ```
  Then open `http://localhost:8080` in your browser.


### Cross-Project Resource Analysis Setup

Since SAIFGuard is deployed in the **central security project** (`saifguard`), it needs permission to analyze resources in other target projects (such as `saifguard-usecase`). The target project ID is provided dynamically to the agent as part of your prompt (e.g., *"Scan the project saifguard-usecase"*).

To grant the SAIFGuard service account access to search and analyze resources in the target project:

1. Identify the Service Account under which SAIFGuard is running in the central project (e.g., `saifguard-sa@saifguard.iam.gserviceaccount.com`).
2. Grant the **Cloud Asset Viewer** (`roles/cloudasset.viewer`) role to this service account on the **target use-case project**:

```bash
gcloud projects add-iam-policy-binding TARGET_USE_CASE_PROJECT_ID \
  --member="serviceAccount:saifguard-sa@saifguard.iam.gserviceaccount.com" \
  --role="roles/cloudasset.viewer"
```

This allows SAIFGuard's `gcp_project_tool` to execute Asset Inventory lookups and scan the target project's resources for compliance.

#### 🪣 GCS Bucket Access for App Specifications

When using the **Design Document Analysis** capability (`analysis_tool`), you will provide a GCS path containing the application design PDF (e.g., `gs://YOUR_BUCKET_NAME/design.pdf`).

To allow the central SAIFGuard service account to read the design specification PDF from the bucket in your target use-case project, grant it the **Storage Object Viewer** (`roles/storage.objectViewer`) role on that bucket:

```bash
gcloud storage buckets add-iam-policy-binding gs://YOUR_BUCKET_NAME \
  --member="serviceAccount:saifguard-sa@saifguard.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

#### 🧠 Vertex AI API Access for Model Inferences

To allow the SAIFGuard service account (`saifguard-sa@saifguard.iam.gserviceaccount.com`) to query Gemini models inside the central project `saifguard`, grant it the **Vertex AI User** (`roles/aiplatform.user`) role:

```bash
gcloud projects add-iam-policy-binding saifguard \
  --member="serviceAccount:saifguard-sa@saifguard.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"
```

Note that some Gemini models are only available in the `global` multi-region (for example Gemiin 3.6 flash as of July 2026).

---

## 📄 Dual-Mode Markdown Report Delivery (`SAIF_AUDIT_REPORT.md`)

SAIFGuard automatically adapts how it delivers the generated [`SAIF_AUDIT_REPORT.md`](SAIF_AUDIT_REPORT.md) based on the runtime environment (`src/saifguard/report_tool.py`):

1. **Local CLI & IDE Mode**:
   - Writes `SAIF_AUDIT_REPORT.md` directly to your local workspace directory.
2. **Stateless Cloud Run / Multi-User Server Mode (`K_SERVICE` or `SAIFGUARD_RUNTIME=server`)**:
   - Stores each generated report in session-isolated memory (`store_session_report(session_id, report_md)`) to prevent multi-user file collisions across concurrent requests.
   - Download the Markdown report for any session via the FastAPI endpoint:
     ```bash
     curl -X GET "https://YOUR_CLOUD_RUN_URL/report/{session_id}" -o SAIF_AUDIT_REPORT.md
     ```

---

## 🌐 Securing SAIFGuard with Identity-Aware Proxy (IAP)

To protect the SAIFGuard Mesop UI without exposing it publicly, you can enable **Direct IAP** directly on Cloud Run (without requiring an external HTTPS Load Balancer):

### 1. Enable Direct IAP on Cloud Run
When deploying via Cloud Build, Direct IAP is enabled by default (`_ENABLE_IAP="true"`). Alternatively, you can enable or update it manually:
```bash
# Enable IAP directly on your Cloud Run service
gcloud run services update saifguard-ui \
  --iap \
  --region="YOUR_REGION" \
  --project="YOUR_PROJECT_ID"
```

### 2. Authorize the IAP Service Agent as Cloud Run Invoker
Cloud Run requires the IAP Service Agent to have permission to invoke the service:
```bash
PROJECT_NUMBER=$(gcloud projects describe "YOUR_PROJECT_ID" --format="value(projectNumber)")

gcloud run services add-iam-policy-binding saifguard-ui \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region="YOUR_REGION" \
  --project="YOUR_PROJECT_ID"
```

### 3. Grant User & Group Access Permissions
Assign the **IAP-secured Web App User** (`roles/iap.httpsResourceAccessor`) role to permitted users, groups, or domains at the Cloud Run service level:

```bash
# Grant access to a specific user on the Cloud Run service
gcloud iap web add-iam-policy-binding \
  --resource-type=cloud-run \
  --service=saifguard-ui \
  --region="YOUR_REGION" \
  --project="YOUR_PROJECT_ID" \
  --member="user:your-email@domain.com" \
  --role="roles/iap.httpsResourceAccessor"

# Grant access to a Google Group on the Cloud Run service
gcloud iap web add-iam-policy-binding \
  --resource-type=cloud-run \
  --service=saifguard-ui \
  --region="YOUR_REGION" \
  --project="YOUR_PROJECT_ID" \
  --member="group:your-group@domain.com" \
  --role="roles/iap.httpsResourceAccessor"

# Alternatively, grant project-wide IAP access:
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="domain:yourdomain.com" \
  --role="roles/iap.httpsResourceAccessor"
```

### 4. Direct Browser Access
Once IAP and permissions are set up, navigate directly to your Cloud Run URL in any browser:
```text
https://saifguard-ui-[HASH]-[REGION].a.run.app
```
Users will authenticate with Google SSO and will be automatically allowed based on the IAP IAM policy.

### Troubleshooting: "You don't have access" (IAP Authorization)
If users receive *You don't have access* after Google login:
- Verify that `roles/iap.httpsResourceAccessor` is bound to their email/group on the IAP Cloud Run resource (`gcloud iap web get-iam-policy ...`).
- Verify that the IAP Service Agent (`service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com`) has `roles/run.invoker` on the Cloud Run service.

