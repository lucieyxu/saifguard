# SAIFGuard

TLDR; SAIFGuard is an ADK-based agent with a Mesop UI and looker dashboard to speed up security reviews and allow AI applications to go to production faster.

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



## Local Setup

Configure environment constants in `src/saifguard/config.py`.

To publish dashboard metrics during scans, set `GENERATE_DASHBOARD=True`.

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

SAIFGuard includes a containerized deployment configuration for Google Cloud Run using a unified Docker container capable of serving either the **Mesop UI** or the **FastAPI backend**.

### Deployment Files
* `src/Dockerfile`: Multi-stage Python container executing as non-root `appuser`.
* `src/entrypoint.sh`: Router script to select UI or API execution mode.
* `src/run_front.py`: Bypasses Mesop localhost binding to support Cloud Run `0.0.0.0` TCP startup probes.
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
  --substitutions=_PROJECT_ID="YOUR_PROJECT_ID",_REGION="YOUR_REGION",_AR_REPO="YOUR_AR_REPOSITORY",_SERVICE_NAME="saifguard-ui",_APP_TYPE="mesop"
```

#### 2. Deploy the FastAPI Backend API
```bash
cd src
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT_ID="YOUR_PROJECT_ID",_REGION="YOUR_REGION",_AR_REPO="YOUR_AR_REPOSITORY",_SERVICE_NAME="saifguard-api",_APP_TYPE="api"
```

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

#### 📊 BigQuery Permissions for Dashboarding

When the GCP Project Scan tool runs, it aggregates all discovered security vulnerabilities and publishes them directly to a BigQuery table (defaulting to `dashboard.vulnerabilities` in your BQ project).

To allow the SAIFGuard service account (`saifguard-sa@saifguard.iam.gserviceaccount.com`) to run queries and write this compliance data, grant it both the **BigQuery Data Editor** (`roles/bigquery.dataEditor`) and **BigQuery Job User** (`roles/bigquery.jobUser`) roles on your BigQuery project:

```bash
# Grant BigQuery Data Editor to write tables
gcloud projects add-iam-policy-binding BQ_PROJECT_ID \
  --member="serviceAccount:saifguard-sa@saifguard.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataEditor"

# Grant BigQuery Job User to execute query jobs
gcloud projects add-iam-policy-binding BQ_PROJECT_ID \
  --member="serviceAccount:saifguard-sa@saifguard.iam.gserviceaccount.com" \
  --role="roles/bigquery.jobUser"
```

---

## 📈 How to Access & Build the Data Studio Dashboard

All recommendations generated by SAIFGuard are stored as structured rows in BigQuery. You can open the pre-configured Data Studio dashboard template or build a custom report in minutes:

### Option 1: Open Pre-Configured Data Studio Template Link
Click the direct auto-provisioning template link:
[Open SAIFGuard Data Studio Dashboard Template](https://lookerstudio.google.com/reporting/create?c.reportId=08795748-d7d4-44a0-b6f7-272475314ba8&ds.ds0.connector=bigquery&ds.ds0.type=TABLE&ds.ds0.projectId=YOUR_PROJECT_ID&ds.ds0.datasetId=dashboard&ds.ds0.tableId=vulnerabilities)

### Option 2: Connect BigQuery to Data Studio Manually
1. **Open Data Studio:** Navigate to [Data Studio](https://datastudio.google.com/).
2. **Create a Data Source:** Click **Create > Data Source** in the top-left corner.
3. **Select the BigQuery Connector:** Under the Google Connectors catalog, select **BigQuery**.
4. **Select Your Table:**
   * Click **My Projects**.
   * Select your BQ billing project ID (e.g., `saifguard`).
   * Select the dataset (e.g., `dashboard`).
   * Select the table (e.g., `vulnerabilities`).
5. **Connect & Design:** Click **Connect** in the top-right.
   * Data Studio will pull all schemas from BigQuery. You will see fields like `name`, `description`, `severity`, `category`, `remediation`, and the direct Google Cloud Console `url` link for each resource.
   * Build scorecards, severity charts, and clickable compliance tables to distribute compliance tracking across your team!

---

## 🌐 Securing SAIFGuard with Identity-Aware Proxy (IAP)

To protect the SAIFGuard Mesop UI without exposing it publicly, you can enable **Direct IAP** directly on Cloud Run (without requiring an external HTTPS Load Balancer):

### 1. Enable Direct IAP on Cloud Run
```bash
# Enable IAP directly on your Cloud Run service
gcloud run services update saifguard-ui \
  --iap \
  --region="YOUR_REGION" \
  --project="YOUR_PROJECT_ID"
```

### 2. Grant Access Permissions
Assign the **IAP-secured Web App User** (`roles/iap.httpsResourceAccessor`) role to permitted users or domain members:

```bash
# Grant access to a specific user
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="user:your-email@domain.com" \
  --role="roles/iap.httpsResourceAccessor"

# Grant access to all users in an organization domain
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="domain:yourdomain.com" \
  --role="roles/iap.httpsResourceAccessor"
```

### Troubleshooting: "You don't have access" (IAP Authorization)
If users receive *You don't have access* after Google login, verify that `roles/iap.httpsResourceAccessor` has been granted to their account or domain.
