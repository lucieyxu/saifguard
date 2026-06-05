# SAIFGuard

TLDR; SAIFGuard is an ADK-based agent with a Mesop UI and looker dashboard to speed up security reviews and allow AI applications to go to production faster.

## Context
### The Problem: The AI Deployment Bottleneck

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
Change constants in ./saifguard/config.py.

If you want to publish the dashboards again when running a project scan, set the environment variable GENERATE_DASHBOARD to True.

### Run with FastAPI
```
cd src
poetry install
poetry run uvicorn app:app --host 0.0.0.0 --port 8080 --reload
```

Once the app is up, in another terminal, you can curl the invoke api to call the agent:
```
curl -X GET "http://127.0.0.1:8080/healthcheck"
```

Example to call analysis tool:
```
curl -N -X POST "http://127.0.0.1:8080/invoke" -H "Content-Type: application/json" -d '{
    "user_id": "test-user-1",
    "message": "Please analyze the document at gs://[YOUR BUCKET]/[YOUR FILE].pdf"
}'
```

### Run with UI
```
cd src
poetry install
poetry run mesop front.py
```

## Troubleshooting

If you have the following error: google.auth.exceptions.RefreshError: Reauthentication is needed. Please run `gcloud auth application-default login` to reauthenticate.

Make sure you are authenticated with `gcloud auth application-default login`.

Make sure Vertex AI API is enabled in your project: `gcloud services enable aiplatform.googleapis.com --project [YOUR PROJECT]`.

## Google Cloud Run Deployment

We have added a production-grade containerized deployment configuration to run SAIFGuard inside Google Cloud Run. This setup uses a unified Docker container capable of serving either the **interactive Mesop UI** or the **FastAPI backend**.

### 📂 Deployment Files Created
* `src/Dockerfile`: Multi-stage secure Python container (executes as non-root `appuser`).
* `src/entrypoint.sh`: Entrypoint router script to switch between UI and backend.
* `src/run_front.py`: Bypasses Mesop localhost binding to support Cloud Run `0.0.0.0` TCP startup probes.
* `src/cloudbuild.yaml`: Google Cloud Build pipeline supporting Artifact Registry build layer caching.
* `src/requirements.txt`: Frozen dependency lock compiled from pyproject.toml.
* `src/.dockerignore`: Excludes local cache, virtualenvs, and secrets from the container context.

### 🚀 How to Deploy

You can build and deploy either service using Google Cloud Build:

#### 1. Deploy the Interactive Mesop UI (Default)
This is the web interface where you can chat with the SAIFGuard agent:
```bash
cd src
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT_ID="YOUR_PROJECT_ID",_REGION="YOUR_REGION",_AR_REPO="YOUR_AR_REPOSITORY",_SERVICE_NAME="saifguard-ui",_APP_TYPE="mesop"
```

#### 2. Deploy the FastAPI Backend API
This runs the serverless API endpoint for invoking the agent programmatically:
```bash
cd src
gcloud builds submit . \
  --config=cloudbuild.yaml \
  --substitutions=_PROJECT_ID="YOUR_PROJECT_ID",_REGION="YOUR_REGION",_AR_REPO="YOUR_AR_REPOSITORY",_SERVICE_NAME="saifguard-api",_APP_TYPE="api"
```

### 🔗 Cross-Project Resource Analysis Setup

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

## 📈 How to Access & Build the Looker Studio Dashboard

All recommendations generated by SAIFGuard are stored as structured rows in BigQuery. You can build a Looker Studio dashboard on top of this in minutes:

1. **Open Looker Studio:** Navigate to [Looker Studio](https://lookerstudio.google.com/).
2. **Create a Data Source:** Click **Create > Data Source** in the top-left corner.
3. **Select the BigQuery Connector:** Under the Google Connectors catalog, select **BigQuery**.
4. **Select Your Table:**
   * Click **My Projects**.
   * Select your BQ billing project ID (e.g., `saifguard`).
   * Select the dataset (e.g., `dashboard`).
   * Select the table (e.g., `vulnerabilities`).
5. **Connect & Design:** Click **Connect** in the top-right.
   * Looker Studio will pull all schemas from BigQuery. You will see fields like `name`, `description`, `severity`, `category`, `remediation`, and the direct Google Cloud Console `url` link for each resource.
   * Build scorecards, severity charts, and clickable compliance tables to distribute compliance tracking across your team!

---

## 🌐 Securing SAIFGuard with Identity-Aware Proxy (IAP)

To protect the SAIFGuard Mesop UI from public exposure, you can secure it using **Identity-Aware Proxy (IAP)**. This can be done either directly on Cloud Run (using Direct IAP) or through an HTTPS Load Balancer.

### 🚨 Troubleshooting: "You don't have access" (IAP Authorization)

If you successfully authenticate with Google but receive the message:
> *You don't have access. User: your-email@domain.com*

This means IAP successfully authenticated your identity, but your account does not have permission to access the secured web app. To grant access, assign the **IAP-secured Web App User** (`roles/iap.httpsResourceAccessor`) role to your user account (or your organization's domain) at the project level:

```bash
# Grant access to a specific user
gcloud projects add-iam-policy-binding saifguard \
  --member="user:xxx" \
  --role="roles/iap.httpsResourceAccessor"

# Grant access to all members in an organization domain
gcloud projects add-iam-policy-binding saifguard \
  --member="domain:xxx" \
  --role="roles/iap.httpsResourceAccessor"
```
