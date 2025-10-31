# SAIFGuard

## Local Setup
Change constant in ./saifguard/config.py.

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

## Instructions to deploy to Cloud Run

### Prerequisites

1.  **Permissions**: Ensure the user running the commands has the `Artifact Registry Administrator` (`roles/artifactregistry.admin`) and `Cloud Run Developer` (`roles/run.developer`) roles on the project.

2.  **Enable APIs**: Make sure the required APIs are enabled:
```bash
gcloud services enable artifactregistry.googleapis.com cloudbuild.googleapis.com run.googleapis.com --project=${PROJECT_ID}
```

### Deployment Steps

1.  **Add Gunicorn**: For production deployments on Cloud Run, you'll need a production-grade server.
    ```bash
    poetry add gunicorn
    ```

2.  **Update requirements**: Export your dependencies to `requirements.txt`.
    ```bash
    poetry export -f requirements.txt --output requirements.txt --without-hashes
    ```

3.  **Create Artifact Registry repository** (only needs to be done once):
```bash
gcloud artifacts repositories create saifguard \
    --repository-format=docker \
    --location=europe-west1 \
    --project=${PROJECT_ID}
```
Build container image: `gcloud builds submit --tag "europe-west1-docker.pkg.dev/${PROJECT_ID}/saifguard/saifguard-ui:latest"`
Deploy to Cloud Run: 
```bash
gcloud run deploy saifguard-ui \
  --image="europe-west1-docker.pkg.dev/saifguard/saifguard/saifguard-ui:latest" \
  --region="europe-west1" \
  --allow-unauthenticated \
  --port="8080" \
  --set-env-vars="MESOP_RUN_TARGET=src.front" \
  --project="saifguard"
```

Trying to deploy from source: 
```bash
gcloud run deploy saifguard-ui \
  --source . \
  --region="europe-west1" \
  --allow-unauthenticated \
  --port="8080" \
  --project="saifguard"
```