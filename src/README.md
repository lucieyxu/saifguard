# SAIFGuard

## Local Setup
Change constant in ./saifguard/config.py.

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