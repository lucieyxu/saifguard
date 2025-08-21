# SAIFGuard

## Local Setup
Change constant in config.py then run: 
```
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