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