#!/bin/bash
set -e

# Default to "mesop" if APP_TYPE is not set
APP_TYPE=${APP_TYPE:-mesop}

echo "Starting application with APP_TYPE: $APP_TYPE"

if [ "$APP_TYPE" = "api" ]; then
    # Run the FastAPI app
    exec uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}
elif [ "$APP_TYPE" = "adk-web" ] || [ "$APP_TYPE" = "adk" ] || [ "$APP_TYPE" = "adk_ui" ]; then
    # Run the built-in ADK Web UI
    exec python run_adk_web.py
else
    # Run the Mesop UI
    exec python run_front.py
fi
