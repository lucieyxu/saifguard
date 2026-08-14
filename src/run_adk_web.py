import os
import sys
from google.adk.cli import main

if __name__ == "__main__":
    port = os.environ.get("PORT", "8080")
    host = os.environ.get("HOST", "0.0.0.0")
    sys.argv = ["adk", "web", ".", "--host", host, "--port", str(port)]
    main()
