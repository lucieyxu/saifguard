import os
import sys
import vertexai
from saifguard.config import PROJECT_ID, REGION


def _extract_engine_info(engine):
    resource = getattr(engine, "api_resource", None) or engine
    name = getattr(resource, "name", "") or getattr(engine, "name", "")
    display_name = getattr(resource, "display_name", "") or getattr(engine, "display_name", "")
    engine_id = name.split("/")[-1] if name else ""
    return engine_id, display_name


def ensure_agent_engine(target_display_name: str = "saifguard-session-engine") -> str:
    location = REGION
    print(f"Connecting to Vertex AI in project '{PROJECT_ID}', location '{location}'...")
    try:
        client = vertexai.Client(project=PROJECT_ID, location=location)

        # 1. Search for existing engine by display_name
        try:
            for engine in client.agent_engines.list():
                e_id, d_name = _extract_engine_info(engine)
                if d_name == target_display_name and e_id:
                    print(f"✅ Found existing Agent Platform Runtime '{d_name}' (ID: {e_id})")
                    return e_id
        except Exception as e:
            print(f"Note: Could not list runtime engines ({e}). Attempting creation...")

        # 2. Create lightweight instance if not found
        print(f"Creating new Agent Platform Runtime '{target_display_name}'...")
        created = client.agent_engines.create(
            config={
                "display_name": target_display_name,
                "description": "Agent Platform Runtime for SAIFGuard sessions",
            }
        )
        engine_id, _ = _extract_engine_info(created)
        print(f"✅ Created Agent Platform Runtime '{target_display_name}' (ID: {engine_id})")
        return engine_id
    except Exception as e:
        print(f"⚠️ Warning: Could not create or list Agent Platform Runtime: {e}")
        print("Continuing deployment with default session fallback.")
        return ""


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "saifguard-session-engine"
    engine_id = ensure_agent_engine(name)

    if len(sys.argv) > 2:
        out_path = sys.argv[2]
        try:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(engine_id.strip() if engine_id else "")
            print(f"Wrote ID ('{engine_id}') to {out_path}")
        except Exception as e:
            print(f"Note: Could not write to {out_path}: {e}")

    if engine_id:
        print(f"\nexport AGENT_RUNTIME_ID=\"{engine_id}\"")
