# SAIF Pillar 4: Harmonize Platform-Level Controls for Consistent Security

## Core Principles
Agentic workflows (LLMs with autonomous tool calling) and CI/CD pipelines must enforce strict boundaries: least privilege on agent tools, Human-in-the-Loop gates, loop ceilings, and non-root container isolation.

---

## 1. Excessive Agency & Tool Parameter Schemas
* **Threat**: OWASP LLM06. An LLM calls a function with arbitrary or malicious parameters (e.g., SQL injection, shell command execution, uncontrolled file deletion).
* **Audit Checklist**:
  * Check Python functions exposed as tools (`@tool`, `FunctionDeclaration`).
  * Verify all tool arguments enforce strict Pydantic schemas, type constraints, and regex whitelists.
  * Verify tools never pass LLM-supplied strings directly into `os.system()`, `subprocess.Popen(shell=True)`, or raw SQL cursors.
* **Remediation**:
```python
from pydantic import BaseModel, Field, constr

class SafeQueryInput(BaseModel):
    account_id: constr(pattern=r"^[A-Z0-9]{8,12}$") = Field(description="Alphanumeric account ID")
    limit: int = Field(default=10, ge=1, le=50)

@tool(args_schema=SafeQueryInput)
def get_account_summary(account_id: str, limit: int) -> dict:
    # Safe parameterized query execution
    return db.query("SELECT * FROM accounts WHERE id = :id LIMIT :limit", {"id": account_id, "limit": limit})
```

---

## 2. Human-in-the-Loop (HITL) Verification
* **Threat**: Autonomous agent takes irreversible actions (money transfers, database drops, email broadcasts) without explicit human confirmation.
* **Audit Checklist**:
  * Any tool with state-changing or destructive side effects (`delete_*`, `transfer_*`, `update_*`) MUST require interactive approval before execution.

---

## 3. Runaway Loop & Budget Ceiling Protection
* **Threat**: OWASP LLM10. Malicious prompt causes an agent to enter an infinite tool-calling loop, consuming thousands of dollars in tokens.
* **Audit Checklist**:
  * Agent runners must configure `max_iterations` (typically $\le 15$).
  * Calls to external tools must specify hard timeouts (e.g. 10 seconds).

---

## 4. Container & Supply Chain Security
* **Threat**: Container breakout, compromised build dependencies.
* **Audit Checklist**:
  * Dockerfiles MUST include `USER <non-root-user>` and NEVER run as root (`USER 0`).
  * Base images MUST pin immutable sha256 digests (`@sha256:...`) rather than floating tags (`:latest`).
  * Build arguments MUST NEVER contain plaintext secrets (`ARG SECRET=...`).
