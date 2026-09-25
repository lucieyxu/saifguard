import logging
import os
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def _strip_frontmatter(text: str) -> str:
    """Remove the leading YAML frontmatter block from a SKILL.md."""
    if not text.startswith("---"):
        return text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return text
    return parts[2].lstrip("\n")


def get_candidate_skill_dirs() -> list[Path]:
    """Return ordered search paths for skill resolution."""
    dirs: list[Path] = []

    # 1. Environment variable override
    env_dir = os.environ.get("SAIFGUARD_SKILLS_DIR")
    if env_dir:
        dirs.append(Path(env_dir))

    # 2. Local container / package directory: src/saifguard/skills
    dirs.append(Path(__file__).resolve().parent / "skills")

    # 3. Local workspace override: .agents/skills
    dirs.append(Path.cwd() / ".agents" / "skills")

    # 4. Global user config directory
    dirs.append(Path.home() / ".gemini" / "config" / "skills")

    # 5. Repo root skills directory (if present in development)
    dirs.append(Path(__file__).resolve().parents[2] / "skills")

    return dirs


def resolve_skill_dir(skill_name: str) -> Path | None:
    """Find the first matching skill directory across candidate directories."""
    for base_dir in get_candidate_skill_dirs():
        candidate = base_dir / skill_name
        if (candidate / "SKILL.md").is_file():
            return candidate
    return None


def resolve_skill_file(skill_name: str) -> Path | None:
    """Find the first matching SKILL.md across candidate directories."""
    skill_dir = resolve_skill_dir(skill_name)
    return (skill_dir / "SKILL.md") if skill_dir else None


def load_skill_instructions(
    skill_name: str,
    fallback_prompt: str = "",
    references: list[str] | None = None,
) -> str:
    """Load the prompt body of a skill's SKILL.md and optional reference files."""
    # Map legacy skill names to unified saifguard skill + reference
    effective_skill = skill_name
    auto_refs = list(references) if references else []
    if skill_name == "gcp_security_audit":
        effective_skill = "saifguard"
        if "saif_gcp_live_audit.md" not in auto_refs:
            auto_refs.append("saif_gcp_live_audit.md")
    elif skill_name == "design_file_audit":
        effective_skill = "saifguard"
        if "saif_design_doc_audit.md" not in auto_refs:
            auto_refs.append("saif_design_doc_audit.md")

    skill_dir = resolve_skill_dir(effective_skill)
    if not skill_dir:
        LOGGER.error(
            f"Could not load skill '{effective_skill}' from any candidate directory. "
            f"Falling back to a minimal prompt; audit output will be degraded."
        )
        return fallback_prompt

    try:
        skill_file = skill_dir / "SKILL.md"
        parts = [_strip_frontmatter(skill_file.read_text(encoding="utf-8"))]
        for ref_name in auto_refs:
            ref_path = skill_dir / "references" / ref_name
            if ref_path.is_file():
                parts.append(f"\n\n---\n\n{ref_path.read_text(encoding='utf-8')}")
            else:
                LOGGER.warning(f"Reference file '{ref_name}' not found at {ref_path}")

        LOGGER.debug(f"Loaded skill '{effective_skill}' (refs: {auto_refs}) from {skill_dir}")
        return "\n".join(parts)
    except OSError as e:
        LOGGER.error(
            f"Could not read skill '{effective_skill}' from {skill_dir} ({e}). "
            f"Falling back to a minimal prompt."
        )
        return fallback_prompt
