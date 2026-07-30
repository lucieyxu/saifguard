import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def load_skill_instructions(skill_name: str, fallback_prompt: str = "") -> str:
    """Dynamically load system instructions from a skill's SKILL.md file."""
    try:
        # Check inside python package directory (production / container runtime)
        pkg_skill = Path(__file__).resolve().parent / "skills" / skill_name / "SKILL.md"
        if pkg_skill.exists():
            LOGGER.info(f"Loaded skill '{skill_name}' from package path: {pkg_skill}")
            return pkg_skill.read_text()

        # Fallback to workspace root .agents/skills/
        root_dir = Path(__file__).resolve().parents[2]
        skill_file = root_dir / ".agents" / "skills" / skill_name / "SKILL.md"
        if skill_file.exists():
            LOGGER.info(f"Loaded skill '{skill_name}' from workspace path: {skill_file}")
            return skill_file.read_text()

    except Exception as e:
        LOGGER.warning(f"Could not load skill '{skill_name}': {e}")

    return fallback_prompt
