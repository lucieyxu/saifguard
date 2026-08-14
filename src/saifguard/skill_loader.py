import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).resolve().parent / "skills"


def _strip_frontmatter(text: str) -> str:
    """Remove the leading YAML frontmatter block from a SKILL.md.

    The `name`/`description` keys are metadata for humans picking a skill; they
    are not instructions and should not reach the model.
    """
    if not text.startswith("---"):
        return text
    parts = text.split("---", 2)
    # ["", "<frontmatter>", "<body>"] when a closing delimiter is present.
    if len(parts) < 3:
        return text
    return parts[2].lstrip("\n")


def load_skill_instructions(skill_name: str, fallback_prompt: str = "") -> str:
    """Load the prompt body of a skill's SKILL.md, without its frontmatter."""
    skill_file = SKILLS_DIR / skill_name / "SKILL.md"
    try:
        body = _strip_frontmatter(skill_file.read_text())
        LOGGER.info(f"Loaded skill '{skill_name}' from {skill_file}")
        return body
    except OSError as e:
        # An audit prompt silently degrading to a stub would produce a report
        # with no severity ordering and no output format, so make it loud.
        LOGGER.error(
            f"Could not load skill '{skill_name}' from {skill_file} ({e}). "
            f"Falling back to a minimal prompt; audit output will be degraded."
        )
        return fallback_prompt
