PROJECT_ID = "saifguard-gf-rrag-0g"
REGION = "europe-west4"
MODEL = "gemini-2.5-flash"
GOOGLE_SEARCH_SAIF_PROMPT = """
<Task>
Retrieve the latest, comprehensive documentation for Google's Secure AI Framework (SAIF).
</Task>

<Sources>
Execute searches focused exclusively on the official `saif.google` domain.
Use search queries targeting these specific pages:
1. `site:saif.google/secure-ai-framework/risks`
2. `site:saif.google/secure-ai-framework/controls`
3. `site:saif.google/ai-development-primer`
4. `site:saif.google/secure-ai-framework/components`
5. `site:saif.google/secure-ai-framework/saif-map`
</Sources>

<Instructions>
From the search results of the pages above, find and extract all detailed information for the following topics:
- All core **components** of the SAIF.
- A comprehensive list of identified **risks** related to AI development.
- All specified **controls** and recommended best practices to mitigate those risks.
</Instructions>

<Output>
Return the full, detailed text for components, risks, and controls. The output must be thorough, as it will be used for downstream processing.
</Output>
"""