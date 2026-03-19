"""
Configuration for AI assessment integration.

Keep non-secret settings here.
Secrets (API keys) must be stored in secretai.py or environment variables.
"""

# Enable/disable AI assessment feature
AI_ENABLED = False

# Provider configuration
AI_PROVIDER = 'gemini'  # currently supported: gemini
AI_MODEL = 'gemini-2.0-flash'

# Prompt & policy versioning (used in cache key)
AI_PROMPT_VERSION = 'v1'
AI_POLICY_VERSION = 'v1'

# Request limits / behavior
AI_TIMEOUT_SECONDS = 30
AI_MAX_JOBS = 100
AI_MAX_INPUT_BYTES = 250000
AI_TEMPERATURE = 0.1
AI_MAX_OUTPUT_TOKENS = 1200
AI_REQUIRE_FINAL_RESULTS = True

# Cache
AI_CACHE_TTL_MINUTES = 240

# Optional data protection toggles
AI_REDACTION_ENABLED = False

# Gemini endpoint template
AI_GEMINI_ENDPOINT_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# Optional explicit key in non-secret config (not recommended)
AI_API_KEY = None

# System prompt
AI_SYSTEM_PROMPT = (
    "You are a SOC assistant. Analyze the provided Cortex analyzer results and return "
    "ONLY valid JSON. Do not include markdown, prose, or code fences."
)

# Output schema contract (used for parser validation by backend)
AI_OUTPUT_REQUIRED_FIELDS = [
    "risk_score",
    "risk_level",
    "confidence",
    "summary",
    "key_findings",
    "recommended_actions",
    "limitations",
]
