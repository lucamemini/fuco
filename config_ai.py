"""
Configuration for AI assessment integration.

Keep non-secret settings here.
Secrets (API keys) must be stored in secretai.py or environment variables.
"""

# Enable/disable AI assessment feature
AI_ENABLED = True

# Provider configuration
AI_PROVIDER = 'gemini'  # currently supported: gemini
AI_MODEL = 'gemini-flash-latest'

# Prompt & policy versioning (used in cache key)
AI_PROMPT_VERSION = 'v3'
AI_POLICY_VERSION = 'v1'

# Request limits / behavior
AI_TIMEOUT_SECONDS = 60
AI_TIMEOUT_RETRIES = 1
AI_MAX_JOBS = 100
AI_MAX_INPUT_BYTES = 250000
AI_PROMPT_INJECTION_GUARD_ENABLED = True
AI_PROMPT_MAX_STRING_CHARS = 1200
# Short-report limits (condensed AI payload — no raw JSON blobs embedded)
AI_MAX_TAGS_PER_REPORT = 5        # max taxonomy tags per analyzer sent to AI
AI_MAX_TAG_VALUE_LEN = 80         # max chars for a single tag string
AI_MAX_EVIDENCE_PER_REPORT = 3    # max summary-derived evidence lines per analyzer
AI_MAX_EVIDENCE_VALUE_LEN = 120   # max chars for a single evidence line
AI_MAX_FULL_REPORT_BYTES_PER_REPORT = 100000  # cap per premium full_report to avoid bundle overflow
AI_PREMIUM_ANALYZERS = [
    'virustotal',
    'abuseipdb',
    'misp',
    'maltiverse',
    'scorpion',
]
AI_TEMPERATURE = 0.1
AI_MAX_OUTPUT_TOKENS = 4096  # Gemini Flash max is 8192; 4096 fits full JSON schema (facts/deductions/findings/actions)
AI_REQUIRE_FINAL_RESULTS = True

# AI call logging
AI_LOG_REQUEST_RESPONSE = True
AI_LOG_FULL_JSON = False   # Set True only for temporary deep debugging
AI_LOG_MAX_CHARS = 1000    # Clip long excerpts to keep logs readable/safe

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
    "ONLY valid JSON. Do not include markdown, prose, or code fences. Respond in Italian."
)

# Output schema contract (used for parser validation by backend)
AI_OUTPUT_REQUIRED_FIELDS = [
    "risk_score",
    "risk_level",
    "confidence",
    "summary",
    "facts",
    "deductions",
    "key_findings",
    "recommended_actions",
    "limitations",
]
