"""
AI assessment manager.
Handles normalization, cache key generation, cache usage and Gemini calls.
"""

import hashlib
import importlib
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Tuple
from urllib import error as url_error
from urllib import parse as url_parse
from urllib import request as url_request

import config_ai as ai_cfg

logger = logging.getLogger(__name__)

try:
    secretai = importlib.import_module("secretai")
except Exception:
    secretai = None


class AIProviderError(RuntimeError):
    """Raised when AI provider returns a structured/known failure."""

    def __init__(self, message: str, status_code: int = 502, retry_after_seconds=None):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


def _extract_retry_after_seconds(detail: str):
    if not detail:
        return None

    retry_delay_match = re.search(r'"retryDelay"\s*:\s*"(\d+)s"', detail)
    if retry_delay_match:
        return int(retry_delay_match.group(1))

    retry_in_match = re.search(r'Please retry in\s+([0-9]+(?:\.[0-9]+)?)s', detail)
    if retry_in_match:
        return max(1, int(float(retry_in_match.group(1))))

    return None


def _json_dumps(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_payload(data) -> str:
    return hashlib.sha256(_json_dumps(data).encode("utf-8")).hexdigest()


def get_api_key() -> str:
    env_key = os.getenv("FUCO_AI_API_KEY") or os.getenv("GEMINI_API_KEY")
    if env_key:
        return env_key

    if secretai is not None:
        key = getattr(secretai, "AI_API_KEY", None)
        if key:
            return key

    cfg_key = getattr(ai_cfg, "AI_API_KEY", None)
    return cfg_key if cfg_key else ""


def is_enabled() -> bool:
    if not getattr(ai_cfg, "AI_ENABLED", False):
        return False
    if getattr(ai_cfg, "AI_PROVIDER", "").lower() != "gemini":
        return False
    return bool(get_api_key())


def build_bundle(observable: str, datatype: str, reports: list) -> dict:
    bundle = {
        "observable": observable,
        "datatype": datatype,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "reports": reports,
    }
    raw = _json_dumps(bundle).encode("utf-8")
    max_size = int(getattr(ai_cfg, "AI_MAX_INPUT_BYTES", 250000))
    if len(raw) > max_size:
        raise ValueError(f"AI input too large ({len(raw)} bytes > {max_size})")
    return bundle


def make_cache_key(bundle: dict) -> str:
    stable = {
        "bundle": bundle,
        "provider": getattr(ai_cfg, "AI_PROVIDER", "gemini"),
        "model": getattr(ai_cfg, "AI_MODEL", "gemini-2.0-flash"),
        "prompt_version": getattr(ai_cfg, "AI_PROMPT_VERSION", "v1"),
        "policy_version": getattr(ai_cfg, "AI_POLICY_VERSION", "v1"),
    }
    return _hash_payload(stable)


def _extract_json_text(gemini_response: dict) -> str:
    candidates = gemini_response.get("candidates") or []
    if not candidates:
        raise ValueError("No Gemini candidates in response")

    first = candidates[0]
    content = first.get("content") or {}
    parts = content.get("parts") or []
    if not parts:
        raise ValueError("No Gemini parts in response")

    text = parts[0].get("text")
    if not text:
        raise ValueError("Gemini response part missing text")
    return text


def _normalize_assessment(raw_assessment: dict) -> dict:
    result = dict(raw_assessment or {})

    result.setdefault("risk_score", 0)
    result.setdefault("risk_level", "unknown")
    result.setdefault("confidence", 0)
    result.setdefault("summary", "No summary provided")
    result.setdefault("key_findings", [])
    result.setdefault("recommended_actions", [])
    result.setdefault("limitations", ["Model output did not include limitations"]) 

    if isinstance(result.get("risk_score"), (int, float)):
        result["risk_score"] = max(0, min(100, int(result["risk_score"])))
    else:
        result["risk_score"] = 0

    if isinstance(result.get("confidence"), (int, float)):
        result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
    else:
        result["confidence"] = 0.0

    return result


def _build_prompt(bundle: dict) -> str:
    return (
        "Analyze the following Cortex results and produce a SOC-oriented assessment. "
        "Output MUST be valid JSON with fields: "
        "risk_score (0-100), risk_level (low|medium|high|critical|unknown), "
        "confidence (0-1), summary (string), key_findings (array of strings), "
        "recommended_actions (array of strings), limitations (array of strings). "
        "Do not include markdown."
        "\n\nINPUT_JSON:\n" + json.dumps(bundle, ensure_ascii=False)
    )


def call_gemini(bundle: dict) -> Tuple[dict, dict]:
    model = getattr(ai_cfg, "AI_MODEL", "gemini-2.0-flash")
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError("AI API key not configured")

    endpoint_tpl = getattr(
        ai_cfg,
        "AI_GEMINI_ENDPOINT_TEMPLATE",
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    )
    endpoint = endpoint_tpl.format(model=model)

    body = {
        "systemInstruction": {
            "parts": [{"text": getattr(ai_cfg, "AI_SYSTEM_PROMPT", "You are a SOC assistant.")}]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": _build_prompt(bundle)}],
            }
        ],
        "generationConfig": {
            "temperature": float(getattr(ai_cfg, "AI_TEMPERATURE", 0.1)),
            "maxOutputTokens": int(getattr(ai_cfg, "AI_MAX_OUTPUT_TOKENS", 1200)),
            "responseMimeType": "application/json",
        },
    }

    url = endpoint + "?" + url_parse.urlencode({"key": api_key})
    payload = json.dumps(body).encode("utf-8")

    req = url_request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    timeout = int(getattr(ai_cfg, "AI_TIMEOUT_SECONDS", 30))
    started = time.time()

    try:
        with url_request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            parsed = json.loads(raw)
    except url_error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
        status_code = int(getattr(e, "code", 502) or 502)
        if status_code == 429:
            retry_after = _extract_retry_after_seconds(detail)
            raise AIProviderError(
                "Gemini quota/rate limit exceeded",
                status_code=429,
                retry_after_seconds=retry_after,
            )
        raise AIProviderError(f"Gemini HTTP error: {status_code}", status_code=status_code)
    except Exception as e:
        raise RuntimeError(f"Gemini request failed: {e}")

    elapsed_ms = int((time.time() - started) * 1000)

    text = _extract_json_text(parsed)
    try:
        assessment = json.loads(text)
    except Exception:
        raise RuntimeError("Gemini did not return valid JSON")

    usage = parsed.get("usageMetadata") or {}
    meta = {
        "model": model,
        "latency_ms": elapsed_ms,
        "token_usage": {
            "input_tokens": int(usage.get("promptTokenCount", 0) or 0),
            "output_tokens": int(usage.get("candidatesTokenCount", 0) or 0),
            "total_tokens": int(usage.get("totalTokenCount", 0) or 0),
        },
    }

    return _normalize_assessment(assessment), meta


def get_or_generate_assessment(cache_manager, bundle: dict, force_refresh: bool = False) -> dict:
    cache_key = make_cache_key(bundle)

    if not force_refresh:
        cached = cache_manager.get_ai_assessment(cache_key)
        if cached:
            response = dict(cached)
            response["source"] = "cache"
            return response

    assessment, meta = call_gemini(bundle)

    response = {
        "ok": True,
        "source": "fresh",
        "cache_key": cache_key,
        "prompt_version": getattr(ai_cfg, "AI_PROMPT_VERSION", "v1"),
        "model": meta["model"],
        "latency_ms": meta["latency_ms"],
        "token_usage": meta["token_usage"],
        "assessment": assessment,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    cache_manager.set_ai_assessment(cache_key, response)
    return response
