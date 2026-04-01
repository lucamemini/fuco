# FUCO API Reference

This document describes the HTTP APIs exposed by FUCO for third‑party integrations.

## Base URL
Use the same host where FUCO is served. Example:
- http://<host>:<port>

## Authentication & CSRF
POST requests should include CSRF protection; some APIs also require an authenticated session.

**Flow**
1. Call POST /api/auth/login with JSON credentials when you need session-protected endpoints (for example responder actions).
2. Store the session cookie returned by the server.
3. Obtain a CSRF token from any HTML page that renders `csrf_token()` (e.g., the UI pages) and send it on POST requests as the `X-CSRFToken` header.

If authentication is missing, endpoints protected by `login_required_json` return 401.

**CSRF allowlist**
If configured, requests from IPs in `CSRF_WHITELIST` bypass CSRF checks. This is intended for trusted automation clients.

## Common Error Format
Most errors are returned as:
- { "error": "message" }

---

## Auth APIs

### POST /api/auth/login
Body:
- username (string)
- password (string)

Response:
- success (bool)
- username (string)
- message (string)

### POST /api/auth/logout
Response:
- success (bool)
- message (string)

### GET /api/auth/status
Response:
- authenticated (bool)
- username (string)
- session_timeout (int)

### POST /api/auth/refresh
Response:
- success (bool)
- message (string)

### POST /api/auth/validate-key
Body:
- api_key (string)

Response:
- valid (bool)

---

## Analyzer APIs

### GET /api/getAnalyzer
Returns the list of analyzers and supported data types.

Response:
- analyzers (array)
- supportedDataTypes (array)

### POST /api/submit_job
Submit a single analyzer job.

Body:
- analyzer (string)
- datatype (string)
- data (string)
- tlp (int, optional)
- pap (int, optional)

Response:
- status: success|error
- job_id (string)
- analyzer (string)
- tlp (int)
- pap (int)

### GET /api/poll_job/<job_id>
Poll a single job status.

Response:
- status: success|pending|failed|error
- job_id (string)
- analyzer_name (string, on success)
- report_status (string, on failure)

### POST /api/short
Run short analysis and return taxonomies.

Body:
- Data (string)
- DataType (string, optional)
- analyzer_list (array of strings)

Response:
- array of results with input/analyzer/status/taxonomies

### POST /api/analysis
Run full analysis and return full reports.

Body:
- Data (string)
- DataType (string, optional)
- analyzer_list (array of strings)

Response:
- question (string)
- datatype (string)
- results (array)

### GET /getAnalysis?JobId=<job_id>
Returns rendered HTML for the LONG template for a job. If the template fails, a generic JSON or error message is returned.

### GET /getShort?JobId=<job_id>
Returns rendered HTML for the SHORT template for a job.

---

## AI Assessment APIs

### POST /api/ai/analyze
Generate an AI assessment for already collected FUCO/Cortex reports. The endpoint is cache-aware and may return either a fresh result or a cached one.

Body:
- observable (string)
- datatype (string)
- jobs (array of job IDs)
- force_refresh (bool, optional; default `false`)

Behavior:
- reports are loaded from FUCO cache using the provided job IDs
- if `AI_REQUIRE_FINAL_RESULTS=True`, non-final jobs return `409`
- if the same normalized bundle was already assessed, the response may return `source: "cache"`
- provider quota errors may return `429` with `retry_after_seconds`

Response:
- ok (bool)
- source (`fresh` or `cache`)
- cache_key (string)
- prompt_version (string)
- model (string)
- latency_ms (int)
- token_usage (object with `input_tokens`, `output_tokens`, `total_tokens`)
- assessment (object)
- created_at (ISO timestamp)

Assessment fields:
- risk_score (0-100)
- risk_level (`low|medium|high|critical|unknown`)
- confidence (0-1)
- summary (string)
- facts (array)
- deductions (array)
- key_findings (array)
- recommended_actions (array)
- limitations (array)

Example:
```json
{
  "observable": "8.8.8.8",
  "datatype": "ip",
  "jobs": ["job-id-1", "job-id-2"],
  "force_refresh": false
}
```

### POST /api/ai/cache-assessment
Return only a cached AI assessment. This endpoint never triggers a new AI provider call.

Body:
- same as `/api/ai/analyze`

Response:
- same shape as `/api/ai/analyze`, with `source: "cache"`

Notes:
- returns `404` if no cached AI assessment is available
- useful for preloading the AI panel in the UI without incurring model cost

---

## Cache APIs

### GET /api/cache/stats
Returns cache statistics.

### POST /api/cache/clear
Clears the cache.

---

## Responder APIs (require authenticated session)

### GET /api/responder/list
Query params:
- dataType (optional)

Response:
- success (bool)
- count (int)
- responders (array)

### POST /api/responder/execute
Body:
- observable (string)
- dataType (string)
- responderId (string)
- tlp (int, optional)
- pap (int, optional)
- message (string, optional)

Response:
- success (bool)
- job_id (string)
- observable (string)
- responder_name (string)
- status (string)
- created_at (string)
- executed_by (string)

### POST /api/responder/bulk
Body:
- observables (array of { data, dataType })
- responderIds (array)
- tlp (int, optional)
- pap (int, optional)
- message (string, optional)

Notes:
- dataType can be omitted; FUCO will auto‑detect when possible.
- Limits: MAX_BULK_OBSERVABLES and MAX_BULK_RESPONDERS.
- Responder access can be restricted per user using `RESPONDER_USER_CONSTRAINTS`.

Response:
- success (bool)
- total_executed (int)
- total_requested (int)
- results (array)

### GET /api/responder/status/<job_id>
Returns responder job status.

### GET /api/responder/poll/<job_id>
Polls until completion. Query params:
- maxAttempts (optional)
- delay (optional)

### GET /api/responder/history?limit=<n>
Returns responder execution history.

### POST /api/responder/validate
Body:
- username (string)
- password (string)

### GET /api/responder/for-observable?dataType=<type>
Returns compatible responders for a data type.

---

## Notes for Integrators
- All POST requests should include `Content-Type: application/json`.
- For POST requests, include `X-CSRFToken` header and session cookies.
- If you cannot change a legacy script, add its source IP to `CSRF_WHITELIST`.
- Rate limits may be enabled per endpoint (see configuration).
