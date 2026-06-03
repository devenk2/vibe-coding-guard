# NIST SSDF — API Security

These rules extend the NIST SSDF practice groups with API-specific security checks.
They apply to REST/HTTP APIs built with any framework (FastAPI, Flask, Django, Express, etc.).

## PW.5 — API Input Validation & SSRF Prevention
- **Never let user input control the full URL** for server-side HTTP requests (SSRF)
- Validate and allowlist target URLs/hosts before making outbound requests
- Use `urllib.parse` (Python) or `URL` constructor (JS) to validate URL scheme and host
- Restrict redirect targets to an allowlist — never redirect to user-supplied URLs (open redirect)
- Set body size limits on API request parsers (e.g., `express.json({ limit: '100kb' })`)
- Validate `Content-Type` headers on incoming requests

## PW.6 — Secure API Deserialization
- Never deserialize YAML from API request bodies with an unsafe loader
- Use `yaml.safe_load()` for any YAML from external sources
- Prefer JSON as the API data interchange format

## PW.7 — JWT & Token Security
- Always verify JWT signatures — never use `verify=False`
- Never allow JWT algorithm `"none"` — enforce a strong algorithm (`HS256`, `RS256`)
- Rotate signing keys periodically
- Set appropriate token expiration (`exp` claim)

## PW.8 — API Error Handling & Data Exposure
- Never return stack traces, tracebacks, or `str(e)` in API error responses
- Return generic error messages to clients; log details server-side only
- Exclude sensitive fields (`password`, `secret`, `token`, `ssn`) from API responses
- Use explicit response models/serializers — avoid `fields = '__all__'`

## PW.9 — API Configuration & Access Control
- **Never use wildcard CORS origins** (`Access-Control-Allow-Origin: *`) with credentials
- Restrict CORS to specific trusted domains
- Add rate limiting to all API endpoints (Python: slowapi, flask-limiter; JS: express-rate-limit)
- Add security headers middleware (Python: flask-talisman, starlette; JS: helmet)
- Protect mutation endpoints (POST/PUT/PATCH/DELETE) with authentication middleware
- Set timeouts on all outbound HTTP requests to prevent resource exhaustion

## RV.1 — API Credential Management
- Never pass API keys or tokens as URL query parameters (`?api_key=...`)
- Send credentials via `Authorization` header or POST body
- API keys in URLs are logged in server logs, proxy logs, browser history, and Referer headers
