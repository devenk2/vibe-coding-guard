# NIST SSDF — PW: Produce Well-Secured Software

These rules map to the NIST SSDF "Produce Well-Secured Software" practice group.

## PW.5 — Validate All Inputs
- **Never write user input directly to a database without validation** — even with ORMs and parameterized queries
- Validate all inputs: enforce length limits, type constraints, and format checks
- Sanitize text inputs to prevent stored XSS (e.g., html.escape(), bleach.clean(), DOMPurify)
- Use parameterized/prepared statements for all database queries
- Never build SQL queries with string concatenation, f-strings, or % formatting
- Use allowlists over denylists for input validation
- For Python: use Pydantic Field(max_length=...) and field_validator decorators
- For JS: use validation libraries (Joi, Zod, express-validator) on all route handlers

## PW.6 — Prevent Code Injection
- Never use eval(), exec(), or similar dynamic code execution
- For Python: use ast.literal_eval() instead of eval() for safe literal parsing
- For Python: use subprocess.run() with argument lists, never shell=True
- For Python: use yaml.safe_load() instead of yaml.load()
- For Python: avoid pickle for untrusted data; use JSON instead
- For JS: avoid eval(), new Function(), and setTimeout/setInterval with strings

## PW.7 — Use Strong Cryptography
- Never use MD5 or SHA1 for security purposes (password hashing, integrity checks)
- Use SHA-256 or SHA-3 for hashing
- Use bcrypt, scrypt, or argon2 for password hashing
- Use cryptographically secure random number generators

## PW.8 — Handle Errors Properly
- Never use bare except: clauses — catch specific exception types
- Never silently swallow exceptions with pass
- Log security-relevant errors for monitoring
- Do not leak sensitive information in error messages

## PW.9 — Secure Configuration
- Never disable SSL/TLS certificate verification (verify=False, rejectUnauthorized: false)
- Use HTTPS for all external communication
- Never set file permissions to 777
- Follow the principle of least privilege
