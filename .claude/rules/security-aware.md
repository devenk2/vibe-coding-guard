# Security-Aware Development

This project uses Vibe Coding Guard for automated security scanning.

## Before Writing Code
- Consider security implications of your changes
- Think about what inputs your code will handle and how they could be abused
- Check if the libraries you're using have known vulnerabilities

## When Writing Code
- Follow the principle of least privilege
- Validate inputs at trust boundaries
- Use safe defaults (HTTPS, parameterized queries, no eval)
- Handle errors explicitly without leaking sensitive information

## After Writing Code
- Review security findings from Vibe Coding Guard
- Fix all HIGH severity issues immediately
- Address MEDIUM severity issues before merging
- Document any intentional exceptions with justification
