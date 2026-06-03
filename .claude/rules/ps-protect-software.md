# NIST SSDF — PS: Protect the Software

These rules map to the NIST SSDF "Protect the Software" practice group.

## PS.1 — Protect Code and Artifacts
- Never force-push to main/master branches
- Do not run destructive commands (rm -rf) on system or root directories
- Do not write to system configuration directories (/etc/)
- Protect against destructive disk operations (mkfs, dd on devices)

## PS.2 — Secure the Development Environment
- Use version control for all source code
- Protect CI/CD pipelines from injection attacks
- Review third-party actions and scripts before use

## PS.3 — Protect the Software Supply Chain
- Pin all dependency versions explicitly (package==1.2.3)
- Use lockfiles (requirements.txt with pinned versions, package-lock.json, poetry.lock)
- Never pipe remote content directly to shell (curl | bash)
- Verify checksums for downloaded artifacts
- Review dependencies before adding them to your project
- Avoid running containers in privileged mode
