# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in SecPostureIQ, please report it responsibly:

1. **Email:** Send details to the repository maintainers via the contact information on their GitHub profiles.
2. **GitHub Security Advisories:** Use [GitHub's private vulnerability reporting](../../security/advisories/new) to submit a report directly through the repository.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgement:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Depends on severity; critical issues targeted within 7 days

## Security Best Practices for Deployers

When deploying SecPostureIQ in a customer Azure tenant:

1. **Use Managed Identity** — Never store credentials in environment variables or code.
2. **Follow least-privilege** — Grant only the Microsoft Graph permissions listed in the setup guide.
3. **Enable Content Safety** — Keep the Azure Content Safety middleware active in production.
4. **Rotate secrets** — If using any Key Vault secrets, enable auto-rotation.
5. **Network isolation** — Deploy the Container App in a VNet with restricted ingress where possible.
6. **Audit logging** — Ensure the audit logger middleware is enabled for compliance.

## Dependency Management

- Dependencies are pinned in `pyproject.toml`.
- Dependabot or Renovate should be enabled to receive automated security updates.
- Run `pip audit` periodically to check for known vulnerabilities.
