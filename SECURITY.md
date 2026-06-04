# Security Policy

## Supported Versions

- **SecureVault** `main` branch – fully supported.
- No older tags are maintained.

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not** open a public issue. Instead, follow these steps:

1. **Email** the details confidentially to `topherbot@proton.me`.
2. Include a clear description of the issue, steps to reproduce, and potential impact.
3. Do not disclose the vulnerability publicly until we have released a fix.

We aim to acknowledge receipt within 48 hours and provide a remediation timeline.

## Disclosure Policy

We follow a **responsible disclosure** process. After a fix is deployed, we will:

- Publish a CVE identifier (if applicable).
- Update the `CHANGELOG.md` with a brief summary.
- Credit the reporter (if they consent).

## Security Best Practices for Deployers

- Run SecureVault behind TLS termination (e.g., Nginx or Caddy).
- Set a strong `SECRET_KEY` environment variable.
- Regularly rotate JWT signing keys and database backups.
- Restrict database file permissions to the service user only.
- Enable OS‑level firewall rules to restrict inbound traffic.

---

Thank you for helping keep SecureVault safe!
