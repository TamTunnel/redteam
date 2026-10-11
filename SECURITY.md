# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for a suspected security vulnerability in Redteam
itself. Report it privately to:

**security@tamtunnel.dev**

Include in your report:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (minimal fixture or rule file preferred).
- The affected version / commit hash.
- Any suggested fix, if you have one.

## Disclosure

We follow coordinated disclosure with a **90-day window**: we will work with you
to confirm and fix the issue, and public disclosure happens 90 days after your
report (or sooner, by mutual agreement) once a fix is available.

## Scope

Redteam is a *scanner* — it reads code and never executes it, with one documented exception: `redteam.config.js` is loaded via dynamic `import()` and therefore executed (standard practice, same as eslint/vite — see README). Reports about the
security of code that Redteam *flags* are the scanner's job, not vulnerabilities
in Redteam. This policy covers bugs in Redteam itself: its engines, rule
registry, reporters, action wrapper, and release artifacts.
