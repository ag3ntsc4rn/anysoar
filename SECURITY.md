# Security policy

## Reporting a vulnerability

**Please do not open public issues, discussions or pull requests for security vulnerabilities.**

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/ag3ntsc4rn/anysoar/security/advisories/new)
(Security tab → "Report a vulnerability").

Please include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version or commit.

This is a volunteer-maintained project. You can expect an acknowledgement within 7 days. Fixes
will be coordinated with you before public disclosure, and reporters are credited in the
advisory unless they prefer otherwise.

## Supported versions

anysoar is pre-alpha. Only the latest release receives security fixes.

## Scope

anysoar sits between AI agents and security tooling, so issues that let an agent bypass the
policy layer (action tiers, approvals, the audit log or the kill switch) are in scope and are
treated as high severity.
