# Security Policy

ZSV (Zeus Scanner Vuln) is a dual-use security tool: the same features that
make it useful for defensive testing (port/service discovery, XSS probing,
CVE matching) could be misused against systems the operator does not own or
control. This document covers both directions: how we handle security
reports about ZSV itself, and the rules for how ZSV is meant to be used.

## Responsible use of ZSV (read this first)

- **Only scan targets you own or have explicit, written authorization to
  test.** Unauthorized scanning/probing of systems is illegal in most
  jurisdictions (e.g. the U.S. CFAA, UK Computer Misuse Act, and equivalents
  elsewhere), even when no damage results.
- ZSV enforces this at the tool level: it refuses to run any scan unless you
  pass `--authorized`. That flag is your representation that you have the
  right to test the target -- ZSV cannot verify authorization for you, and
  passing it does not make an unauthorized scan legal.
- The XSS module only sends inert marker payloads (no external callbacks,
  no data exfiltration, no code execution) and never follows links off the
  single host you specify.
- If you're scanning on behalf of an employer or client, get written scope
  and authorization *before* running ZSV, not after.

## Reporting a vulnerability in ZSV itself

If you find a security issue in ZSV's own code (e.g. something that could
let a malicious *target* server attack the person running the scanner, a
SQL injection in the database layer, an SSRF beyond the intended target,
credential/API-key leakage, etc.), please report it privately rather than
opening a public issue:

- Open a private security advisory via the repository's **Security** tab
  ("Report a vulnerability"), or
- Email the maintainers directly (see the repository's contact info).

Please include: the affected version/commit, steps to reproduce, and the
potential impact. We'll acknowledge reports within a few business days and
aim to ship a fix or mitigation before any public disclosure.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x (latest `main`) | Yes |

This project is pre-1.0; only the latest `main` branch receives fixes.

## Scope

In scope: ZSV's own Python code (`zsv/` package) -- the database layer, the
scanner modules, the CVE client, and the report renderer.

Out of scope: vulnerabilities in Nmap or Nikto themselves (report those
upstream), and any target system ZSV is pointed at.
