# Security policy

Strata is an offline forensic tool: it reads evidence images, keeps cases on
disk, and normally talks only to `127.0.0.1`. Its trust story matters, so
reports are taken seriously and handled privately.

## Supported versions

Strata has just had its initial release, so every version currently published
is supported by security fixes.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting for this repository
(**Security → Report a vulnerability**), or contact the maintainer directly.
Include:

- the Strata version and the platform it ran on
- what an attacker could do with the flaw, and how you reached that
- a reproducer — a synthetic image or case file is ideal; please do not send
  real evidence

You can expect an initial response within two weeks. Fixes will be credited to
the reporter on request.

## Scope

In scope:

- the engine's parsing surface: image formats, filesystem parsers, registry,
  archive and artefact parsers, anything that consumes untrusted bytes
- the local HTTP interface and its request gating (origin/host checks,
  session cookies)
- case files: the audit log's tamper-evidence, case SQLite handling
- the password handling for BitLocker and LUKS unlock

Out of scope:

- the trustworthiness of the evidence itself — a malformed exhibit is
  input, not an attack surface; format bugs are exactly what the report
  chain is for
- issues requiring write access to the examiner's own machine first

## Notes for deployers

- `python3 run.py --host 0.0.0.0` serves the interface to the network with
  **no authentication**: anyone who can reach the port can drive the session.
  Use it only on a trusted, isolated network.
- Evidence is opened read-only, but the case folder is not — protect it like
  any case record.