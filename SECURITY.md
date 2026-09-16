# Security

Strata reads forensic evidence and can unlock encrypted volumes. If you find a
way to subvert either, please report it privately rather than in a public
issue.

## Supported versions

This is an initial release, and there is only one line of development.
Security fixes land on `main` and are included in the next release. Older
checkouts are not patched in place.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

**<https://github.com/switch-nz/strata/security/advisories/new>**

That channel is private to the maintainers until an advisory is published.
Please do not open a public issue for anything exploitable.

Include what you would want to receive: the evidence or input that triggers
it, the OS and Python version, and what you believe an attacker gains. A
synthetic image that reproduces the problem is worth more than a description
of one — do not send real case material.

Expect an acknowledgement within a week. If a fix is warranted, you will be
credited in the advisory unless you would rather not be.

## Scope

**In scope**

- The parsing surface in `engine/` — image formats, filesystems, registry
  hives, artefact and database parsers. These read attacker-controlled bytes
  by definition; memory exhaustion, infinite loops, path traversal on
  extraction, or anything that escapes the parser and reaches the host is a
  vulnerability.
- The local HTTP API and the interface it serves, including the preview
  pane's removal of active content.
- Case-file handling and the audit log — in particular, any way to alter
  recorded history without the chain reporting it.
- Key handling for BitLocker and LUKS unlock.

**Out of scope**

- The trust assumptions of the evidence formats themselves. A crafted image
  that is parsed exactly as its format specifies is not a vulnerability, even
  where the result is misleading; report that as a correctness issue.
- Serving the interface to other machines on purpose. `--host 0.0.0.0` is
  documented as unauthenticated (see below) — reaching an interface someone
  deliberately exposed is the documented behaviour, not a flaw.
- Findings that require an attacker who already has the examiner's account on
  the examination machine.

## Serving the interface over a network

By default Strata binds to `127.0.0.1` and is reachable only from the machine
it runs on.

`--host 0.0.0.0` serves the full interface to the network **with no
authentication**. Anyone who can reach the port can drive the session, open
evidence, read case data, and trigger unlock attempts. There is no login, no
token, and no transport encryption. Use it only on a network you trust, and
prefer an SSH tunnel to exposing the port.
