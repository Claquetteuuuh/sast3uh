# Security Policy

sasteuuuh runs other people's scanners on other people's code. A bug in it
is a security bug by default, and it is treated as one.

## Supported versions

Only the latest release and `main` receive security fixes.

| Version        | Supported |
| -------------- | --------- |
| latest release | ✅        |
| `main`         | ✅        |
| anything older | ❌        |

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub's
vulnerability reporting:

<https://github.com/Claquetteuuuh/sasteuuuh/security/advisories/new>

Include the version (`sasteuuuh --version`), the scanner(s) involved, a
minimal reproduction and the impact you see. You will get an
acknowledgement within 72 hours and a fix or a mitigation plan within 14
days for a confirmed issue. Credit is given in the advisory unless you
prefer otherwise.

## What is in scope

- Anything that lets scanned code or scanner output execute commands,
  read or write files outside the target, or escape the sandbox the
  wrapper gives each scanner.
- Argument or environment injection into a scanner invocation.
- Findings silently dropped, deduplicated away or downgraded so that a
  real issue never reaches the report or the exit code.
- Secrets (tokens, environment) leaking into reports, logs or artifacts.
- Weaknesses in this repository's own supply chain (CI workflows,
  dependency pins, release process).

## What the project does to stay safe

- No `unsafe` (forbidden at the crate level); no panics, unwraps or
  blind indexing in library code (clippy denies them).
- Every scanner is spawned with an argument list, never a shell string,
  with a scrubbed environment, a working directory, a timeout and an
  output cap.
- Every commit goes through pre-commit (secrets, lint, tests), Bearer,
  Grype, cargo-deny; every push through Semgrep; CI adds CodeQL, zizmor,
  Plumber, Dependency Review and OpenSSF Scorecard.
- Every GitHub Action is pinned by commit SHA; Dependabot holds new
  releases back for a cooldown window before proposing them.
