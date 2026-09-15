# Contributing

Thanks for looking at Strata. This page is short on purpose — the README sets
the quality bar; this is how PRs meet it.

## Running the app

Python 3.8 or later, no install step:

```bash
python3 run.py          # then open http://127.0.0.1:8722
```

## What a PR needs

- **Verify the behaviour against the running app** and say which OS and Python
  you used. The repo has no heavy test culture; a described observation from
  the real interface is the equivalent here.
- **CI must pass.** The workflow byte-compiles the engine, checks the web
  frontend, runs the cross-platform smoke matrix (which launches the real
  server), and runs the unit tests.
- Keep the diff focused: one behaviour per PR, no drive-by reformatting.

## The rules that make this codebase what it is

Reviewers read PRs against these, so state any exception up front:

- **Standard library only.** No third-party dependencies, in the engine or in
  the tests. A PR that adds one needs a very good reason.
- **Nothing touches the network.** The local HTTP interface serves the UI on
  loopback; the app never calls out.
- **Evidence is opened read-only.** Writes belong to the case database, the
  index, and preferences — never to the exhibit.
- **All colours resolve through CSS custom properties**, the canvas renderers
  included. A new theme is a variable block, not scattered colour values —
  this keeps theming pure data.

## Tests

Unit tests live in `tests/` (stdlib `unittest`) and the smoke script launches
the app itself:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
python3 tests/smoke.py
```

Run both before pushing. If your change touches a parser, a test that feeds
it malformed input is worth more than one that feeds it a happy path.

## Reporting problems

Please don't open public issues for anything exploitable — see
[`SECURITY.md`](SECURITY.md) for the private route. Bug reports and feature
requests use the issue templates; the bug template asks for OS + Python
version and, where possible, a synthetic image or case file that reproduces
the problem (never real evidence).