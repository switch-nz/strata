# Contributing

Strata is early, and the shape of it is still moving. Issues, reproductions
and patches are all welcome.

## Running it

Python 3.8 or later. There is no install step and nothing to build.

```bash
python3 run.py          # then open http://127.0.0.1:8722
python3 run.py --browser
```

The interface is plain HTML, CSS and JavaScript served from `web/` — no
bundler, no transpiler. Edit a file and reload the page.

## The rules that make this codebase what it is

These are review criteria, not aspirations. A change that breaks one of them
will be asked to justify itself.

**Standard library only.** `engine/` has no third-party imports and depends on
nothing but Python itself; the interface loads no frameworks and no remote
assets. That is why there is no install step, why it runs on an isolated
machine, and why the whole thing can be read. A pull request that adds a
dependency needs a very good reason, and "it would be convenient" is not one.

**Nothing touches the network.** No telemetry, no update checks, no fetching
anything at runtime. Evidence sits on machines where outbound traffic is a
problem in itself.

**Evidence is read-only.** Images are opened read-only and stay that way.
Anything derived — caches, extractions, reports — is written beside the case,
never back into the evidence.

**Colours resolve through CSS custom properties.** Every colour, including the
ones the canvas renderers use, comes from a custom property defined on
`:root`; the canvas code reads them with `getComputedStyle().getPropertyValue()`
rather than holding literals. That is what keeps a theme pure data: a new
theme is one `:root[data-theme="…"]` block and an entry in the theme list, and
nothing has to be taught about it. The one deliberate exception is the swatch
previews in the theme picker, which show colours from *other* themes and so
cannot resolve against the active one.

**Say what was measured.** Where the tool reports a finding, it reports how it
was reached — what was searched, what was skipped, where a walk was truncated,
how a carved length was decided. Do not add a result that cannot explain
itself.

## Pull requests

Keep the change and its justification in one place: what it does, why, and how
you know it works.

There is no test suite yet — [adding the first one][tests] is open, and so is
[CI][ci]. Until those land, the standard is behaviour verified against the
running application:

- Say what you exercised in the interface, and on which OS and Python version.
- If it touches parsing, say what evidence you ran it against. Synthetic
  images are ideal and can be shared; real case material must not be attached
  to an issue or a pull request.
- If it touches the interface, check it in more than one theme — light and
  dark at minimum.

Platform-specific code paths (`os.name == 'nt'`, `sys.platform == 'darwin'`)
are easy to break from one machine. If you cannot test the other platforms,
say so rather than assuming.

## Reporting bugs

Use the issue templates. What matters most is the version of Python and the
OS, what was open at the time, and a reproduction — ideally against evidence
you can share.

Security problems go to the private channel in [`SECURITY.md`](SECURITY.md),
not to the issue tracker.

[tests]: https://github.com/switch-nz/strata/issues/3
[ci]: https://github.com/switch-nz/strata/issues/2
