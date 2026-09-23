# Contributing to ZSV

Thanks for considering a contribution to ZSV (Zeus Scanner Vuln). This
project stays useful only if it stays trustworthy, so a few ground rules
below are stricter than a typical repo.

## Ground rules

1. **Never commit real scan data.** No target IPs/hostnames from real
   engagements, no `.db` files, no generated reports. `.gitignore` already
   excludes these -- don't work around it.
2. **New scanner modules must be non-destructive by default.** Detection
   should never require an actual exploit, data exfiltration, or anything
   that could degrade the target's availability. If a check is inherently
   higher-risk (e.g. an authenticated brute-force module), it must be
   opt-in via an explicit flag and clearly documented as such.
3. **Every module returns data, the CLI decides what to do with it.**
   Follow the existing pattern (see `zsv/scanners/headers_scanner.py`):
   a scanner function takes plain arguments and returns a list of
   dataclasses/dicts. It should not touch the database or the CLI directly
   -- that wiring belongs in `zsv/main.py`.
4. **Tests required for new detection logic.** If you add a check that
   flags something, add a test with both a positive case (it fires) and a
   negative case (it doesn't false-positive) -- see `tests/test_zsv.py`
   for the pattern (a tiny `http.server` fixture is usually enough).

## Development setup

```bash
git clone <this repo>
cd zsv
python3 -m pip install -e ".[dev]"   # or: pip install -r requirements.txt
python3 -m unittest discover tests -v
```

## Pull requests

- Keep PRs focused -- one module/fix per PR is easier to review than a
  grab-bag.
- Describe what the change detects (or fixes) and how you tested it.
- CI runs the unit test suite on every PR; please make sure it's green
  before requesting review.

## Reporting bugs / requesting features

Open a GitHub issue. For anything that looks like a security bug in ZSV
itself (as opposed to a bug in a detection rule), see `SECURITY.md` instead
of filing a public issue.

## Code style

Plain, readable Python (type hints where they help, dataclasses over bare
dicts for structured results, no dependencies beyond what's already in
`requirements.txt` unless there's a strong reason). If in doubt, match the
style of the module you're editing.
