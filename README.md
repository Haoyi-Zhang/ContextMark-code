# TDSC-01 executable artifact

The artifact checks implementation correspondence for the context-bound lineage compiler, finite threshold carrier, predictable risk bounds, recovery discipline, and the repaired multi-context trace contract. It is not a production watermark or proof-assistant development.

## Run

From `artifact/`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m unittest discover -s tests -q
PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 sh run_experiments_sharded.sh reproduced
```

Read-only package verification has two valid, project-scoped entry points:

```bash
# From the full TDSC-01 project root
PYTHONDONTWRITEBYTECODE=1 python artifact/verify_release.py --root . --evidence-dir artifact/reproduced

# From a standalone artifact root
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python verify_release.py --root . --evidence-dir reproduced
```

The full-package command checks paper and citation keys, parses the current PDFs, checks retained execution evidence, and optionally runs tests. The standalone command checks artifact execution evidence and tests. Neither fixes author slots, page counts, or manuscript bytes to a historical package.

Requirements are CPU-only Python 3.12 or later and the two versions in `requirements.txt`. A complete run can also use `python -B run_experiments.py --out reproduced`. The output directory must be absent or empty at preparation; existing evidence is never deleted. A sharded continuation must use the same output directory. Its version-2 manifest binds current sources against the artifact root and generated evidence against the output root, including when output is outside this repository.

`results/` retains the earlier Linux campaign and its original source bindings and 89-test result. The current suite has 107 tests: 12 regressions check restoration of complete canonical request transcripts, invalid risk inputs, and preservation of previous evidence; six additional tests cover restore-index membership and matched session transcripts. All 107 pass locally on Windows with CPython 3.12.14, cryptography 46.0.4, and SciPy 1.17.0. Historical CPU measurements are not overwritten or relabeled as current runs. After source changes, the old run manifest is expected not to match current sources; do not refresh its digests to conceal that difference. Verify a new run with `--evidence-dir` instead.

Recovery authenticates snapshots and additionally validates request identities, canonical program bytes, request-to-record agreement, and successful ancestry of every non-genesis terminal attempt. It still does not implement persistent pending reservations or prevent rollback to an older authenticated snapshot. Risk formulas require nonnegative integer budgets and valid primitive probabilities; invalid inputs are rejected, not assigned a zero-security-loss result.

The `scientific-checks.yml` workflow targets a flat artifact repository on Ubuntu 24.04. It installs the declared dependencies, bounds the complete owned finite run, retains scientific failure gates, and uploads raw output even after failure. The retained Linux run in `results/current/` passed the then-current 101 tests without skips, rejected all 47 mutations, and checked 4,352 compiled coalition cells, 128 closure cases, 4,802 field-reader cases and 496 threshold cases. Recovery and terminal-state checks passed in that run. Its CPU measurements remain tied to that execution; a fresh run exercises all 107 current tests.

## Evidence interpretation

The portable restore regression runs with `python -B -m unittest discover -s tests -p test_restore_membership.py -v`.
It uses owned in-memory envelope and threshold fixtures, an independent
list-scan transcript projection, complete terminal retries and re-exported
states, and matched session/stateless requests. Restore reuses the local set
already needed to validate the ordered attempted-context index; canonical
order, authentication, request binding, ancestry and atomic installation are
unchanged. This regression does not run a campaign or measure performance.

- The 42 rows, 384 cells, and five architecture names are truth-table views of the same `REQUIRED` map, not independent mechanism interactions.
- The 256 same-key cells test `read_candidates` and canonical scalar selection.
- The 4,352 compiled coalition cells use valid signed tips, distinct context-derived keys, exact tip payloads, expected trace sets, and a canonical contributor.
- Long-chain timing uses the authenticated-envelope backend and an in-memory terminal registry, including one final full-chain/tip export but excluding persistent reservation, commit, recovery I/O, and anti-rollback services. Append and export costs are reported separately; distinct exported pairs are verified outside construction timing. Threshold-carrier timing is separate.
- Threshold and residual/subset timing retain every one of 31 raw samples. The huge $(32,16)$ subset baseline is not run.

## Limits

The finite carrier is visible and language-bounded. The envelope is intentionally removable. The finite truth table is not a distribution over real attackers. The probability grid is diagnostic; uniform validity comes from the theorem. The pinned in-toto dependency could not be acquired after a concrete attempt, so no in-toto execution or performance score is claimed.
