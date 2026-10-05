# TDSC-01 executable artifact

The artifact checks implementation correspondence for the context-bound lineage compiler, finite threshold carrier, predictable risk bounds, recovery discipline, and the repaired multi-context trace contract. It is not a production watermark or proof-assistant development.

## Run

From `artifact/`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m unittest discover -s tests -q
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. sh run_experiments_sharded.sh
```

Read-only package verification has two valid, project-scoped entry points:

```bash
# From the full TDSC-01 project root
PYTHONDONTWRITEBYTECODE=1 python artifact/verify_release.py --root .

# From a standalone artifact root
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python verify_release.py --root .
```

The full-package command checks paper and citation keys, parses the current PDFs, checks retained execution evidence, and optionally runs tests. The standalone command checks artifact execution evidence and tests. Neither fixes author slots, page counts, or manuscript bytes to a historical package.

## Evidence interpretation

- The 42 rows, 384 cells, and five architecture names are truth-table views of the same `REQUIRED` map, not independent mechanism interactions.
- The 256 same-key cells test `read_candidates` and canonical scalar selection.
- The 4,352 compiled coalition cells use valid signed tips, distinct context-derived keys, exact tip payloads, expected trace sets, and a canonical contributor.
- Long-chain timing uses the authenticated-envelope backend and an in-memory terminal registry, including one final full-chain/tip export but excluding persistent reservation, commit, recovery I/O, and anti-rollback services. Append and export costs are reported separately; distinct exported pairs are verified outside construction timing. Threshold-carrier timing is separate.
- Threshold and residual/subset timing retain every one of 31 raw samples. The huge $(32,16)$ subset baseline is not run.

## Limits

The finite carrier is visible and language-bounded. The envelope is intentionally removable. The finite truth table is not a distribution over real attackers. The probability grid is diagnostic; uniform validity comes from the theorem. The pinned in-toto dependency could not be acquired after a concrete attempt, so no in-toto execution or performance score is claimed.
