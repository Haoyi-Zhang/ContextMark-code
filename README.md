# ContextMark

The artifact checks implementation correspondence for the context-bound lineage compiler, finite threshold carrier, predictable risk bounds, recovery discipline, and the repaired multi-context trace contract. It is not a production watermark or proof-assistant development.

## Figures

`reporting/draw_security.py` reads the four retained security CSVs and produces
the two editable-source vector plots. It requires matplotlib 3.10.8, numpy
2.3.5, fontTools, and an installed embeddable Times-compatible TrueType family.
It prefers TeX Gyre Termes, then Times New Roman, then Liberation Serif; it does
not install or redistribute font files. Run it from this repository with
`python reporting/draw_security.py`; use `--outdir` to select an output folder.
The full paper/artifact packet's figure wrapper uses the same renderer, so
plot data, axes and styles have one source. No security experiment is rerun by
this drawing command.

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

`results/` retains the earlier Linux campaign and its original source bindings and 89-test result. The collection now has 127 tests: the previous 107 plus 20 durable-state tests. A focused repair run executes 37 tests (20 new durability, six existing restore/session, seven request-transcript and four risk-input checks), all passing without skips on Windows with CPython 3.12.14, cryptography 50.0.2, and SQLite 3.53.1. The subsequent canonical GitHub scientific run passed all 127 tests, as detailed below; it did not replace the archived local campaigns. Historical CPU measurements are not overwritten or relabeled as current runs. After source changes, the old run manifest is expected not to match current sources; do not refresh its digests to conceal that difference. The bounded durability output is a separate evidence format, not a complete `verify_release.py --evidence-dir` campaign.

Recovery authenticates snapshots and additionally validates request identities, canonical program bytes, request-to-record agreement, and successful ancestry of every non-genesis terminal attempt. The optional `registry_path` adds a single-owner authenticated SQLite ledger with pending reservation committed before key derivation/marking, terminal success/failure committed before release, and conservative restart recovery. It does not prevent rollback to an older authenticated snapshot. Risk formulas require nonnegative integer budgets and valid primitive probabilities; invalid inputs are rejected, not assigned a zero-security-loss result.

## Durable local issuance

Supply the same persistent path and actual configured keys on every restart. The deterministic constructor below uses test keys only and is not a deployment key-management example:

```python
with ContextMarkCompiler.deterministic(["builder"], registry_path="state.sqlite") as issuer:
    chain, artifact = issuer.issue([], program, actor="builder", operation="compile")
```

The parent directory must already exist on reliable local storage. SQLite uses `journal_mode=DELETE` and `synchronous=EXTRA`. Entry and header HMACs preserve integrity; unique request/context indices preserve reservation identity. Keep the database, journal (when present), and `.owner` file together. Do not replace or unlink the owner file during use. Another live owner rejects. On reopening, previously pending requests become durable `InterruptedAttempt` failures and cannot mark again, even if the previous process may have exited before marking. This is intentionally conservative. Exact successful retries return stored bytes, failures remain terminal, and an uncertain write stops both issuance and snapshot export until reopening. A closed issuer cannot continue. Omitting `registry_path` selects the original in-memory mode, which is not crash safe.

These guarantees depend on protected files and real filesystem flush/locking behavior; there is no anti-rollback witness, distributed replica coordination, or power-loss validation. Deleting/replacing the database or switching to an untracked fresh path is outside the storage-freshness premise.

The safe bounded entrypoint runs owned stub services only:

```bash
python -B -m unittest discover -s tests -p test_durable_registry.py -v
python -B run_durable_experiment.py --out results/NEW-DIRECTORY --cpu-name "OBSERVED-CPU" --filesystem "OBSERVED-LOCAL-FILESYSTEM"
```

Use an absent output directory. The second command runs 37 focused tests, then two warm-ups and 11 measured pairs at depths 1, 8, and 32. It records all 39 pairs, matched terminal bytes, reopen/retry checks and environment metadata. The measured local run is in `results/durable-state/`. Its cryptography version is 50.0.2, not the historical 46.0.4 pin; the dependency specification for that earlier campaign is unchanged. The ordinary durable-state path uses the same authenticated storage and identical prevalidated bytes, excluding their preparation/signing/marking/checking. It is a persistence-cost reference, not an end-to-end watermark-free provenance competitor or a novelty result.

The `scientific-checks.yml` workflow targets a flat artifact repository on Ubuntu 24.04. It installs the declared dependencies, bounds the complete owned finite run, retains scientific failure gates, and uploads raw output even after failure. The retained Linux run in `results/current/` passed the then-current 101 tests without skips, rejected all 47 mutations, and checked 4,352 compiled coalition cells, 128 closure cases, 4,802 field-reader cases and 496 threshold cases. Recovery and terminal-state checks passed in that run. Its CPU measurements remain tied to that execution.

At canonical head [`971f29a09e39d3ba158d54b7f909ea3c27088b9a`](https://github.com/Haoyi-Zhang/ContextMark/commit/971f29a09e39d3ba158d54b7f909ea3c27088b9a), GitHub [scientific run 38188562264, job 114616133565](https://github.com/Haoyi-Zhang/ContextMark/actions/runs/38188562264/job/114616133565) completed successfully. Its log records `deterministic_test_count: 127`, `passed: 127`, `failed: 0`, and 4,352 compiled coalition cells with zero trace mismatches and zero canonical-selection mismatches. These are bounded deterministic CI results; the retained local measurement timestamps and CPU timings are unchanged, and no fresh remote latency result is claimed here.

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
