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

The full-package command accepts the current two-root `paper/` and `artifact/` packet, with an optional root navigation `README.md`; it checks paper and citation keys, parses the current PDFs, checks execution evidence, and optionally runs tests. The standalone command checks artifact execution evidence and tests. Neither fixes author slots, page counts, or manuscript bytes to a historical package.

Requirements are CPU-only Python 3.12 or later and the two versions in `requirements.txt`. A complete run can also use `python -B run_experiments.py --out reproduced`. The output directory must be absent or empty at preparation; existing evidence is never deleted. A sharded continuation must use the same output directory. Its version-2 manifest binds current sources against the artifact root and generated evidence against the output root, including when output is outside this repository.

`results/` retains the earlier Linux campaign, original source bindings and
89-test result. Historical focused and CI records remain separate. The present
collection has 135 tests: the 128-test source snapshot plus two owner-lifetime,
three loopback, and two package/test-contract regressions. The current reviewed
state/RPC subset executes 43 tests without skips (21 durable, six restore/session,
seven request-transcript,
four risk-input, two owner-lifetime and three loopback). Its results are in
`results/owned-workflow/tests.json`. This subset does not rerun the archived
attack/probability campaigns. Historical CPU data and source bindings are not
overwritten or relabeled; an old manifest is expected not to match changed
sources. The bounded outputs are not a complete `verify_release.py` campaign.

Recovery authenticates snapshots and additionally validates request identities, canonical program bytes, request-to-record agreement, and successful ancestry of every non-genesis terminal attempt. The optional `registry_path` adds a single-owner authenticated SQLite ledger with pending reservation committed before key derivation/marking, terminal success/failure committed before release, and conservative restart recovery. It does not prevent rollback to an older authenticated snapshot. Risk formulas require nonnegative integer budgets and valid primitive probabilities; invalid inputs are rejected, not assigned a zero-security-loss result.

## Durable local issuance

Supply the same persistent path and actual configured keys on every restart. The deterministic constructor below uses test keys only and is not a deployment key-management example:

```python
with ContextMarkCompiler.deterministic(["builder"], registry_path="state.sqlite") as issuer:
    chain, artifact = issuer.issue([], program, actor="builder", operation="compile")
```

The parent directory must already exist on reliable local storage. SQLite uses `journal_mode=DELETE` and `synchronous=EXTRA`. Entry and header HMACs preserve integrity; unique request/context indices preserve reservation identity. Keep the database, journal (when present), and `.owner` file together. Do not replace or unlink the owner file during use. Another live owner rejects. On reopening, previously pending requests become durable `InterruptedAttempt` failures and cannot mark again, even if the previous process may have exited before marking. This is intentionally conservative. Exact successful retries return stored bytes, failures remain terminal, and an uncertain write stops both issuance and snapshot export until reopening. A closed issuer cannot continue. Omitting `registry_path` selects the original in-memory mode, which is not crash safe.

These guarantees depend on protected files and real filesystem flush/locking behavior; there is no anti-rollback witness, distributed replica coordination, or power-loss validation. Deleting/replacing the database or switching to an untracked fresh path is outside the storage-freshness premise.

Live post-reservation calls also retain ownership when another request encounters
a storage error. An active-attempt counter covers dispatch, postchecks and
terminal handling; close refuses until every live call unwinds. Stored pending
rows may then remain for conservative recovery. This is local quiescence, not
remote cancellation. A remote adapter must send once or use server-side attempt
deduplication; an uncertain mark response must not trigger a second sample.

## Owned real-carrier loopback workflow

`owned_network_workflow.py` executes the actual finite `(5,3)` threshold adapter
over local HTTP, with durable SQLite, Ed25519 and the existing SHA/HMAC domains.
Only 127.0.0.1 with an OS-assigned port is used; there is no configurable external
target. Plaintext deterministic test keys are intentional fixture input, not a
secure key-transport protocol. See `OWNED_WORKFLOW.md` for complete boundaries.

```bash
PYTHONDONTWRITEBYTECODE=1 python -B owned_network_workflow.py --out /tmp/owned-results --work /tmp/owned-cases --cpu-name "OBSERVED CPU" --filesystem "OBSERVED FILESYSTEM"
PYTHONDONTWRITEBYTECODE=1 python -B owned_network_workflow.py --out /tmp/owned-results --work /tmp/owned-cases --check
PYTHONDONTWRITEBYTECODE=1 python -B reproduce_owned_failures.py --out /tmp/owned-failures --work /tmp/owned-failure-cases
```

Output/work directories must be absent. `results/owned-workflow/` retains all
36 path runs (15 measured plus three warm-up pairs), 492 observed marks, 1,020
reads, HTTP inputs/outputs and raw databases. Before every mark a separate SQL
connection observes committed pending state. Session/replay canonical requests,
pairs and terminal bytes agree, including semantic reopen and all exact retries.
No retry adds a mark. The complete-cost medians are 29.5657/29.3156,
99.6529/98.4027 and 763.7503/804.7971 ms at depths 1/8/32 (session/replay).
Session is not faster at the first two depths under this full boundary.
Response-loss negatives remain separately under `results/owned-failures/`.
Owner-interleaving pre/post outputs remain under `results/owner-lifetime/`.
The checker reconciles recorded values; it does not rerun network/crypto work.

The safe bounded entrypoint runs owned stub services only:

```bash
python -B -m unittest discover -s tests -p test_durable_registry.py -v
python -B run_durable_experiment.py --out results/NEW-DIRECTORY --cpu-name "OBSERVED-CPU" --filesystem "OBSERVED-LOCAL-FILESYSTEM"
```

Use an absent output directory. The current second command selects 38 focused
tests, then two warm-ups and 11 measured pairs at depths 1, 8, and 32. It retains
all 39 pairs and matched terminal bytes. The historical local run in
`results/durable-state/` used its then-current 37-test selection and cryptography
50.0.2, not the Linux 46.0.4 pin; those recorded values are unchanged. The ordinary
path shares storage and receives identical prevalidated bytes, excluding their
preparation/signing/marking/checking. It is a persistence reference, not an
end-to-end provenance competitor or novelty result.

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
