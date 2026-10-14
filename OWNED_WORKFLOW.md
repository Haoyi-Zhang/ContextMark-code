# Owned persistent loopback workflow

The measured paths are actual executions of the existing finite threshold
carrier, compiler and SQLite ledger, not a synthetic latency model or a native
production backend. Plaintext fixture keys are derived from public seed 29.
The HTTP client sends once per call and has no retry loop. The server binds only
127.0.0.1 at an OS-assigned port; no external address is accepted by this runner.

Session and stateless full-prefix issue use identical evolving programs,
actor/operation/metadata, keys, `(n,t)=(5,3)` carrier and DELETE/EXTRA persistence.
Depths 1/8/32 have one warm-up and five measured pairs each. Pair order alternates
by sample parity. No sample is discarded or extrapolated. The measured replay
baseline prepares, signs, marks, checks and persists its own identical requests;
it is not handed prevalidated terminal bytes. The older stub/prevalidated-byte
persistence comparison remains a separate historical protocol.

Each paired path is a separate benchmark fixture world with its own database
and the same public test coins. This does not authorize multiple live issuer
registries in one production key domain.

Full workflow time starts before program/service acquisition and database open,
then covers issue plus one export, final verification, serialization and registry
export, close, semantic reopen, reconstruction/retry of every exact request,
final close and server teardown. Diagnostic output writes are excluded. Per-phase
times and actual RPC durations are retained. RPC duration includes a separate
SQL observation of the pending row before marking. HTTP byte counts include
headers and bodies, but not IP/TCP framing, retransmissions or TLS. Median/p95
aggregates use the five measured samples; nearest-rank p95 is their maximum.

`summary.json`, `samples.json` and `matched_pairs.json` bind the executed sources
and record aggregates. Each `cases/<depth>-<sample>-<mode>/trace.json` retains
canonical requests, signed output pair, terminal snapshot, server-side crypto
outputs and client-side response/byte/time observations. Its database and owner
file are closed raw fixture evidence. Both paths match byte-for-byte, and exact
retries add zero marks. Raw deterministic test-key values are not user secrets.

The owner-lifetime regression has a controlled held request and an unrelated
reservation or ambiguous terminal-write error. Before the repair, close released
ownership while the held call was still active; after it, close and takeover
reject until the call unwinds. Error outputs and recovery states are preserved.
This corrects a live-owner invariant, not a demonstrated per-context resampling
failure. Owner loss after process death does not cancel a remote operation.

Two additional negatives execute real marking before losing its response and
lose a read during semantic recovery. The former retires the attempt as failure
and does not resample; the latter rejects recovery without resetting storage.
These cases, with full server/client observations, are separate from timing rows.

SQLite's primary [transaction documentation](https://www.sqlite.org/lang_transaction.html)
distinguishes transaction/error state from application state. Its
[atomic-commit description](https://www.sqlite.org/atomiccommit.html) makes flush
and filesystem premises explicit. The measurements do not validate those
hardware premises or upgrade one-attempt dispatch to exactly-once successful
delivery. Power loss, rollback freshness, distributed replicas, WAN/TLS behavior,
real compiler integration and watermark robustness remain distinct experiments.
