# ClaimVerifier

**A GenLayer Intelligent Contract that checks a specific factual claim against several web sources: validators independently read every source, and the contract derives whether the claim is supported, partially supported, contradicted, or not provable, counting independent evidence rather than URLs.**

> **Status.** Deployed and partly exercised on GenLayer Studio Next (GenVM v0.3) on 10 Nov 2026: claim registration, source management, owner-only access control and one full verification reached consensus with three validator models. See [Tested on Studio Next](#tested-on-studio-next) for exactly what was and was not run live. The 83 local tests run against a *simulation* of the SDK with scripted pages and answers and do not prove real validator consensus or real model behaviour.

## What it does

An owner registers a **claim** (a precise statement), the **expected facts** that must hold for it to be true, and 2 to 5 **evidence URLs**. `verify_claim` has the leader and every validator fetch all sources and judge, per source and per expected fact: `SUPPORTED`, `CONTRADICTED`, `MENTIONED` (referred to but not demonstrated), `NOT_ADDRESSED` or `UNCLEAR`. The contract then derives, in code:

| Overall status | Meaning |
|---|---|
| `SUPPORTED` | every expected fact is directly supported |
| `PARTIALLY_SUPPORTED` | some facts supported, the rest unverified |
| `CONTRADICTED` | a fact is directly contradicted and no source supports it |
| `INSUFFICIENT_EVIDENCE` | sources do not address the facts (lack of proof is not falsity) |
| `SOURCE_UNAVAILABLE` | no source could be read (never treated as contradiction) |
| `INCONCLUSIVE` | sources disagree, evidence is unclear, or fewer than the required number of sources were readable |

The report also contains per-source results, per-fact results, supporting / contradictory / unverified findings, source relationships, an **evidence strength** (`STRONG` / `MODERATE` / `WEAK` / `INSUFFICIENT`) and an informational confidence.

ClaimVerifier does not determine absolute truth. It reports whether the registered evidence supports or contradicts a precisely formulated claim, and it says what it could not establish.

## Why multi-source, and why not a vote

- **Three copies of one press release are one confirmation.** The contract detects duplicate content programmatically (word 5-gram similarity) and treats sources as independent only when the model gives a positive reason *and* they are on different registrable domains. Strength counts independent groups, not URLs.
- **A mention is not proof.** `MENTIONED` never counts as support.
- **Conflicts are not resolved by majority.** If one source supports a fact and another contradicts it, the result is `INCONCLUSIVE`.
- **Quotations are checked.** An excerpt only counts if it appears verbatim in the page; validators re-check it in their own copy. `STRONG` requires a verified excerpt from every supporting source.

## How it works

```
register_claim -> OPEN --add_evidence_source (2..5, append-only)--> verify_claim -> ASSESSED --reassess_claim (repeatable)
```

Every accepted assessment is appended to the history with the evidence set (URLs) that was used. History is never overwritten (at most 20 assessments per claim). Unavailable or inconclusive results are recorded too, but do not count as a verification (`last_verified_at` only moves on conclusive results).

## Consensus (Equivalence Principle)

`verify_claim` and `reassess_claim` use the custom leader/validator pattern through `gl.vm.run_nondet_default` (falls back to `run_nondet_unsafe` on GenVM v0.2).

- **Leader:** fetches every source, asks the LLM per source and per fact, normalises the answer, then the contract derives everything else.
- **Validators:** do not trust the leader. They check its output is well formed and that all derived fields follow from its own per-fact answers, **re-fetch every source and run the full assessment themselves**, verify the leader's quotations in their own copy, and compare: overall status, each source's access status and per-fact results, and the deterministic duplicate-content pairs. Wording, strength, independence labels, findings and confidence are not compared.
- State is written only after consensus; a failed round changes nothing.

Details: [docs/CONSENSUS.md](docs/CONSENSUS.md).

## Public API

| Method | Kind | Notes |
|---|---|---|
| `register_claim(claim_text, category, instructions, expected_facts, min_sources, max_sources, external_ref, expires_at)` | write | `expected_facts`: separate with `\|\|`. `expires_at`: unix seconds or `0`. |
| `add_evidence_source(claim_id, source_url, source_type, description)` | write | Owner only; append-only; duplicates refused. |
| `verify_claim(claim_id)` | write | Owner only; first assessment. Use a generous fee. |
| `reassess_claim(claim_id)` | write | Owner only; adds a new assessment, keeps all earlier ones. |
| `get_claim`, `get_evidence_sources`, `get_latest_assessment`, `get_assessment(claim_id, n)`, `get_assessment_history`, `get_claim_count` | view | History is newest first. |
| `get_integration_status(claim_id)` | view | Stable read interface for other contracts and apps ([docs/INTEGRATION.md](docs/INTEGRATION.md)). |

## Deploy

1. Open [Studio Next](https://studio-next.genlayer.com/), paste `contracts/claim_verifier.py` (keep the two header lines), deploy with no arguments.
2. Register a claim, add sources, verify. Examples: [docs/USAGE.md](docs/USAGE.md).

The `Depends` runner hash is tied to the GenVM bundle (this file uses the one reported for Studio Next bundles v0.6.0-rc9/rc10). If schema loading fails with `runner absent` / `runner malformed`, copy the first two lines of a built-in example contract in your Studio build.

## Tests

`python -m unittest discover -s tests -v` (83 tests, no dependencies). Mocked/simulated only; see the module docstring of `tests/test_claim_verifier.py` for what they do and do not prove. Mutation checks (validator always `True`, state written before consensus, independence ignored, unavailable treated as contradiction) make the suite fail.

## Tested on Studio Next

Live, 10 Nov 2026, GenVM v0.3.0-rc10, 3 agreeing validator models per run, using public gists as sources (a short backup-tool user guide and release notes).

| Scenario | Result | Transaction |
|---|---|---|
| `register_claim` (two expected facts, 2-3 sources) | `OPEN`, facts split correctly, owner recorded | n/a (state read back) |
| `add_evidence_source` by a non-owner | refused: `[EXPECTED] only the claim owner can do this` (3 validators agree) | `0x884a3e3102bee31d4757b3b6c2d5877c64498aa8ee850d897afbd181b49dcdc9` |
| `add_evidence_source` by the owner (2 sources) | stored with positions 1 and 2, types and descriptions kept | n/a (state read back) |
| `verify_claim` with 2 sources | `SUPPORTED`, `MODERATE`; both quotations verified verbatim; the release-notes source only *mentioned* the restore procedure and was not counted as support for it; sources on one domain were not treated as independent | `0x3821cec0c27bcf776debd694433f217515e29b5944761a9d4367870baa0c7349` |

**Not run on a live network** (simulation tests only): `PARTIALLY_SUPPORTED` and `INSUFFICIENT_EVIDENCE` outcomes, `reassess_claim` and history preservation, source conflict (`INCONCLUSIVE`), `CONTRADICTED`, unavailable sources (`SOURCE_UNAVAILABLE`), duplicate content detection, a page with an injected instruction, claim expiry, the 20-assessment cap, and rejection of invalid claim/source inputs.

## Known limitations

- **Only part of the scenarios were run live** (see the table above). Real validators may disagree on borderline pages more often than the simulation suggests (seen live on the sibling contracts); then nothing is stored and the call can be retried.
- Sources are plain HTTP GET, cleaned and truncated to **6,000 characters each**: JavaScript-rendered pages, logins, paywalls and long documents (large source files) are only partly seen or look empty.
- Independence is a conservative heuristic (duplicate text, same registrable domain, the model's reasoning); it is not proof of independent origin. Registrable-domain detection is approximate (last two labels).
- Per-fact judgements and excerpts are model output. Only the per-fact results, statuses and duplicate pairs are compared by validators; treat summaries and findings as paraphrase.
- Claim specificity checks are heuristics (length, word count); a vague claim with long facts can still pass.
- Only the claim owner can add sources and trigger verification (prevents history flooding and unauthorised reassessment).
- Reachability is not authenticity: no cryptographic proof of what a source said at a point in time is provided.
- Cross-contract calls to MilestoneJudge / EvidenceWatch were not implemented or verified; see INTEGRATION.md.

MIT, see [LICENSE](LICENSE).
