# F1 Immutable Observation Ledger

## Record pipeline

```text
Recorded upstream JSON
        │
        ▼
Strict canonical payload ── no floats, duplicate keys, raised ceilings, or mutable aliasing
        │
        ▼
Exact source contract ── chain + exact event/finality/visibility triple + limits
        │
        ▼
Observation envelope ── source sequence + source identity + timestamps + payload digests
        │
        ▼
Per-segment record chain ── ordinal + previous record digest + envelope digest
        │
        ▼
Cross-segment manifest chain ── previous segment digest + start/end source checkpoints
        │
        ▼
Sealed JSONL storage ── exclusive publication + fsync + read-only + one hard link
        │
        ▼
Deterministic replay ── reconstruct and verify every authority boundary
```

## Source continuity

Each source has a collector-assigned unsigned 64-bit sequence. A newly observed source starts at zero. Subsequent observations are contiguous across segment boundaries, not merely within one file. Every manifest records complete starting and ending source checkpoints containing both the sequence and last observation time.

A missing upstream range is represented by an explicit closed `source-gap` metadata envelope. The local collector sequence remains contiguous because the gap record itself is an observation; missing upstream content is never silently skipped or fabricated.

Observation time may remain equal but cannot move backwards for a source, including across segments. Source event identifiers are unique within one segment; the source sequence is the cross-segment identity authority.

## Record and segment integrity

Each record binds:

- segment identity and ordinal;
- previous record SHA-256 within that segment;
- complete observation envelope and its SHA-256;
- record SHA-256.

Each manifest binds:

- previous segment SHA-256, or zero for the first segment;
- source checkpoints before and after the segment;
- first/last record digests;
- a digest over the ordered record-digest vector;
- exact record count;
- exact source-contract-set digest;
- manifest/segment SHA-256.

The chain verifier requires each segment's previous digest and starting checkpoints to equal the prior segment's ending authority. It rejects missing prefixes, wrong parents, duplicate segment IDs, source restarts, source gaps, time regressions, contract-set drift, mutation, reordering, deletion, duplication, truncation, excessive record lines, unknown fields, or noncanonical framing.

## Storage

Segments are canonical UTF-8 JSON Lines with LF endings and exactly one terminal newline. The final line is the manifest.

The Linux storage authority:

1. opens every directory component with no-follow semantics;
2. creates an exclusive temporary regular file;
3. writes and `fsync`s the complete sealed bytes;
4. removes all write bits and `fsync`s again;
5. publishes through a no-overwrite hard link;
6. removes the temporary link and `fsync`s the directory;
7. requires the published file to be regular, read-only, and single-linked.

Stable reads reject writable files, additional hard links, symlink targets or parents, pathname replacement, identity/metadata changes, growth, truncation, optional external payload-digest mismatch, and internal replay failure.

## Head transitions

The EVM head tracker emits deterministic `bootstrap`, `extend`, `reorg`, `duplicate`, or `orphan` evidence. It can bootstrap from an arbitrary observed height. Every tracker is configured for one exact `(chain, source, observation kind, finality, full visibility)` stream, so confirmed, finalized, and preconfirmed authorities cannot be mixed. Since the tracker consumes only the head subset of a source, source sequences must strictly increase but need not be adjacent; the full ledger remains responsible for contiguous all-event sequencing.

Each transition binds the triggering observation SHA-256 and source sequence and can verify that trigger later. Known-parent height and timestamp inconsistencies fail closed. A repeated block hash with conflicting metadata fails closed. Unknown-parent topology is reported as an orphan but is not retained until a parent path is known. Rejected heads do not consume sequence or mutate topology. The tracker records source claims and never upgrades their declared finality.
