from __future__ import annotations

from aladdin_mev_engine.observation import ObservationEnvelope
from aladdin_mev_engine.source_contracts import Finality, ObservationKind, Visibility


def make_observation(
    *,
    source_id: str = "ethereum-json-rpc",
    sequence: int = 0,
    event_id: str | None = None,
    observed_at: int = 1_000,
    emitted_at: int | None = 999,
    kind: ObservationKind = ObservationKind.BLOCK_HEAD,
    finality: Finality = Finality.CONFIRMED,
    visibility: Visibility = Visibility.FULL,
    payload: object | None = None,
) -> ObservationEnvelope:
    if payload is None:
        payload = {
            "block_number": str(sequence),
            "block_hash": "0x" + f"{sequence + 1:064x}",
            "parent_hash": "0x" + ("0" * 64 if sequence == 0 else f"{sequence:064x}"),
            "block_timestamp_unix_s": str(100 + sequence),
        }
    return ObservationEnvelope.create(
        source_id=source_id,
        source_sequence=sequence,
        source_event_id=event_id or f"event-{source_id}-{sequence}",
        observed_at_unix_ms=observed_at,
        emitted_at_unix_ms=emitted_at,
        kind=kind,
        finality=finality,
        visibility=visibility,
        payload=payload,
    )
