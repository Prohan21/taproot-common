"""Tests for the read-only interaction reconstruction helper."""

from typing import Any, Mapping, Sequence

from taproot_common.activity.reconstruction import (
    ReconstructedInteraction,
    reconstruct_interaction,
)


class FakeFetcher:
    def __init__(
        self,
        interaction_rows: Sequence[Mapping[str, Any]],
        activity_rows: Sequence[Mapping[str, Any]],
    ) -> None:
        self._interaction_rows = interaction_rows
        self._activity_rows = activity_rows
        self.queries: list[tuple[str, tuple[Any, ...]]] = []

    async def fetch(self, query: str, *args: Any) -> Sequence[Mapping[str, Any]]:
        self.queries.append((query, args))
        if "FROM interaction_records" in query:
            return self._interaction_rows
        return self._activity_rows


async def test_returns_joined_interaction_and_activities() -> None:
    fetcher = FakeFetcher(
        interaction_rows=[
            {"interaction_id": "int-1", "interaction_type": "service_request"}
        ],
        activity_rows=[
            {"activity_id": "act-1", "interaction_id": "int-1"},
            {"activity_id": "act-2", "interaction_id": "int-1"},
        ],
    )
    result = await reconstruct_interaction("int-1", fetcher=fetcher)

    assert isinstance(result, ReconstructedInteraction)
    assert result.found is True
    assert result.interaction is not None
    assert result.interaction["interaction_id"] == "int-1"
    assert result.activity_ids == ("act-1", "act-2")
    assert all(args == ("int-1",) for _, args in fetcher.queries)


async def test_missing_interaction_reports_not_found() -> None:
    fetcher = FakeFetcher(interaction_rows=[], activity_rows=[])
    result = await reconstruct_interaction("missing", fetcher=fetcher)

    assert result.found is False
    assert result.interaction is None
    assert result.activities == ()


async def test_queries_are_read_only() -> None:
    fetcher = FakeFetcher(interaction_rows=[], activity_rows=[])
    await reconstruct_interaction("int-1", fetcher=fetcher)
    for query, _ in fetcher.queries:
        assert query.strip().upper().startswith("SELECT")
