"""Read-only reconstruction of an interaction from the System of Record.

This is the diagnosis/SoR-reconstruction primitive: given one
``interaction_id``, return the interaction record and every activity record
that joins it, ordered by occurrence. It never writes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence


class ActivityDbFetcher(Protocol):
    """Minimal async fetch protocol satisfied by asyncpg connections/pools."""

    async def fetch(self, query: str, *args: Any) -> Sequence[Mapping[str, Any]]:
        """Run a read-only query and return mapping-like rows."""
        ...


_INTERACTION_QUERY = """
SELECT interaction_id, interaction_type, project_id, domain_area,
       caller_summary, default_actor_chain, root_agent_id,
       source_entry_point, retention_policy_id, collapse_metadata, started_at
FROM interaction_records
WHERE interaction_id = $1
"""

_ACTIVITIES_QUERY = """
SELECT activity_id, interaction_id, parent_activity_id, project_id,
       domain_area, target_type, target_id, action_family, action,
       lifecycle_phase, outcome, durability, evidence_class, event_label,
       primary_target, occurred_at
FROM activity_records
WHERE interaction_id = $1
ORDER BY occurred_at, id
"""


@dataclass(frozen=True)
class ReconstructedInteraction:
    """The joined record set for one interaction."""

    interaction_id: str
    interaction: Mapping[str, Any] | None
    activities: tuple[Mapping[str, Any], ...]

    @property
    def found(self) -> bool:
        return self.interaction is not None

    @property
    def activity_ids(self) -> tuple[str, ...]:
        return tuple(str(row["activity_id"]) for row in self.activities)


async def reconstruct_interaction(
    interaction_id: str,
    *,
    fetcher: ActivityDbFetcher,
) -> ReconstructedInteraction:
    """Return the interaction record and all activity records joining it."""

    interaction_rows = await fetcher.fetch(_INTERACTION_QUERY, interaction_id)
    activity_rows = await fetcher.fetch(_ACTIVITIES_QUERY, interaction_id)
    return ReconstructedInteraction(
        interaction_id=interaction_id,
        interaction=dict(interaction_rows[0]) if interaction_rows else None,
        activities=tuple(dict(row) for row in activity_rows),
    )
