"""Real-Postgres acceptance tests for the DB role & ownership contract
(WO-026 T1/T2). Proves, against a deliberately drifted database:

* the bootstrap is idempotent for both contract shapes,
* an ``_app`` role can DML but not DDL,
* the DDL role owns everything and ownership-sensitive ``ALTER`` works
  (the migration-019 failure mode is unreachable),
* Retrieval-S's runtime-created ``*_vector_store`` tables stay app-owned
  and legal, and
* the ``system_record`` writer can insert but never UPDATE/DELETE fact
  tables (the WO-018 0004 append-only guarantee survives the split).

Run with a superuser (or CREATEROLE+CREATEDB) URL:

    TAPROOT_DB_CONTRACT_TEST_DATABASE_URL=postgresql://postgres:pw@host/postgres \
        uv run pytest tests/test_db_contract_postgres.py -v

Skipped when the URL is not provided, matching
tests/test_sor_tamper_evidence_postgres.py.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit

import pytest

from taproot_common.db_contract import (
    SERVICE_DB_CONTRACTS,
    SYSTEM_RECORD_CONTRACT,
    quote_literal,
    render_service_bootstrap,
    render_service_verify,
    render_shared_bootstrap,
    render_shared_verify,
)

DB_URL = os.environ.get("TAPROOT_DB_CONTRACT_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DB_URL,
        reason="TAPROOT_DB_CONTRACT_TEST_DATABASE_URL not set (needs a real Postgres)",
    ),
]

TEST_PASSWORD = "wo026-test-password"
TEST_DATABASES = ("retrieval", "evalservice", "system_record")
TEST_ROLES = (
    "taproot_retrieval_ddl",
    "retrieval_app",
    "taproot_evals_ddl",
    "evals_app",
    "taproot_system_record_ddl",
    "taproot_system_record_writer",
    "front_s_app",
    "wo026_legacy_owner",
    "wo026_admin",
)


def _url_for(
    database: str, user: str | None = None, password: str | None = None
) -> str:
    parts = urlsplit(DB_URL)
    netloc = parts.netloc
    if user is not None:
        host_port = netloc.rsplit("@", 1)[-1]
        netloc = f"{user}:{password}@{host_port}"
    return urlunsplit((parts.scheme, netloc, f"/{database}", parts.query, ""))


async def _connect(database: str, user: str | None = None, password: str | None = None):
    import asyncpg

    return await asyncpg.connect(_url_for(database, user, password))


async def _apply(conn, statements: list[str]) -> None:
    for statement in statements:
        try:
            await conn.execute(statement)
        except Exception as exc:
            message = f"statement failed: {statement[:400]} -- {exc}"
            raise AssertionError(message) from exc


@pytest.fixture
async def cluster():
    maintenance = await _connect(urlsplit(DB_URL).path.lstrip("/") or "postgres")
    for db in TEST_DATABASES:
        await maintenance.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
    for role in TEST_ROLES:
        await maintenance.execute(f'DROP ROLE IF EXISTS "{role}"')
    for db in TEST_DATABASES:
        await maintenance.execute(f'CREATE DATABASE "{db}"')
    try:
        yield maintenance
    finally:
        for db in TEST_DATABASES:
            await maintenance.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        for role in TEST_ROLES:
            await maintenance.execute(f'DROP ROLE IF EXISTS "{role}"')
        await maintenance.close()


async def _seed_drifted_database(database: str) -> None:
    """Mimic the live symptom: objects owned by a role that is NOT the
    migration role (init-databases created them as the master/admin)."""
    admin = await _connect(database)
    try:
        await admin.execute("CREATE ROLE wo026_legacy_owner NOLOGIN")
        await admin.execute("GRANT wo026_legacy_owner TO current_user")
        # PG15+ revoked PUBLIC's CREATE on schema public; the historical
        # objects predate that, so the seed grants it explicitly.
        await admin.execute("GRANT CREATE ON SCHEMA public TO wo026_legacy_owner")
        await admin.execute("SET ROLE wo026_legacy_owner")
        await admin.execute(
            "CREATE TABLE stores (id SERIAL PRIMARY KEY, name TEXT NOT NULL)"
        )
        await admin.execute("CREATE TABLE schema_migrations (version TEXT PRIMARY KEY)")
        await admin.execute("RESET ROLE")
        await admin.execute("INSERT INTO stores (name) VALUES ('seed')")
    finally:
        await admin.close()


class TestPerServiceShape:
    async def test_drifted_database_converges_and_app_is_dml_only(
        self, cluster
    ) -> None:
        contract = SERVICE_DB_CONTRACTS["evals"]
        await _seed_drifted_database("evalservice")

        admin = await _connect("evalservice")
        try:
            bootstrap = render_service_bootstrap(
                contract, ddl_password_sql=quote_literal(TEST_PASSWORD)
            )
            await _apply(admin, bootstrap)
            await _apply(admin, bootstrap)  # idempotent re-run is a safe no-op

            owners = {
                r["tablename"]: r["tableowner"]
                for r in await admin.fetch(
                    "SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public'"
                )
            }
            assert owners == {
                "stores": contract.ddl_role,
                "schema_migrations": contract.ddl_role,
            }

            await _apply(admin, render_service_verify(contract))
            await admin.execute(
                f"ALTER ROLE {contract.app_role} WITH LOGIN PASSWORD "
                f"{quote_literal(TEST_PASSWORD)}"
            )
        finally:
            await admin.close()

        import asyncpg

        app = await _connect("evalservice", contract.app_role, TEST_PASSWORD)
        try:
            await app.execute("INSERT INTO stores (name) VALUES ('from-app')")
            assert await app.fetchval("SELECT count(*) FROM stores") == 2
            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await app.execute("CREATE TABLE rogue (id INT)")
            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await app.execute("ALTER TABLE stores ADD COLUMN hacked TEXT")
            with pytest.raises(asyncpg.exceptions.RaiseError, match="must run as"):
                await _apply(
                    app, render_service_verify(contract, expect_migration_role=True)
                )
        finally:
            await app.close()

        ddl = await _connect("evalservice", contract.ddl_role, TEST_PASSWORD)
        try:
            # The exact live failure mode: an ownership-sensitive ALTER on a
            # historically drifted table (migration 019's shape).
            await ddl.execute("ALTER TABLE stores ADD COLUMN deleted_at TIMESTAMPTZ")
            await _apply(
                ddl, render_service_verify(contract, expect_migration_role=True)
            )
            await ddl.execute("CREATE TABLE ddl_made (id INT, note TEXT)")
        finally:
            await ddl.close()

        app = await _connect("evalservice", contract.app_role, TEST_PASSWORD)
        try:
            # Default privileges: DDL-created tables auto-grant DML.
            await app.execute("INSERT INTO ddl_made VALUES (1, 'auto-granted')")
        finally:
            await app.close()

    async def test_retrieval_runtime_owned_vector_stores_stay_legal(
        self, cluster
    ) -> None:
        contract = SERVICE_DB_CONTRACTS["retrieval"]
        await _seed_drifted_database("retrieval")

        admin = await _connect("retrieval")
        try:
            await _apply(
                admin,
                render_service_bootstrap(
                    contract, ddl_password_sql=quote_literal(TEST_PASSWORD)
                ),
            )
            await admin.execute(
                f"ALTER ROLE {contract.app_role} WITH LOGIN PASSWORD "
                f"{quote_literal(TEST_PASSWORD)}"
            )
        finally:
            await admin.close()

        import asyncpg

        app = await _connect("retrieval", contract.app_role, TEST_PASSWORD)
        try:
            # Physical store isolation: the runtime legitimately creates
            # per-store tables — and only tables matching the declared shape.
            await app.execute(
                "CREATE TABLE policies_vector_store (id TEXT PRIMARY KEY, content TEXT)"
            )
        finally:
            await app.close()

        ddl = await _connect("retrieval", contract.ddl_role, TEST_PASSWORD)
        try:
            await _apply(
                ddl, render_service_verify(contract, expect_migration_role=True)
            )
            # Migrations can still alter runtime-owned dynamic tables
            # (migration 010's shape) via app-role membership.
            await ddl.execute(
                "ALTER TABLE policies_vector_store ADD COLUMN metadata JSONB"
            )
        finally:
            await ddl.close()

        app = await _connect("retrieval", contract.app_role, TEST_PASSWORD)
        try:
            await app.execute("CREATE TABLE rogue_catalog (id INT)")
            with pytest.raises(
                asyncpg.exceptions.RaiseError, match="objects with wrong owner"
            ):
                await _apply(app, render_service_verify(contract))
            await app.execute("DROP TABLE rogue_catalog")
            await _apply(app, render_service_verify(contract))
        finally:
            await app.close()


class TestNonSuperuserAdminPath:
    async def test_bootstrap_leaves_no_admin_memberships(self, cluster) -> None:
        """The RDS-realistic path: a non-superuser CREATEROLE admin runs the
        bootstrap. It must converge ownership AND end the session holding no
        usable membership in any role it touched — a lingering membership in
        a role that reaches rds_iam PAM-locks the admin's password login."""
        contract = SERVICE_DB_CONTRACTS["evals"]
        await cluster.execute(
            f"CREATE ROLE wo026_admin LOGIN CREATEROLE PASSWORD {quote_literal(TEST_PASSWORD)}"
        )
        await cluster.execute('ALTER DATABASE "evalservice" OWNER TO wo026_admin')

        admin = await _connect("evalservice", "wo026_admin", TEST_PASSWORD)
        try:
            await admin.execute("CREATE ROLE wo026_legacy_owner NOLOGIN")
            await admin.execute("GRANT CREATE ON SCHEMA public TO wo026_legacy_owner")
            await admin.execute("GRANT wo026_legacy_owner TO wo026_admin")
            await admin.execute("SET ROLE wo026_legacy_owner")
            await admin.execute(
                "CREATE TABLE stores (id SERIAL PRIMARY KEY, name TEXT NOT NULL)"
            )
            await admin.execute("RESET ROLE")
            await admin.execute("REVOKE wo026_legacy_owner FROM wo026_admin")

            bootstrap = render_service_bootstrap(
                contract, ddl_password_sql=quote_literal(TEST_PASSWORD)
            )
            await _apply(admin, bootstrap)
            await _apply(admin, bootstrap)  # idempotent as the same admin

            owner = await admin.fetchval(
                "SELECT tableowner FROM pg_tables "
                "WHERE schemaname = 'public' AND tablename = 'stores'"
            )
            assert owner == contract.ddl_role

            residual = await admin.fetch(
                "SELECT g.rolname FROM pg_auth_members m "
                "JOIN pg_roles u ON u.oid = m.member "
                "JOIN pg_roles g ON g.oid = m.roleid "
                "WHERE u.rolname = 'wo026_admin' AND (m.set_option OR m.inherit_option)"
            )
            assert [r["rolname"] for r in residual] == []

            await _apply(admin, render_service_verify(contract))
        finally:
            await admin.close()


class TestSharedSystemRecordShape:
    async def test_writer_is_append_only_and_never_owns(self, cluster) -> None:
        contract = SYSTEM_RECORD_CONTRACT
        admin = await _connect("system_record")
        try:
            await admin.execute(
                "CREATE TABLE activity_records (id SERIAL PRIMARY KEY, payload TEXT)"
            )
            await admin.execute(
                "CREATE TABLE retention_policies "
                "(id SERIAL PRIMARY KEY, days INT, updated_at TIMESTAMPTZ)"
            )
            bootstrap = render_shared_bootstrap()
            await _apply(admin, bootstrap)
            await _apply(admin, bootstrap)  # idempotent
            await _apply(admin, render_shared_verify())

            owners = {
                r["tablename"]: r["tableowner"]
                for r in await admin.fetch(
                    "SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public'"
                )
            }
            assert set(owners.values()) == {contract.ddl_role}

            import asyncpg

            await admin.execute(f"GRANT {contract.writer_role} TO current_user")
            await admin.execute(f"SET ROLE {contract.writer_role}")
            await admin.execute(
                "INSERT INTO activity_records (payload) VALUES ('fact')"
            )
            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await admin.execute(
                    "UPDATE activity_records SET payload = 'rewritten' WHERE id = 1"
                )
            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await admin.execute("DELETE FROM activity_records WHERE id = 1")
            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await admin.execute("CREATE TABLE writer_owned (id INT)")
            await admin.execute("INSERT INTO retention_policies (days) VALUES (30)")
            await admin.execute("UPDATE retention_policies SET days = 60 WHERE id = 1")
            await admin.execute("RESET ROLE")

            # A drifted writer (UPDATE on a fact table) fails verification.
            await admin.execute(
                f"GRANT UPDATE ON activity_records TO {contract.writer_role}"
            )
            with pytest.raises(asyncpg.exceptions.RaiseError, match="append-only"):
                await _apply(admin, render_shared_verify())
            await admin.execute(
                f"REVOKE UPDATE ON activity_records FROM {contract.writer_role}"
            )
            await _apply(admin, render_shared_verify())
        finally:
            await admin.close()
