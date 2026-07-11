"""Alembic environment for the TAP-38 system record database."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, inspect, pool, text
from sqlalchemy.engine import Connection

from taproot_common.activity.schema import (
    ACTIVITY_TABLES,
    SYSTEM_RECORD_ALEMBIC_VERSION_TABLE,
    SYSTEM_RECORD_DATABASE_ENV_VAR,
    validate_system_record_migration_preflight,
)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def _system_record_database_url() -> str:
    database_url = os.environ.get(SYSTEM_RECORD_DATABASE_ENV_VAR, "").strip()
    if not database_url:
        raise RuntimeError(
            f"{SYSTEM_RECORD_DATABASE_ENV_VAR} is required for system record migrations"
        )
    return database_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""

    context.configure(
        url=_system_record_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=SYSTEM_RECORD_ALEMBIC_VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode."""

    config.set_main_option("sqlalchemy.url", _system_record_database_url().replace("%", "%%"))
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.begin() as connection:
        _assume_system_record_ddl_role(connection)
        _guard_system_record_schema_shape(connection)
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table=SYSTEM_RECORD_ALEMBIC_VERSION_TABLE,
        )
        with context.begin_transaction():
            context.run_migrations()


def _assume_system_record_ddl_role(connection: Connection) -> None:
    """WO-026 shared-database shape: system_record objects are owned by the
    NOLOGIN ``taproot_system_record_ddl`` role, so the (admin-run) migration
    grants itself the owner role for this session (the bootstrap leaves no
    lingering admin memberships), assumes it, and asserts the contract
    fail-closed before migrating."""

    from taproot_common.db_contract import (
        SYSTEM_RECORD_CONTRACT,
        _grant_membership_to_current_user,
        render_shared_verify,
        should_enforce_contract,
    )

    if not should_enforce_contract():
        return
    connection.execute(
        text(_grant_membership_to_current_user(SYSTEM_RECORD_CONTRACT.ddl_role))
    )
    connection.execute(text(f'SET ROLE "{SYSTEM_RECORD_CONTRACT.ddl_role}"'))
    for statement in render_shared_verify():
        connection.execute(text(statement))


def _guard_system_record_schema_shape(connection: Connection) -> None:
    """Fail closed before Alembic trusts a possibly stale v1 revision stamp."""

    inspector = inspect(connection)
    table_names = inspector.get_table_names()
    current_revisions = _current_system_record_revisions(connection, table_names)
    columns_by_table = {
        table_name: tuple(
            column["name"] for column in inspector.get_columns(table_name)
        )
        for table_name in ACTIVITY_TABLES
        if table_name in table_names
    }
    validate_system_record_migration_preflight(
        table_names=table_names,
        current_revisions=current_revisions,
        columns_by_table=columns_by_table,
    )


def _current_system_record_revisions(
    connection: Connection,
    table_names: list[str],
) -> tuple[str, ...] | None:
    if SYSTEM_RECORD_ALEMBIC_VERSION_TABLE not in table_names:
        return None
    result = connection.execute(
        text(f"SELECT version_num FROM {SYSTEM_RECORD_ALEMBIC_VERSION_TABLE}")
    )
    return tuple(str(row[0]) for row in result)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
