"""Alembic environment for the TAP-38 system record database."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from taproot_common.activity import SYSTEM_RECORD_DATABASE_ENV_VAR

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def _system_record_database_url() -> str:
    database_url = os.environ.get(SYSTEM_RECORD_DATABASE_ENV_VAR, "").strip()
    if not database_url:
        raise RuntimeError(f"{SYSTEM_RECORD_DATABASE_ENV_VAR} is required for system record migrations")
    return database_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""

    context.configure(
        url=_system_record_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table="system_record_alembic_version",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode."""

    config.set_main_option("sqlalchemy.url", _system_record_database_url())
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table="system_record_alembic_version",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
