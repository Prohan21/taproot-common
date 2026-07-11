"""Platform database role & ownership contract (WO-026, ADR 0010).

Exactly one role ever creates or alters database objects in each Taproot
schema — the per-service DDL owner role — while the runtime connects as a
DML-only app role. This module is the single source of truth for:

* the canonical role/schema/database names per service (both contract
  shapes: per-service and the shared ``system_record`` database),
* the idempotent bootstrap SQL that establishes the contract (the only
  step that ever needs admin privilege), and
* the verify SQL that asserts the contract fail-closed before migrations
  run (used by every migration entrypoint and the customer preflight).

The module is intentionally stdlib-only and runnable as a standalone
script (``python src/taproot_common/db_contract.py --help``) so operator
tasks can use it without installing taproot-common's dependencies.
Renderers emit plain SQL (``DO`` blocks, ``GRANT``/``ALTER``) executable
by psql or any driver; nothing here opens a database connection.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from collections.abc import Sequence

CONTRACT_VERSION = 1

REMEDIATION = (
    "Run the db-ownership-contract bootstrap for this service with admin credentials "
    "(taproot-infra workflow db-ownership-contract.yml, or the checked-in customer "
    "bootstrap SQL in taproot-infra/deploy/customer/docs/secrets/). "
    "See taproot-infra/docs/runbooks/db-ownership-migration.md."
)


class DbContractError(ValueError):
    """Raised for unknown services or invalid identifiers."""


def quote_ident(value: str) -> str:
    if not value or "\x00" in value:
        raise DbContractError("invalid PostgreSQL identifier")
    return '"' + value.replace('"', '""') + '"'


def quote_literal(value: str) -> str:
    if "\x00" in value:
        raise DbContractError("invalid PostgreSQL literal")
    return "'" + value.replace("'", "''") + "'"


@dataclasses.dataclass(frozen=True)
class SchemaContract:
    """One schema governed by the contract inside a service database."""

    name: str
    # Privileges the app role holds on tables in this schema. The audit
    # shapes (Front-S ``audit``, system_record fact tables) stay
    # append-only by omitting UPDATE/DELETE.
    app_table_privileges: tuple[str, ...] = ("SELECT", "INSERT", "UPDATE", "DELETE")
    # Retrieval-S runtime creates one physical table per store; it is the
    # only schema where the app role keeps CREATE.
    app_can_create: bool = False
    # LIKE patterns for runtime-created objects that are legitimately
    # owned by the app role (Retrieval-S dynamic vector-store tables).
    app_owned_like: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class ServiceDbContract:
    """Per-service shape: one DDL owner role + one DML app role."""

    service: str
    database: str
    app_role: str
    ddl_role: str
    schemas: tuple[SchemaContract, ...]

    @property
    def ddl_bundle_secret(self) -> str:
        """Secrets Manager bundle template for the migration credential."""
        return f"taproot-{{env}}-{self.service}-db-ddl"

    @property
    def app_bundle_secret(self) -> str:
        return f"taproot-{{env}}-{self.service}-db"

    @property
    def needs_app_membership(self) -> bool:
        """DDL role needs membership in the app role when the runtime owns
        objects (so migrations can still ALTER dynamic tables)."""
        return any(s.app_owned_like for s in self.schemas)


@dataclasses.dataclass(frozen=True)
class SharedDbContract:
    """Shared-database shape (system_record): one owner/DDL role that runs
    the taproot-common migrations, one shared append-only writer role, and
    read-only reader roles. Honors the WO-018 0004 append-only model."""

    database: str
    schema: str
    ddl_role: str
    writer_role: str
    reader_roles: tuple[str, ...]
    # Tables the writer may UPDATE in place (live-editable config; every
    # other table is an append-only fact log guarded by the WO-018 0004
    # reject trigger and the absence of UPDATE/DELETE grants).
    writer_update_tables: tuple[str, ...] = ("retention_policies",)


SERVICE_DB_CONTRACTS: dict[str, ServiceDbContract] = {
    "front": ServiceDbContract(
        service="front",
        database="front_s",
        app_role="front_s_app",
        ddl_role="taproot_front_ddl",
        schemas=(
            SchemaContract(name="public"),
            SchemaContract(name="audit", app_table_privileges=("SELECT", "INSERT")),
        ),
    ),
    "prompt": ServiceDbContract(
        service="prompt",
        database="taproot",
        app_role="prompt_s_app",
        ddl_role="taproot_prompt_ddl",
        schemas=(SchemaContract(name="prompt_s"),),
    ),
    "evals": ServiceDbContract(
        service="evals",
        database="evalservice",
        app_role="evals_app",
        ddl_role="taproot_evals_ddl",
        schemas=(SchemaContract(name="public"),),
    ),
    "retrieval": ServiceDbContract(
        service="retrieval",
        database="retrieval",
        app_role="retrieval_app",
        ddl_role="taproot_retrieval_ddl",
        schemas=(
            SchemaContract(
                name="public",
                app_can_create=True,
                app_owned_like=("%\\_vector\\_store",),
            ),
        ),
    ),
    "toolbox": ServiceDbContract(
        service="toolbox",
        database="toolbox",
        app_role="toolbox_app",
        ddl_role="taproot_toolbox_ddl",
        schemas=(SchemaContract(name="public"),),
    ),
    "worker": ServiceDbContract(
        service="worker",
        database="worker_s",
        app_role="worker_s_app",
        ddl_role="taproot_worker_ddl",
        schemas=(SchemaContract(name="public"),),
    ),
    "guardrail": ServiceDbContract(
        service="guardrail",
        database="guardrail_s",
        app_role="guardrail_s_app",
        ddl_role="taproot_guardrail_ddl",
        schemas=(SchemaContract(name="guardrail_s"),),
    ),
}

SYSTEM_RECORD_CONTRACT = SharedDbContract(
    database="system_record",
    schema="public",
    ddl_role="taproot_system_record_ddl",
    writer_role="taproot_system_record_writer",
    reader_roles=("front_s_app",),
)


def get_service_contract(service: str) -> ServiceDbContract:
    try:
        return SERVICE_DB_CONTRACTS[service]
    except KeyError:
        raise DbContractError(
            f"unknown service {service!r}; known: {', '.join(sorted(SERVICE_DB_CONTRACTS))}, system_record"
        ) from None


def _ensure_role(role: str, *, login: bool) -> str:
    role_i = quote_ident(role)
    role_l = quote_literal(role)
    mode = "LOGIN" if login else "NOLOGIN"
    return (
        "DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {role_l}) "
        f"THEN CREATE ROLE {role_i} {mode}; END IF; END $$;"
    )


def _set_role_password(role: str, password_sql: str) -> str:
    return f"ALTER ROLE {quote_ident(role)} WITH LOGIN PASSWORD {password_sql};"


def _grant_membership_to_current_user(role: str) -> str:
    # PG16 splits membership into USAGE/SET behaviors, and a CREATEROLE
    # creator's implicit grant is ADMIN OPTION only — so check the abilities
    # the bootstrap actually needs (inherited privileges + SET ROLE), not
    # bare MEMBER-ship.
    role_i = quote_ident(role)
    role_l = quote_literal(role)
    return f"""DO $$
BEGIN
    IF NOT (pg_has_role(current_user, {role_l}, 'USAGE')
            AND pg_has_role(current_user, {role_l},
                CASE WHEN current_setting('server_version_num')::int >= 160000
                     THEN 'SET' ELSE 'MEMBER' END)) THEN
        EXECUTE format('GRANT {role_i} TO %I', current_user);
    END IF;
END $$;"""


def _revoke_membership_from_current_user(role: str) -> str:
    """Admin memberships taken during the bootstrap must not persist: if the
    role (or anything it belongs to) is ever in ``rds_iam``, a lingering
    membership PAM-locks the admin out of password auth entirely. On PG16+
    only the SET/INHERIT behaviors are revoked so the CREATEROLE admin keeps
    its implicit ADMIN OPTION (needed for idempotent re-runs)."""

    role_i = quote_ident(role)
    role_l = quote_literal(role)
    return f"""DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_auth_members m
               JOIN pg_roles g ON g.oid = m.roleid
               JOIN pg_roles u ON u.oid = m.member
               WHERE g.rolname = {role_l} AND u.rolname = current_user) THEN
        IF current_setting('server_version_num')::int >= 160000 THEN
            EXECUTE format('REVOKE SET OPTION FOR {role_i} FROM %I', current_user);
            EXECUTE format('REVOKE INHERIT OPTION FOR {role_i} FROM %I', current_user);
        ELSE
            EXECUTE format('REVOKE {role_i} FROM %I', current_user);
        END IF;
    END IF;
END $$;"""


def _reassign_schema_objects(
    schema: str,
    ddl_role: str,
    app_role: str | None,
    app_owned_like: Sequence[str],
) -> str:
    """Empirically reconcile ownership of every relation in the schema onto
    the DDL role (or the app role for declared runtime-owned patterns),
    granting the admin membership in each distinct current owner first.
    Memberships taken here are revoked before the block ends: a lingering
    admin membership in a role that belongs to ``rds_iam`` (Front-S's app
    role does, for IAM DB auth) PAM-locks the admin's password login.
    Idempotent; a no-op on a conforming database."""

    schema_l = quote_literal(schema)
    ddl_l = quote_literal(ddl_role)
    if app_role is not None and app_owned_like:
        patterns = ", ".join(quote_literal(p) for p in app_owned_like)
        app_l = quote_literal(app_role)
        target_expr = f"CASE WHEN r.relname LIKE ANY (ARRAY[{patterns}]) THEN {app_l} ELSE {ddl_l} END"
    else:
        target_expr = ddl_l
    return f"""DO $$
DECLARE
    r RECORD;
    target TEXT;
    granted TEXT[] := '{{}}';
    g TEXT;
    member_mode TEXT := CASE WHEN current_setting('server_version_num')::int >= 160000
                             THEN 'SET' ELSE 'MEMBER' END;
BEGIN
    FOR r IN
        SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner) AS owner
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = {schema_l}
          AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
          -- serial/identity sequences follow their table's owner and
          -- reject a direct ALTER SEQUENCE OWNER
          AND NOT (c.relkind = 'S' AND EXISTS (
              SELECT FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype IN ('a', 'i')
          ))
    LOOP
        target := {target_expr};
        IF r.owner = target THEN
            CONTINUE;
        END IF;
        IF r.owner <> current_user AND NOT pg_has_role(current_user, r.owner, 'USAGE') THEN
            EXECUTE format('GRANT %I TO %I', r.owner, current_user);
            granted := granted || r.owner;
        END IF;
        IF NOT (pg_has_role(current_user, target, 'USAGE')
                AND pg_has_role(current_user, target, member_mode)) THEN
            EXECUTE format('GRANT %I TO %I', target, current_user);
            granted := granted || target;
        END IF;
        IF r.relkind = 'S' THEN
            EXECUTE format('ALTER SEQUENCE %I.%I OWNER TO %I', {schema_l}, r.relname, target);
        ELSIF r.relkind = 'v' THEN
            EXECUTE format('ALTER VIEW %I.%I OWNER TO %I', {schema_l}, r.relname, target);
        ELSIF r.relkind = 'm' THEN
            EXECUTE format('ALTER MATERIALIZED VIEW %I.%I OWNER TO %I', {schema_l}, r.relname, target);
        ELSE
            EXECUTE format('ALTER TABLE %I.%I OWNER TO %I', {schema_l}, r.relname, target);
        END IF;
    END LOOP;
    FOR r IN
        SELECT p.proname, p.oid, pg_get_userbyid(p.proowner) AS owner,
               pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = {schema_l}
          AND pg_get_userbyid(p.proowner) <> {ddl_l}
    LOOP
        IF r.owner <> current_user AND NOT pg_has_role(current_user, r.owner, 'USAGE') THEN
            EXECUTE format('GRANT %I TO %I', r.owner, current_user);
            granted := granted || r.owner;
        END IF;
        EXECUTE format('ALTER FUNCTION %I.%I(%s) OWNER TO %I', {schema_l}, r.proname, r.args, {ddl_l});
    END LOOP;
    FOREACH g IN ARRAY granted LOOP
        IF current_setting('server_version_num')::int >= 160000 THEN
            EXECUTE format('REVOKE SET OPTION FOR %I FROM %I', g, current_user);
            EXECUTE format('REVOKE INHERIT OPTION FOR %I FROM %I', g, current_user);
        ELSE
            EXECUTE format('REVOKE %I FROM %I', g, current_user);
        END IF;
    END LOOP;
END $$;"""


def _schema_grants(schema: SchemaContract, ddl_role: str, app_role: str) -> list[str]:
    s = quote_ident(schema.name)
    ddl = quote_ident(ddl_role)
    app = quote_ident(app_role)
    table_privs = ", ".join(schema.app_table_privileges)
    statements = [
        f"CREATE SCHEMA IF NOT EXISTS {s};",
        f"ALTER SCHEMA {s} OWNER TO {ddl};",
        f"REVOKE CREATE ON SCHEMA {s} FROM PUBLIC;",
        f"GRANT USAGE ON SCHEMA {s} TO {app};",
    ]
    if schema.app_can_create:
        statements.append(f"GRANT CREATE ON SCHEMA {s} TO {app};")
    else:
        statements.append(f"REVOKE CREATE ON SCHEMA {s} FROM {app};")
    statements.append(
        _reassign_schema_objects(schema.name, ddl_role, app_role, schema.app_owned_like)
    )
    statements.extend(
        [
            f"REVOKE ALL ON ALL TABLES IN SCHEMA {s} FROM {app};",
            f"GRANT {table_privs} ON ALL TABLES IN SCHEMA {s} TO {app};",
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {s} TO {app};",
            f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {s} TO {app};",
            # Future objects the DDL role creates auto-grant DML to the app
            # role — creator == owner == alterer, forever.
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ddl} IN SCHEMA {s} "
            f"GRANT {table_privs} ON TABLES TO {app};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ddl} IN SCHEMA {s} "
            f"GRANT USAGE, SELECT ON SEQUENCES TO {app};",
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {ddl} IN SCHEMA {s} "
            f"GRANT EXECUTE ON FUNCTIONS TO {app};",
            # Retire the legacy admin-created defaults that granted ALL.
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {s} REVOKE ALL ON TABLES FROM {app};",
            f"ALTER DEFAULT PRIVILEGES IN SCHEMA {s} REVOKE ALL ON SEQUENCES FROM {app};",
        ]
    )
    return statements


def render_service_bootstrap(
    contract: ServiceDbContract, *, ddl_password_sql: str | None = None
) -> list[str]:
    """Idempotent bootstrap: run connected to the service database with a
    role that can create roles and reassign ownership (the RDS master or a
    customer admin). ``ddl_password_sql`` is a pre-quoted SQL fragment
    (``quote_literal(pw)`` or a psql variable like ``:'ddl_password'``);
    when None the DDL role's login credential is left unmanaged."""

    db = quote_ident(contract.database)
    ddl = quote_ident(contract.ddl_role)
    app = quote_ident(contract.app_role)
    statements = [
        "SELECT pg_advisory_lock(812381205);",
        _ensure_role(contract.ddl_role, login=ddl_password_sql is not None),
        _ensure_role(contract.app_role, login=False),
    ]
    if ddl_password_sql is not None:
        statements.append(_set_role_password(contract.ddl_role, ddl_password_sql))
    statements.extend(
        [
            _grant_membership_to_current_user(contract.ddl_role),
            f"GRANT CONNECT, CREATE ON DATABASE {db} TO {ddl};",
            f"GRANT CONNECT ON DATABASE {db} TO {app};",
            f"REVOKE CREATE ON DATABASE {db} FROM {app};",
        ]
    )
    for schema in contract.schemas:
        statements.extend(_schema_grants(schema, contract.ddl_role, contract.app_role))
    if contract.needs_app_membership:
        # Migrations must still be able to ALTER runtime-owned dynamic
        # tables (Retrieval-S per-store tables), so the DDL role is a
        # member of the app role — never the other way around.
        statements.append(f"GRANT {app} TO {ddl};")
    if len(contract.schemas) == 1 and contract.schemas[0].name != "public":
        schema_name = contract.schemas[0].name
        for role in (contract.ddl_role, contract.app_role):
            statements.append(
                f"ALTER ROLE {quote_ident(role)} IN DATABASE {db} "
                f"SET search_path = {quote_ident(schema_name)}, public;"
            )
    # The admin keeps no membership in contract roles: if the app role is in
    # rds_iam (IAM DB auth), a lingering membership PAM-locks the admin's
    # password login for every later connection.
    statements.append(_revoke_membership_from_current_user(contract.app_role))
    statements.append(_revoke_membership_from_current_user(contract.ddl_role))
    statements.append("SELECT pg_advisory_unlock(812381205);")
    return statements


def render_shared_bootstrap(
    contract: SharedDbContract = SYSTEM_RECORD_CONTRACT,
) -> list[str]:
    """Shared-database shape (system_record): one NOLOGIN owner/DDL role
    (assumed via SET ROLE by the taproot-common migration task), one shared
    append-only writer, and read-only readers. Preserves the WO-018 0004
    append-only guarantees: the writer never gets UPDATE/DELETE on fact
    tables and never owns anything."""

    db = quote_ident(contract.database)
    s = quote_ident(contract.schema)
    ddl = quote_ident(contract.ddl_role)
    writer = quote_ident(contract.writer_role)
    statements = [
        "SELECT pg_advisory_lock(812381206);",
        _ensure_role(contract.ddl_role, login=False),
        _ensure_role(contract.writer_role, login=False),
        _grant_membership_to_current_user(contract.ddl_role),
        f"GRANT CONNECT, CREATE ON DATABASE {db} TO {ddl};",
        f"GRANT CONNECT ON DATABASE {db} TO {writer};",
        f"REVOKE CREATE ON DATABASE {db} FROM {writer};",
        f"CREATE SCHEMA IF NOT EXISTS {s};",
        f"ALTER SCHEMA {s} OWNER TO {ddl};",
        f"REVOKE CREATE ON SCHEMA {s} FROM PUBLIC;",
        f"REVOKE CREATE ON SCHEMA {s} FROM {writer};",
        f"GRANT USAGE ON SCHEMA {s} TO {writer};",
        _reassign_schema_objects(contract.schema, contract.ddl_role, None, ()),
        f"REVOKE ALL ON ALL TABLES IN SCHEMA {s} FROM {writer};",
        f"GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA {s} TO {writer};",
        f"GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {s} TO {writer};",
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {ddl} IN SCHEMA {s} "
        f"GRANT SELECT, INSERT ON TABLES TO {writer};",
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {ddl} IN SCHEMA {s} "
        f"GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {writer};",
    ]
    for table in contract.writer_update_tables:
        table_l = quote_literal(table)
        statements.append(
            "DO $$ BEGIN "
            f"IF EXISTS (SELECT FROM pg_tables WHERE schemaname = {quote_literal(contract.schema)} "
            f"AND tablename = {table_l}) THEN "
            f"EXECUTE 'GRANT UPDATE ON {s}.' || quote_ident({table_l}) || ' TO {writer}'; "
            "END IF; END $$;"
        )
    for reader in contract.reader_roles:
        reader_i = quote_ident(reader)
        statements.extend(
            [
                _ensure_role(reader, login=False),
                f"GRANT CONNECT ON DATABASE {db} TO {reader_i};",
                f"GRANT USAGE ON SCHEMA {s} TO {reader_i};",
                f"GRANT SELECT ON ALL TABLES IN SCHEMA {s} TO {reader_i};",
                f"ALTER DEFAULT PRIVILEGES FOR ROLE {ddl} IN SCHEMA {s} "
                f"GRANT SELECT ON TABLES TO {reader_i};",
            ]
        )
    # See render_service_bootstrap: no lingering admin memberships. The
    # migration path re-grants transiently before its SET ROLE.
    statements.append(_revoke_membership_from_current_user(contract.writer_role))
    statements.append(_revoke_membership_from_current_user(contract.ddl_role))
    statements.append("SELECT pg_advisory_unlock(812381206);")
    return statements


def _verify_schema_statements(
    schema: SchemaContract, ddl_role: str, app_role: str
) -> list[str]:
    s_l = quote_literal(schema.name)
    ddl_l = quote_literal(ddl_role)
    app_l = quote_literal(app_role)
    remediation = quote_literal(REMEDIATION)[1:-1]
    statements = [
        # Schema exists and is owned by the DDL role.
        "DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner "
        f"WHERE n.nspname = {s_l} AND r.rolname = {ddl_l}) THEN "
        f"RAISE EXCEPTION 'db-ownership-contract: schema % is missing or not owned by %. {remediation}', {s_l}, {ddl_l}; "
        "END IF; END $$;",
    ]
    if schema.app_owned_like:
        patterns = ", ".join(quote_literal(p) for p in schema.app_owned_like)
        allowed = (
            f"(pg_get_userbyid(c.relowner) = {ddl_l} "
            f"OR (pg_get_userbyid(c.relowner) = {app_l} AND c.relname LIKE ANY (ARRAY[{patterns}])))"
        )
    else:
        allowed = f"pg_get_userbyid(c.relowner) = {ddl_l}"
    statements.append(
        f"""DO $$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(format('%s.%s owned by %s', n.nspname, c.relname, pg_get_userbyid(c.relowner)), '; ')
    INTO bad
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = {s_l}
      AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
      -- serial/identity sequences follow their table's owner
      AND NOT (c.relkind = 'S' AND EXISTS (
          SELECT FROM pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype IN ('a', 'i')
      ))
      AND NOT {allowed};
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'db-ownership-contract: objects with wrong owner in schema %: %. {remediation}', {s_l}, bad;
    END IF;
END $$;"""
    )
    statements.append(
        # Future DDL-created tables must auto-grant DML to the app role.
        "DO $$ BEGIN "
        "IF NOT EXISTS ("
        "SELECT FROM pg_default_acl d "
        "JOIN pg_namespace n ON n.oid = d.defaclnamespace "
        "JOIN pg_roles o ON o.oid = d.defaclrole "
        "CROSS JOIN LATERAL aclexplode(d.defaclacl) a "
        "JOIN pg_roles g ON g.oid = a.grantee "
        f"WHERE n.nspname = {s_l} AND o.rolname = {ddl_l} AND d.defaclobjtype = 'r' "
        f"AND g.rolname = {app_l} AND a.privilege_type = 'INSERT') THEN "
        f"RAISE EXCEPTION 'db-ownership-contract: default privileges for role % in schema % do not grant the app role %. {remediation}', {ddl_l}, {s_l}, {app_l}; "
        "END IF; END $$;"
    )
    expected_create = "true" if schema.app_can_create else "false"
    statements.append(
        "DO $$ BEGIN "
        f"IF has_schema_privilege({app_l}, {s_l}, 'CREATE') IS DISTINCT FROM {expected_create} THEN "
        f"RAISE EXCEPTION 'db-ownership-contract: app role % CREATE privilege on schema % must be {expected_create}. {remediation}', {app_l}, {s_l}; "
        "END IF; END $$;"
    )
    return statements


def render_service_verify(
    contract: ServiceDbContract, *, expect_migration_role: bool = False
) -> list[str]:
    """Assert the contract; every statement raises with remediation text on
    violation. With ``expect_migration_role`` the connected role itself must
    be the DDL role (the fail-closed migration-entrypoint assertion that
    replaces the WO-003 self-healing preamble)."""

    statements: list[str] = []
    if expect_migration_role:
        ddl_l = quote_literal(contract.ddl_role)
        remediation = quote_literal(REMEDIATION)[1:-1]
        statements.append(
            "DO $$ BEGIN "
            f"IF current_user <> {ddl_l} THEN "
            f"RAISE EXCEPTION 'db-ownership-contract: migrations for {contract.service} must run as %, connected as %. "
            f"Point the migration job at the {contract.ddl_bundle_secret} credential bundle. {remediation}', {ddl_l}, current_user; "
            "END IF; END $$;"
        )
    for schema in contract.schemas:
        statements.extend(
            _verify_schema_statements(schema, contract.ddl_role, contract.app_role)
        )
    return statements


def render_shared_verify(
    contract: SharedDbContract = SYSTEM_RECORD_CONTRACT,
) -> list[str]:
    s_l = quote_literal(contract.schema)
    ddl_l = quote_literal(contract.ddl_role)
    writer_l = quote_literal(contract.writer_role)
    remediation = quote_literal(REMEDIATION)[1:-1]
    update_allowed = ", ".join(quote_literal(t) for t in contract.writer_update_tables)
    return [
        "DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner "
        f"WHERE n.nspname = {s_l} AND r.rolname = {ddl_l}) THEN "
        f"RAISE EXCEPTION 'db-ownership-contract: system_record schema % is not owned by %. {remediation}', {s_l}, {ddl_l}; "
        "END IF; END $$;",
        f"""DO $$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(format('%s.%s owned by %s', n.nspname, c.relname, pg_get_userbyid(c.relowner)), '; ')
    INTO bad
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = {s_l}
      AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
      -- serial/identity sequences follow their table's owner
      AND NOT (c.relkind = 'S' AND EXISTS (
          SELECT FROM pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype IN ('a', 'i')
      ))
      AND pg_get_userbyid(c.relowner) <> {ddl_l};
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'db-ownership-contract: system_record objects with wrong owner: %. {remediation}', bad;
    END IF;
END $$;""",
        # The shared writer must stay append-only: INSERT yes, UPDATE/DELETE
        # no (except declared live-editable config tables).
        f"""DO $$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(t.tablename, '; ')
    INTO bad
    FROM pg_tables t
    WHERE t.schemaname = {s_l}
      AND t.tablename NOT IN ({update_allowed})
      AND (has_table_privilege({writer_l}, format('%I.%I', t.schemaname, t.tablename), 'UPDATE')
           OR has_table_privilege({writer_l}, format('%I.%I', t.schemaname, t.tablename), 'DELETE'));
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'db-ownership-contract: system_record writer % holds UPDATE/DELETE on append-only tables: %. {remediation}', {writer_l}, bad;
    END IF;
END $$;""",
    ]


def render_bootstrap(service: str, *, ddl_password_sql: str | None = None) -> list[str]:
    if service == "system_record":
        return render_shared_bootstrap()
    return render_service_bootstrap(
        get_service_contract(service), ddl_password_sql=ddl_password_sql
    )


def render_verify(service: str, *, expect_migration_role: bool = False) -> list[str]:
    if service == "system_record":
        return render_shared_verify()
    return render_service_verify(
        get_service_contract(service), expect_migration_role=expect_migration_role
    )


MIGRATION_CREDENTIALS_ENV = "TAPROOT_USE_DDL_CREDENTIALS"


def database_secret_purpose(environ: dict[str, str] | None = None) -> str:
    """Which canonical DB secret a process should hydrate: migration jobs set
    ``TAPROOT_USE_DDL_CREDENTIALS`` and get the ``db-ddl`` bundle (the
    ``taproot_<svc>_ddl`` credential); everything else stays on ``db``."""

    env = environ if environ is not None else os.environ
    value = (env.get(MIGRATION_CREDENTIALS_ENV) or "").strip().lower()
    return "db-ddl" if value in {"1", "true", "yes"} else "db"


def should_enforce_contract(environ: dict[str, str] | None = None) -> bool:
    """Whether a migration entrypoint must assert the contract fail-closed.

    ``TAPROOT_DB_CONTRACT_ENFORCE`` (1/true/yes or 0/false/no) always wins;
    otherwise enforcement follows the deployed-cloud signal so local dev and
    CI service containers keep migrating as plain users."""

    env = environ if environ is not None else os.environ
    override = (env.get("TAPROOT_DB_CONTRACT_ENFORCE") or "").strip().lower()
    if override in {"1", "true", "yes"}:
        return True
    if override in {"0", "false", "no"}:
        return False
    provider = (
        (env.get("TAPROOT_CLOUD_PROVIDER") or env.get("CLOUD_PROVIDER") or "")
        .strip()
        .lower()
    )
    return provider not in {"", "local"}


def contract_summary() -> dict[str, object]:
    """Machine-readable registry summary (consumed by tooling and tests)."""
    return {
        "contract_version": CONTRACT_VERSION,
        "services": {
            name: {
                "database": c.database,
                "app_role": c.app_role,
                "ddl_role": c.ddl_role,
                "schemas": [dataclasses.asdict(s) for s in c.schemas],
                "ddl_bundle_secret": c.ddl_bundle_secret,
                "app_bundle_secret": c.app_bundle_secret,
            }
            for name, c in SERVICE_DB_CONTRACTS.items()
        },
        "system_record": dataclasses.asdict(SYSTEM_RECORD_CONTRACT),
    }


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    boot = sub.add_parser("render-bootstrap", help="idempotent admin bootstrap SQL")
    boot.add_argument("--service", required=True)
    boot.add_argument(
        "--ddl-password-env",
        help="name of an env var holding the DDL role password (embedded as a quoted literal)",
    )
    boot.add_argument(
        "--psql-var-passwords",
        action="store_true",
        help="reference the DDL password as the psql variable :'ddl_password' instead",
    )

    verify = sub.add_parser("render-verify", help="fail-closed contract assertion SQL")
    verify.add_argument("--service", required=True)
    verify.add_argument("--expect-migration-role", action="store_true")

    sub.add_parser("summary", help="print the contract registry as JSON")

    args = parser.parse_args(argv)
    if args.command == "summary":
        print(json.dumps(contract_summary(), indent=2, sort_keys=True))
        return 0
    if args.command == "render-bootstrap":
        password_sql = None
        if args.psql_var_passwords:
            password_sql = ":'ddl_password'"
        elif args.ddl_password_env:
            value = os.environ.get(args.ddl_password_env, "")
            if not value:
                print(
                    f"error: env var {args.ddl_password_env} is empty", file=sys.stderr
                )
                return 1
            password_sql = quote_literal(value)
        statements = render_bootstrap(args.service, ddl_password_sql=password_sql)
    else:
        statements = render_verify(
            args.service, expect_migration_role=args.expect_migration_role
        )
    print("\n".join(statements))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
