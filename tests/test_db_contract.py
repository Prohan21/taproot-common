"""Unit tests for the DB role & ownership contract registry and renderers
(WO-026). Pure SQL-rendering tests; real-Postgres behavior is proven in
tests/test_db_contract_postgres.py."""

from __future__ import annotations

import pytest

from taproot_common.db_contract import (
    REMEDIATION,
    SERVICE_DB_CONTRACTS,
    SYSTEM_RECORD_CONTRACT,
    DbContractError,
    _main,
    contract_summary,
    get_service_contract,
    quote_literal,
    render_bootstrap,
    render_service_bootstrap,
    render_service_verify,
    render_shared_bootstrap,
    render_shared_verify,
    render_verify,
)

RELEASE_LANE = {"front", "prompt", "evals", "retrieval", "toolbox", "guardrail"}


class TestRegistry:
    def test_covers_release_lane_and_worker(self) -> None:
        assert RELEASE_LANE | {"worker"} == set(SERVICE_DB_CONTRACTS)

    def test_roles_and_databases_match_live_topology(self) -> None:
        live = {
            "front": ("front_s", "front_s_app"),
            "prompt": ("taproot", "prompt_s_app"),
            "evals": ("evalservice", "evals_app"),
            "retrieval": ("retrieval", "retrieval_app"),
            "toolbox": ("toolbox", "toolbox_app"),
            "worker": ("worker_s", "worker_s_app"),
            "guardrail": ("guardrail_s", "guardrail_s_app"),
        }
        for service, (database, app_role) in live.items():
            contract = SERVICE_DB_CONTRACTS[service]
            assert contract.database == database
            assert contract.app_role == app_role
            assert contract.ddl_role == f"taproot_{service}_ddl"

    def test_ddl_roles_are_unique(self) -> None:
        roles = [c.ddl_role for c in SERVICE_DB_CONTRACTS.values()]
        assert len(roles) == len(set(roles))

    def test_secret_bundle_names(self) -> None:
        contract = SERVICE_DB_CONTRACTS["retrieval"]
        assert contract.ddl_bundle_secret == "taproot-{env}-retrieval-db-ddl"
        assert contract.app_bundle_secret == "taproot-{env}-retrieval-db"

    def test_only_retrieval_allows_runtime_ddl(self) -> None:
        for name, contract in SERVICE_DB_CONTRACTS.items():
            for schema in contract.schemas:
                if name == "retrieval":
                    assert schema.app_can_create
                    assert schema.app_owned_like == ("%\\_vector\\_store",)
                else:
                    assert not schema.app_can_create
                    assert schema.app_owned_like == ()

    def test_front_audit_schema_is_append_only(self) -> None:
        audit = next(
            s for s in SERVICE_DB_CONTRACTS["front"].schemas if s.name == "audit"
        )
        assert audit.app_table_privileges == ("SELECT", "INSERT")

    def test_system_record_shape(self) -> None:
        assert SYSTEM_RECORD_CONTRACT.database == "system_record"
        assert SYSTEM_RECORD_CONTRACT.ddl_role == "taproot_system_record_ddl"
        assert SYSTEM_RECORD_CONTRACT.writer_role == "taproot_system_record_writer"
        assert SYSTEM_RECORD_CONTRACT.writer_update_tables == ("retention_policies",)

    def test_unknown_service_raises(self) -> None:
        with pytest.raises(DbContractError):
            get_service_contract("nope")

    def test_summary_is_json_shaped(self) -> None:
        summary = contract_summary()
        assert summary["contract_version"] == 1
        assert set(summary["services"]) == set(SERVICE_DB_CONTRACTS)


class TestBootstrapRendering:
    def test_service_bootstrap_core_statements(self) -> None:
        statements = render_service_bootstrap(SERVICE_DB_CONTRACTS["evals"])
        sql = "\n".join(statements)
        assert 'ALTER SCHEMA "public" OWNER TO "taproot_evals_ddl"' in sql
        assert 'REVOKE CREATE ON SCHEMA "public" FROM "evals_app"' in sql
        assert (
            'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "public" TO "evals_app"'
            in sql
        )
        assert (
            'ALTER DEFAULT PRIVILEGES FOR ROLE "taproot_evals_ddl" IN SCHEMA "public" '
            'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "evals_app"' in sql
        )
        assert 'REVOKE CREATE ON DATABASE "evalservice" FROM "evals_app"' in sql

    def test_password_literal_is_quoted(self) -> None:
        statements = render_service_bootstrap(
            SERVICE_DB_CONTRACTS["evals"], ddl_password_sql=quote_literal("p'w")
        )
        assert (
            "ALTER ROLE \"taproot_evals_ddl\" WITH LOGIN PASSWORD 'p''w';" in statements
        )

    def test_no_password_leaves_login_unmanaged(self) -> None:
        sql = "\n".join(render_service_bootstrap(SERVICE_DB_CONTRACTS["evals"]))
        assert "PASSWORD" not in sql

    def test_retrieval_keeps_runtime_create_and_membership(self) -> None:
        sql = "\n".join(render_service_bootstrap(SERVICE_DB_CONTRACTS["retrieval"]))
        assert 'GRANT CREATE ON SCHEMA "public" TO "retrieval_app"' in sql
        assert 'GRANT "retrieval_app" TO "taproot_retrieval_ddl"' in sql
        assert "LIKE ANY (ARRAY['%\\_vector\\_store'])" in sql

    def test_named_schema_sets_search_path(self) -> None:
        sql = "\n".join(render_service_bootstrap(SERVICE_DB_CONTRACTS["guardrail"]))
        assert (
            'ALTER ROLE "guardrail_s_app" IN DATABASE "guardrail_s" '
            'SET search_path = "guardrail_s", public;' in sql
        )

    def test_public_schema_services_do_not_touch_search_path(self) -> None:
        sql = "\n".join(render_service_bootstrap(SERVICE_DB_CONTRACTS["evals"]))
        assert "search_path" not in sql

    def test_front_audit_schema_gets_insert_only(self) -> None:
        sql = "\n".join(render_service_bootstrap(SERVICE_DB_CONTRACTS["front"]))
        assert (
            'GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA "audit" TO "front_s_app"'
            in sql
        )
        assert (
            'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "audit"'
            not in sql
        )

    def test_shared_bootstrap_preserves_append_only(self) -> None:
        sql = "\n".join(render_shared_bootstrap())
        assert (
            'GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA "public" TO "taproot_system_record_writer"'
            in sql
        )
        assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" not in sql
        assert "'retention_policies'" in sql
        assert 'ALTER SCHEMA "public" OWNER TO "taproot_system_record_ddl"' in sql

    def test_bootstrap_is_deterministic(self) -> None:
        assert render_bootstrap("toolbox") == render_bootstrap("toolbox")


class TestVerifyRendering:
    def test_verify_asserts_schema_owner_and_objects(self) -> None:
        sql = "\n".join(render_service_verify(SERVICE_DB_CONTRACTS["evals"]))
        assert "not owned by" in sql
        assert "objects with wrong owner" in sql
        assert REMEDIATION in sql

    def test_expect_migration_role_asserts_current_user(self) -> None:
        sql = "\n".join(
            render_service_verify(
                SERVICE_DB_CONTRACTS["retrieval"], expect_migration_role=True
            )
        )
        assert "current_user <> 'taproot_retrieval_ddl'" in sql
        assert "taproot-{env}-retrieval-db-ddl" in sql

    def test_verify_without_flag_has_no_current_user_assert(self) -> None:
        sql = "\n".join(render_service_verify(SERVICE_DB_CONTRACTS["retrieval"]))
        assert "current_user <>" not in sql

    def test_retrieval_verify_allows_app_owned_vector_stores(self) -> None:
        sql = "\n".join(render_service_verify(SERVICE_DB_CONTRACTS["retrieval"]))
        assert "'retrieval_app'" in sql
        assert "LIKE ANY (ARRAY['%\\_vector\\_store'])" in sql

    def test_shared_verify_blocks_writer_update(self) -> None:
        sql = "\n".join(render_shared_verify())
        assert "append-only" in sql
        assert "'taproot_system_record_writer'" in sql

    def test_render_verify_dispatches_system_record(self) -> None:
        assert render_verify("system_record") == render_shared_verify()


class TestMigrationCredentialSwitch:
    def test_defaults_to_runtime_bundle(self) -> None:
        from taproot_common.db_contract import database_secret_purpose

        assert database_secret_purpose({}) == "db"
        assert database_secret_purpose({"TAPROOT_USE_DDL_CREDENTIALS": "0"}) == "db"

    def test_migration_jobs_get_ddl_bundle(self) -> None:
        from taproot_common.db_contract import database_secret_purpose

        assert database_secret_purpose({"TAPROOT_USE_DDL_CREDENTIALS": "1"}) == "db-ddl"
        assert (
            database_secret_purpose({"TAPROOT_USE_DDL_CREDENTIALS": "true"}) == "db-ddl"
        )


class TestEnforcementGate:
    def test_override_wins(self) -> None:
        from taproot_common.db_contract import should_enforce_contract

        assert should_enforce_contract({"TAPROOT_DB_CONTRACT_ENFORCE": "1"})
        assert not should_enforce_contract(
            {"TAPROOT_DB_CONTRACT_ENFORCE": "0", "TAPROOT_CLOUD_PROVIDER": "aws"}
        )

    def test_cloud_provider_signal(self) -> None:
        from taproot_common.db_contract import should_enforce_contract

        assert should_enforce_contract({"TAPROOT_CLOUD_PROVIDER": "aws"})
        assert should_enforce_contract({"CLOUD_PROVIDER": "azure"})
        assert not should_enforce_contract({"TAPROOT_CLOUD_PROVIDER": "local"})
        assert not should_enforce_contract({})


class TestCli:
    def test_summary_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert _main(["summary"]) == 0
        assert '"contract_version": 1' in capsys.readouterr().out

    def test_render_bootstrap_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert _main(["render-bootstrap", "--service", "guardrail"]) == 0
        assert "taproot_guardrail_ddl" in capsys.readouterr().out

    def test_render_bootstrap_psql_vars(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            _main(["render-bootstrap", "--service", "evals", "--psql-var-passwords"])
            == 0
        )
        assert ":'ddl_password'" in capsys.readouterr().out

    def test_render_bootstrap_password_env(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEST_DDL_PW", "sekret")
        assert (
            _main(
                [
                    "render-bootstrap",
                    "--service",
                    "evals",
                    "--ddl-password-env",
                    "TEST_DDL_PW",
                ]
            )
            == 0
        )
        assert "'sekret'" in capsys.readouterr().out

    def test_render_bootstrap_empty_password_env_fails(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("MISSING_PW", raising=False)
        assert (
            _main(
                [
                    "render-bootstrap",
                    "--service",
                    "evals",
                    "--ddl-password-env",
                    "MISSING_PW",
                ]
            )
            == 1
        )

    def test_render_verify_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert (
            _main(
                ["render-verify", "--service", "retrieval", "--expect-migration-role"]
            )
            == 0
        )
        assert "must run as" in capsys.readouterr().out
