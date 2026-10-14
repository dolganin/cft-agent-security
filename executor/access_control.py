"""B05 registered runtime capability, backed by the existing B04 Docker fixture."""
import subprocess
from pathlib import Path
from uuid import uuid4

from executor.access_fixture import AccessFixtureLab, digest
from schemas.access_verification import (
    AccessCheckTrace,
    AccessGenerationEvidence,
    DatabaseOwnershipProof,
)
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetProfile
from security.access_verification import binding_id, validate_access_action


class AccessVerificationRuntime:
    """Operator-owned broker. The model never receives a fixture session or object ID."""

    def __init__(self, *, profile: TargetProfile, target_repository: str | Path,
                 output_directory: str | Path, active_check_id: str):
        self.profile = profile
        self.target_repository = Path(target_repository).resolve()
        self.run_session_id = "b05-" + uuid4().hex
        self.lab = AccessFixtureLab(
            self.target_repository,
            Path(output_directory).resolve() / "fixture-lifecycle",
            profile_file=Path(__file__).resolve().parents[1] / "targets/juice-b05-access-fixture.yaml",
            active_check_id=active_check_id,
        )
        if self.lab.profile.id != profile.id or self.lab.profile.repository_path != profile.repository_path:
            raise ValueError("B05 runtime target profile mismatch")
        self.initial_snapshot: dict[str, str] | None = None

    def prepare(self):
        context = self.lab.prepare()
        if context.status != "ready":
            raise RuntimeError("B04 fixture bootstrap did not pass")
        context = self.lab.controls(context, diagnostic="control")
        if context.status != "ready":
            raise RuntimeError("B04 identity and availability controls did not pass")
        if self.lab.active_check_id in {
            "juice-address-own-write-v1", "juice-basket-own-write-v2", "juice-basket-own-write-v3",
        }:
            context = self.lab.provision_b05()
        self.initial_snapshot = dict(self.lab.source_files)
        return context

    def runtime_services(self) -> RuntimeServiceMap:
        if self.lab.resources is None or self.lab.context is None or self.lab.context.status != "ready":
            raise RuntimeError("B05 Docker fixture is not ready")
        endpoint_ids = sorted({route.endpoint for route in self.profile.verification_routes
                               if route.tool == "verify_access_control"})
        return RuntimeServiceMap(
            session_id=self.run_session_id,
            network_name=self.lab.resources["network"],
            source_files_sha256=self.lab.source_files,
            services={"juice": RuntimeService(
                name="juice", address="http://juice:3000", ready=True,
                readiness_source="http_probe",
                allowed_endpoints=endpoint_ids,
            )},
        )

    @staticmethod
    def _generation(context, *, candidate_owned: bool, reset_ok: bool, operation: str,
                    check_id: str | None = None, session_bindings: dict | None = None) -> AccessGenerationEvidence:
        roles = {role.id: role for role in context.roles}
        permission_id = ("basket-b" if operation == "own_read" or check_id in {
            "juice-basket-own-write-v2", "juice-basket-own-write-v3",
        }
                         else "address-b")
        operation_key = "read" if operation == "own_read" else "update"
        permissions = {(item.role_id, item.object_id): item for item in context.permissions}
        permission_relation = (
            ("role-a", permission_id) in permissions and not getattr(permissions[("role-a", permission_id)], operation_key)
            and ("role-b", permission_id) in permissions and getattr(permissions[("role-b", permission_id)], operation_key)
        )
        return AccessGenerationEvidence(
            generation_sha256=digest(context.generation),
            role_a_identity_sha256=roles["role-a"].identity_sha256,
            role_b_identity_sha256=roles["role-b"].identity_sha256,
            role_a_identity_verified=roles["role-a"].identity_verified,
            role_b_identity_verified=roles["role-b"].identity_verified,
            role_a_user_id=roles["role-a"].server_user_id,
            role_b_user_id=roles["role-b"].server_user_id,
            permission_profile_sha256=context.profile_sha256,
            ownership_verified=candidate_owned,
            permission_relation_verified=permission_relation,
            b04_fixture_ready=context.status == "ready",
            reset_from_previous_verified=reset_ok,
            role_a_session_binding_sha256=(session_bindings or {}).get("role_a"),
            role_b_session_binding_sha256=(session_bindings or {}).get("role_b"),
        )

    def _ready_generation(self, *, after_reset: bool):
        context = self.lab.reset() if after_reset else self.lab.context
        if context is None or context.status != "ready":
            raise RuntimeError("B04 reset/bootstrap failed")
        context = self.lab.controls(context, diagnostic="control")
        if context.status != "ready":
            raise RuntimeError("B04 post-reset controls failed")
        if self.lab.active_check_id in {
            "juice-address-own-write-v1", "juice-basket-own-write-v2", "juice-basket-own-write-v3",
        }:
            context = self.lab.provision_b05()
        return context

    def execute(self, action):
        registration = validate_access_action(self.profile, action)
        contexts = [self.lab.context]
        exchanges = []
        controls: dict[str, bool] = {}
        generations = []
        basket_snapshots = []
        ownership_proofs: list[DatabaseOwnershipProof] = []
        reset_complete = True
        technical_error = None
        try:
            if self.lab.context is None or self.lab.context.status != "ready":
                raise RuntimeError("B04 fixture is not ready")
            operation = registration.operation
            required_controls = (
                {"owner_availability", "negative_control", "attacker_self", "ownership",
                 "permission_relation", "cleanup_baseline"}
                if operation == "own_read" else
                {"owner_write_control", "attacker_self", "negative_control", "ownership",
                 "permission_relation", "cleanup_baseline"}
                if registration.check_id == "juice-basket-own-write-v2" else
                {"owner_write_control", "attacker_self", "authentication_control", "ownership",
                 "permission_relation", "non_interference", "repeat_reset", "cleanup_baseline"}
                if registration.check_id == "juice-basket-own-write-v3" else
                {"owner_availability", "negative_control", "attacker_identity", "ownership",
                 "permission_relation"}
                if operation == "ownership_transfer" else
                {"owner_write_control", "attacker_self", "negative_control", "ownership",
                 "permission_relation", "cleanup_baseline"}
            )

            def merge_controls(step):
                values = {key: value for key, value in step.controls.items() if key in required_controls}
                if registration.check_id == "juice-basket-own-write-v3":
                    for key, value in values.items():
                        controls[key] = controls.get(key, True) and value
                else:
                    controls.update(values)

            first_name = (
                "b05-own-read-first" if operation == "own_read" else
                "b05-basket-write-v3-first" if registration.check_id == "juice-basket-own-write-v3" else
                "b05-basket-write-first" if registration.check_id == "juice-basket-own-write-v2" else
                "b05-ownership-transfer-first" if operation == "ownership_transfer" else
                "b05-own-write-first"
            )
            first_owner_before = (
                self.lab.observe_address_owner(phase="before")
                if operation == "ownership_transfer" else None
            )
            first = self.lab.b05_step(first_name)
            merge_controls(first)
            exchanges.extend(first.exchanges)
            basket_snapshots.extend(first.basket_snapshots)
            generations.append(self._generation(
                contexts[-1],
                candidate_owned=bool(first.controls.get("ownership")), reset_ok=True,
                operation=operation, check_id=registration.check_id,
                session_bindings={"role_a": first.role_a_session_binding_sha256,
                                  "role_b": first.role_b_session_binding_sha256},
            ))

            if operation == "ownership_transfer":
                before = first_owner_before
                ownership_proofs.append(before)
                after = self.lab.observe_address_owner(phase="after")
                ownership_proofs.append(after)
                probe_index = next(index for index, item in enumerate(first.exchanges)
                                   if item.exchange_id == "probe-t-transfer")
                probe = first.exchanges[probe_index]
                first.exchanges[probe_index] = probe.model_copy(update={"mutation_effect": (
                    "changed" if before.owner_role == "role-b" and after.owner_role == "role-a"
                    else "unchanged" if before.owner_role == after.owner_role == "role-b"
                    else "unknown"
                )})

            second_context = self._ready_generation(after_reset=True)
            contexts.append(second_context)
            second_name = (
                "b05-own-read-second" if operation == "own_read" else
                "b05-basket-write-v3-second" if registration.check_id == "juice-basket-own-write-v3" else
                "b05-basket-write-second" if registration.check_id == "juice-basket-own-write-v2" else
                "b05-ownership-transfer-second" if operation == "ownership_transfer" else
                "b05-own-write-second"
            )
            if operation == "ownership_transfer":
                ownership_proofs.append(self.lab.observe_address_owner(phase="before"))
            second = self.lab.b05_step(second_name)
            merge_controls(second)
            basket_snapshots.extend(second.basket_snapshots)
            offset = len(exchanges)
            exchanges.extend(item.model_copy(update={"index": item.index + offset})
                             for item in second.exchanges)
            generations.append(self._generation(
                second_context, candidate_owned=bool(second.controls.get("ownership")), reset_ok=True,
                operation=operation, check_id=registration.check_id,
                session_bindings={"role_a": second.role_a_session_binding_sha256,
                                  "role_b": second.role_b_session_binding_sha256},
            ))

            if operation == "ownership_transfer":
                ownership_proofs.append(self.lab.observe_address_owner(phase="after"))
                probe_index = next(index for index, item in enumerate(second.exchanges)
                                   if item.exchange_id == "probe-t-transfer-t2")
                probe = second.exchanges[probe_index]
                before, after = ownership_proofs[-2:]
                second.exchanges[probe_index] = probe.model_copy(update={"mutation_effect": (
                    "changed" if before.owner_role == "role-b" and after.owner_role == "role-a"
                    else "unchanged" if before.owner_role == after.owner_role == "role-b"
                    else "unknown"
                )})

            if registration.check_id in {"juice-basket-own-write-v2", "juice-basket-own-write-v3",
                                         "juice-address-own-write-v1"}:
                third_context = self._ready_generation(after_reset=True)
                contexts.append(third_context)
                cleanup_operation = ("b05-basket-write-v3-cleanup"
                                     if registration.check_id == "juice-basket-own-write-v3" else
                                     "b05-basket-write-cleanup"
                                     if registration.check_id == "juice-basket-own-write-v2"
                                     else "b05-own-write-cleanup")
                cleanup = self.lab.b05_step(cleanup_operation)
                merge_controls(cleanup)
                basket_snapshots.extend(cleanup.basket_snapshots)
                offset = len(exchanges)
                exchanges.extend(item.model_copy(update={"index": item.index + offset})
                                 for item in cleanup.exchanges)
                generations.append(self._generation(
                    third_context, candidate_owned=bool(cleanup.controls.get("ownership")), reset_ok=True,
                    operation=operation, check_id=registration.check_id,
                    session_bindings={"role_a": cleanup.role_a_session_binding_sha256,
                                      "role_b": cleanup.role_b_session_binding_sha256},
                ))
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
            # Persist a stable diagnostic code; raw exception text may contain target data.
            technical_error = "docker_runtime_or_fixture_failure"
            reset_complete = False
        finally:
            cleanup_complete = self.lab.close()
            source_integrity = (self.initial_snapshot is not None
                                and self.lab._snapshot() == self.initial_snapshot)

        if not cleanup_complete:
            technical_error = technical_error or "cleanup_unverified"
        if not source_integrity:
            technical_error = technical_error or "source_integrity_failed"

        for index, exchange in enumerate(exchanges, start=1):
            if exchange.index != index:
                exchanges[index - 1] = exchange.model_copy(update={"index": index})
        return AccessCheckTrace(
            check_id=registration.check_id,
            binding_id=binding_id(action),
            source_snapshot_digest=action.verification_binding.source_snapshot,
            target=action.target,
            environment=action.environment,
            operation=registration.operation,
            endpoint_id=registration.endpoint_id,
            method=registration.method,
            object_ref=registration.object_ref,
            mutation_field=registration.mutation_field,
            mutation_value_sha256=digest(registration.mutation_value) if registration.mutation_value else None,
            controls=controls,
            generations=generations,
            exchanges=exchanges,
            exchange_count=len(exchanges),
            request_budget=registration.request_budget,
            reset_complete=reset_complete,
            cleanup_complete=cleanup_complete,
            integrity_verified=bool(source_integrity),
            allowed_technical_fields=(
                ["updatedAt"] if registration.check_id in {
                    "juice-basket-own-write-v2", "juice-basket-own-write-v3",
                } else []
            ),
            technical_error=technical_error,
            ownership_proofs=ownership_proofs,
            basket_snapshots=basket_snapshots,
        )
