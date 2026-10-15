"""Operator registry and B01 binding validation for B05 access checks."""
import json
from dataclasses import dataclass
from hashlib import sha256

from schemas.access_verification import AccessCheckSelection, B05CheckId
from schemas.action import ActionProposal
from schemas.finding import Finding
from schemas.target import TargetProfile
from security.verification_binding import resolve_binding


@dataclass(frozen=True)
class AccessCheckRegistration:
    check_id: B05CheckId
    route_id: str
    check: str
    method: str
    endpoint: str
    endpoint_id: str
    operation: str
    object_ref: str
    mutation_field: str | None
    mutation_value: str | int | None
    request_budget: int


ACCESS_CHECKS: dict[str, AccessCheckRegistration] = {
    "juice-basket-own-read-v1": AccessCheckRegistration(
        check_id="juice-basket-own-read-v1", route_id="juice-basket-own-read",
        check="own_read", method="GET", endpoint="/rest/basket/:id",
        endpoint_id="basket-read", operation="own_read", object_ref="basket-b",
        mutation_field=None, mutation_value=None, request_budget=7,
    ),
    "juice-address-own-write-v1": AccessCheckRegistration(
        check_id="juice-address-own-write-v1", route_id="juice-address-own-write",
        check="own_write", method="PUT", endpoint="/api/Addresss/:id",
        endpoint_id="address-write", operation="own_write", object_ref="write-candidate-b",
        mutation_field="city", mutation_value="CFT-B05-FIXED-CITY-MARKER", request_budget=12,
    ),
    "juice-basket-own-write-v2": AccessCheckRegistration(
        check_id="juice-basket-own-write-v2", route_id="juice-basket-own-write-v2",
        check="own_write", method="PUT", endpoint="/api/BasketItems/:id",
        endpoint_id="basket-write", operation="own_write", object_ref="basket-write-candidate-b",
        mutation_field="quantity", mutation_value=2, request_budget=12,
    ),
    "juice-basket-own-write-v3": AccessCheckRegistration(
        check_id="juice-basket-own-write-v3", route_id="juice-basket-own-write-v2",
        check="own_write", method="PUT", endpoint="/api/BasketItems/:id",
        endpoint_id="basket-write", operation="own_write", object_ref="basket-write-candidate-b",
        mutation_field="quantity", mutation_value=2, request_budget=12,
    ),
    "juice-address-ownership-transfer-v1": AccessCheckRegistration(
        check_id="juice-address-ownership-transfer-v1", route_id="juice-address-ownership-transfer",
        check="ownership_transfer", method="PUT", endpoint="/api/Addresss/:id",
        endpoint_id="address-write", operation="ownership_transfer", object_ref="address-b",
        mutation_field=None, mutation_value=None, request_budget=12,
    ),
    "juice-basket-insert-owner-check-v1": AccessCheckRegistration(
        check_id="juice-basket-insert-owner-check-v1", route_id="juice-basket-insert-owner-check",
        check="own_write", method="POST", endpoint="/api/BasketItems",
        endpoint_id="basket-write", operation="basket_insert", object_ref="basket-b",
        mutation_field="BasketId", mutation_value=None, request_budget=14,
    ),
}


def is_access_check_supported(check_id: str) -> bool:
    """Only checks with a safe target operation are offered to the reasoning model."""
    return check_id == "juice-basket-own-read-v1"


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return sha256(payload.encode("utf-8")).hexdigest()


def registered_check(value: object) -> AccessCheckRegistration:
    selection = AccessCheckSelection.model_validate(value)
    return ACCESS_CHECKS[selection.check_id]


def binding_id(action: ActionProposal) -> str:
    if action.verification_binding is None:
        raise ValueError("B05 requires the canonical B01 binding")
    return canonical_digest(action.verification_binding.model_dump(mode="json"))


def validate_access_action(profile: TargetProfile, action: ActionProposal) -> AccessCheckRegistration:
    """Recompute B01 source/route/snapshot and compare the closed B05 registry."""
    registration = registered_check(action.parameters)
    binding = action.verification_binding
    fixture = profile.access_fixture
    if (fixture is None or action.target != profile.id or profile.id != "juice-access-fixture"
            or profile.environment != "sandbox" or action.environment != "sandbox"
            or action.tool != "verify_access_control" or action.service != "juice"
            or action.endpoint != registration.endpoint or binding is None
            or binding.route_id != registration.route_id or binding.tool != action.tool
            or binding.check != registration.check or binding.method != registration.method
            or binding.endpoint != registration.endpoint or binding.service != "juice"
            or binding.target != profile.id or binding.mode is not None):
        raise ValueError("B05 action differs from its registered target, operation or endpoint")
    if registration.check_id == "juice-address-own-write-v1" and not fixture.b05_write_candidate:
        raise ValueError("B05 write candidate is not enabled in the operator fixture")
    if registration.check_id == "juice-basket-own-write-v2" and not fixture.b05_basket_write_candidate:
        raise ValueError("B05 BasketItem v2 candidate is not enabled in the operator fixture")
    if registration.check_id == "juice-basket-own-write-v3" and not fixture.b05_basket_write_v3_candidate:
        raise ValueError("B05 BasketItem v3 candidate is not enabled in the operator fixture")
    if registration.check_id == "juice-basket-insert-owner-check-v1" and not fixture.b05_basket_insert_candidate:
        raise ValueError("B05 BasketItem insertion candidate is not enabled in the operator fixture")
    if (registration.check_id == "juice-address-ownership-transfer-v1"
            and not fixture.b05_ownership_transfer_candidate):
        raise ValueError("B05 ownership-transfer candidate is not enabled in the operator fixture")
    finding = Finding(
        id=binding.finding_id, source="b05-operator-binding", rule_id=binding.family,
        title="Operator-mapped access-control route", description="B05 source binding",
        file=binding.source_file, line_start=binding.line_start, line_end=binding.line_end,
    )
    resolution = resolve_binding(profile, finding)
    if resolution.status != "bound" or resolution.binding != binding:
        raise ValueError("B01 binding is stale, missing or ambiguous")
    routes = [route for route in profile.verification_routes if route.id == binding.route_id]
    if len(routes) != 1 or routes[0].check != registration.check:
        raise ValueError("B05 route registry does not match the selected check")
    if registration.endpoint not in profile.services["juice"].runtime_endpoints:
        raise ValueError("B05 endpoint is outside the registered target scope")
    if registration.check_id == "juice-address-own-write-v1":
        # A real acceptance run showed that Juice Shop's generic Address PUT
        # rewrites UserId through appendUserId(). A city-only request therefore
        # changes ownership as a side effect. Keep the legacy route unavailable.
        raise ValueError(
            "B05 OWN-WRITE is unsupported for this target: its generic Address PUT "
            "rewrites object ownership, so a field-only mutation cannot be guaranteed"
        )
    return registration
