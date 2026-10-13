"""Public B04 fixture contracts. Credentials never belong in these schemas."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

RoleId = Literal["role-a", "role-b"]
ObjectId = Literal["basket-a", "basket-b", "address-a", "address-b", "negative-control-b"]


class FixturePermission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    role_id: RoleId
    object_id: ObjectId
    read: bool
    update: bool


class FixtureObjectSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: ObjectId
    kind: Literal["basket", "address"]
    owner_role_id: RoleId


def fixed_objects():
    return [FixtureObjectSpec(id=name, kind="basket" if name.startswith("basket-") else "address",
                              owner_role_id="role-a" if name.endswith("-a") else "role-b")
            for name in ("basket-a", "basket-b", "address-a", "address-b", "negative-control-b")]


class AccessFixtureProfile(BaseModel):
    """Fixed operator adapter; no URLs, credentials, argv or model write payloads."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: Literal["juice-two-user-v1"] = "juice-two-user-v1"
    adapter: Literal["juice_access_v1"] = "juice_access_v1"
    reset_adapter: Literal["destroy_and_recreate_lab"] = "destroy_and_recreate_lab"
    roles: list[RoleId] = Field(default_factory=lambda: ["role-a", "role-b"], min_length=2, max_length=2)
    objects: list[FixtureObjectSpec] = Field(default_factory=fixed_objects, min_length=5, max_length=5)
    permissions: list[FixturePermission] = Field(min_length=10, max_length=10)
    prepare_http_budget: int = Field(default=64, ge=40, le=64)
    control_http_budget: int = Field(default=32, ge=25, le=32)
    request_timeout_seconds: int = Field(default=3, ge=1, le=5)
    wall_time_seconds: int = Field(default=120, ge=30, le=180)

    @model_validator(mode="after")
    def complete_owner_matrix(self):
        if set(self.roles) != {"role-a", "role-b"}:
            raise ValueError("Two distinct fixture roles are required")
        if sorted((o.id, o.kind, o.owner_role_id) for o in self.objects) != sorted(
            (o.id, o.kind, o.owner_role_id) for o in fixed_objects()
        ):
            raise ValueError("The fixed adapter requires five explicitly owned fixture objects")
        expected = {(role, obj) for role in self.roles for obj in (
            "basket-a", "basket-b", "address-a", "address-b", "negative-control-b")}
        if {(p.role_id, p.object_id) for p in self.permissions} != expected:
            raise ValueError("Fixture permission matrix must contain every actor/object exactly once")
        for permission in self.permissions:
            owner = "role-a" if permission.object_id.endswith("-a") else "role-b"
            if permission.read != (permission.role_id == owner) or permission.update != permission.read:
                raise ValueError("juice_access_v1 requires explicit owner-only permissions")
        return self


class FixtureRole(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: RoleId
    server_user_id: int = Field(gt=0)
    identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity_verified: bool
    server_role: Literal["customer"] | None = None


class FixtureObject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: ObjectId
    kind: Literal["basket", "address"]
    owner_role_id: RoleId
    server_object_id: int = Field(gt=0)
    server_owner_id: int = Field(gt=0)
    baseline_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    ownership_verified: bool


class FixtureControl(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    passed: bool
    reason: str


class FixtureObservation(BaseModel):
    """Redacted server facts, not secrets or an exploit verdict."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["identity", "owner-read", "negative-read", "anonymous", "health"]
    exchange: int = Field(gt=0, le=64)
    http_status: int = Field(ge=100, le=599)
    role_id: RoleId | None = None
    object_id: ObjectId | None = None
    registered_user_id: int | None = Field(default=None, gt=0)
    served_user_id: int | None = Field(default=None, gt=0)
    registered_identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    served_identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    served_owner_id: int | None = Field(default=None, gt=0)
    object_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    passed: bool


class AccessFixtureContext(BaseModel):
    """Safe handoff to B05: registry IDs and evidence facts, never a session token."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["access.fixture.b04.v1"] = "access.fixture.b04.v1"
    fixture_id: str
    generation: str
    profile_id: Literal["juice-two-user-v1"] = "juice-two-user-v1"
    target_id: Literal["juice-access-fixture"] = "juice-access-fixture"
    service_id: Literal["juice"] = "juice"
    source_snapshot: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    permissions: list[FixturePermission] = Field(default_factory=list)
    status: Literal["ready", "inconclusive"]
    roles: list[FixtureRole] = Field(default_factory=list)
    objects: list[FixtureObject] = Field(default_factory=list)
    controls: list[FixtureControl] = Field(default_factory=list)
    observations: list[FixtureObservation] = Field(default_factory=list, max_length=64)
    http_exchanges: int = Field(ge=0)
    reason: str

    @model_validator(mode="after")
    def ready_requires_identity_and_ownership(self):
        if self.status != "ready":
            return self
        AccessFixtureProfile(permissions=self.permissions)
        roles = {r.id: r for r in self.roles}
        objects = {o.id: o for o in self.objects}
        if (len(self.roles) != 2 or set(roles) != {"role-a", "role-b"}
                or len({r.server_user_id for r in self.roles}) != 2
                or not all(r.identity_verified and r.server_role == "customer" for r in self.roles)):
            raise ValueError("Ready fixture requires two distinct proved server identities")
        if (len(self.objects) != 5 or set(objects) != {
            "basket-a", "basket-b", "address-a", "address-b", "negative-control-b"
        } or not all(o.ownership_verified and o.server_owner_id == roles[o.owner_role_id].server_user_id
                     and o.owner_role_id == ("role-a" if o.id.endswith("-a") else "role-b")
                     and o.kind == ("basket" if o.id.startswith("basket-") else "address")
                     for o in self.objects)):
            raise ValueError("Ready fixture requires proved ownership of all registered objects")
        if (len({(o.kind, o.server_object_id) for o in self.objects}) != 5
                or not self.controls or not all(c.passed for c in self.controls)
                or not {"availability", "negative-control", "anonymous-identity"}.issubset(
                    {c.id for c in self.controls})):
            raise ValueError("Ready fixture requires distinct objects and successful independent controls")
        identity_roles = {o.role_id for o in self.observations if o.kind == "identity" and o.passed
                          and o.served_user_id == o.registered_user_id
                          and o.served_identity_sha256 == o.registered_identity_sha256}
        read_objects = {o.object_id for o in self.observations if o.kind == "owner-read" and o.passed}
        if (identity_roles != {"role-a", "role-b"} or read_objects != set(objects)
                or not all(o.passed for o in self.observations)):
            raise ValueError("Ready fixture requires independent identity and owner-read observations")
        by_exchange = {o.exchange: o for o in self.observations}
        if len(by_exchange) != len(self.observations) or max(by_exchange) > self.http_exchanges:
            raise ValueError("Fixture exchange accounting is inconsistent")
        for observation in self.observations:
            if observation.kind == "identity":
                role = roles.get(observation.role_id)
                if (role is None or observation.http_status != 200
                        or observation.registered_user_id != role.server_user_id
                        or observation.served_user_id != role.server_user_id
                        or observation.served_identity_sha256 != role.identity_sha256):
                    raise ValueError("Identity observation differs from registered server identity")
            if observation.kind in {"owner-read", "negative-read"}:
                before = by_exchange.get(observation.exchange - 1)
                after = by_exchange.get(observation.exchange + 1)
                if not all(o and o.kind == "identity" and o.role_id == observation.role_id for o in (before, after)):
                    raise ValueError("Object controls require server identity before and after the action")
            if observation.kind == "owner-read":
                obj = objects.get(observation.object_id)
                if (obj is None or observation.role_id != obj.owner_role_id
                        or observation.http_status != 200 or observation.served_owner_id != obj.server_owner_id
                        or observation.object_sha256 != obj.baseline_sha256):
                    raise ValueError("Object read differs from proved ownership or baseline")
        negative = [o for o in self.observations if o.kind == "negative-read"]
        if (len(negative) != 1 or negative[0].http_status != 400 or negative[0].role_id != "role-a"
                or negative[0].object_id != "negative-control-b"):
            raise ValueError("Distinct negative control observation is required")
        owner_control = [o for o in self.observations if o.kind == "owner-read" and o.object_id == "negative-control-b"]
        if not (any(o.exchange < negative[0].exchange for o in owner_control)
                and any(o.exchange > negative[0].exchange for o in owner_control)):
            raise ValueError("Protected control must be available to its owner before and after denial")
        return self
