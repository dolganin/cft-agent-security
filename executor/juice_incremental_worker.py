"""Fixed, bounded Juice Shop role/Product proof protocols, Docker-only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

BASE = "http://juice:3000"
CONFIG = Path("/input/profile.json")
ROLE_PROTOCOL = "juice-role-registration-v1"
PRODUCT_PROTOCOL = "juice-anonymous-product-put-v1"
TARGET_COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
TARGET_IMAGE = "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
WORKER_IMAGE = "python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"
SOURCE_SETS = {
    ROLE_PROTOCOL: {"server.ts", "routes/login.ts", "routes/currentUser.ts",
                    "models/user.ts", "lib/insecurity.ts"},
    PRODUCT_PROTOCOL: {"server.ts", "models/product.ts", "models/user.ts", "lib/insecurity.ts"},
}
ROLES = {"customer", "deluxe", "accounting", "admin"}
PRODUCT_FIELDS = ("name", "description", "price", "deluxePrice", "image")


class ProofFailure(ValueError):
    """Constant worker diagnostic; never includes target response or credentials."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def _digest(value) -> str:
    encoded = (value if isinstance(value, bytes) else
               json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return hashlib.sha256(encoded).hexdigest()


class FixedHttpClient:
    """Only the fixed internal service is reachable from the Docker-only worker."""

    def __init__(self, *, max_requests: int = 24, timeout: float = 3.0):
        self.max_requests = max_requests
        self.timeout = timeout
        self.deadline = time.monotonic() + 75.0
        self.requests = 0
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method: str, path: str, data: dict | None = None,
                token: str | None = None) -> tuple[int, object | None]:
        if (self.requests >= self.max_requests or time.monotonic() >= self.deadline
                or not path.startswith("/") or ".." in path.split("/")
                or "\\" in path or path.startswith("//")):
            raise ProofFailure("request_scope_or_budget_invalid")
        self.requests += 1
        headers = {"Accept": "application/json", "User-Agent": "cft-juice-mini-proof/1"}
        body = None
        if data is not None:
            body = json.dumps(data, separators=(",", ":")).encode("utf-8")
            if len(body) > 2048:
                raise ProofFailure("request_body_limit")
            headers["Content-Type"] = "application/json"
        if token is not None:
            if not token or len(token) > 4096:
                raise ProofFailure("session_token_invalid")
            headers.update(Authorization="Bearer " + token, Cookie="token=" + token)
        request = Request(BASE + path, data=body, headers=headers, method=method)
        try:
            try:
                response = self.opener.open(
                    request,
                    timeout=min(self.timeout, max(0.05, self.deadline - time.monotonic())),
                )
            except HTTPError as error:
                response = error
                status = error.code
                if status >= 400:
                    error.close()
                    return status, None
            with response:
                status = response.status
                if 300 <= status < 400:
                    raise ProofFailure("redirect_not_allowed")
                if status == 204:
                    return status, None
                raw = response.read(65_537)
                if len(raw) > 65_536:
                    raise ProofFailure("response_size_limit")
                if "json" not in response.headers.get("Content-Type", "").lower():
                    raise ProofFailure("non_json_response")
                try:
                    payload = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise ProofFailure("invalid_json_response") from None
                return status, payload
        except (OSError, URLError, TimeoutError):
            raise ProofFailure("target_unavailable") from None


def _user_identity(payload: object) -> tuple[bool, str | None, str | None, str | None]:
    if not isinstance(payload, dict) or not isinstance(payload.get("user"), dict):
        return False, None, None, None
    user = payload["user"]
    user_id, email, role = user.get("id"), user.get("email"), user.get("role")
    if (type(user_id) is not int or user_id <= 0 or not isinstance(email, str) or not email
            or role not in ROLES):
        return False, None, None, None
    return True, _digest([user_id, email]), role, email


def _register_login_identity(client: FixedHttpClient, *, generation: str,
                              label: str, requested_role: str | None):
    email = f"cft-{label}-{generation}-{secrets.token_hex(5)}@example.invalid"
    password = secrets.token_urlsafe(24)
    registration = {"email": email, "password": password, "passwordRepeat": password}
    if requested_role is not None:
        registration["role"] = requested_role
    register_status, _ = client.request("POST", "/api/Users", registration)
    login_status, login_payload = client.request(
        "POST", "/rest/user/login", {"email": email, "password": password},
    )
    token = None
    if login_status == 200 and isinstance(login_payload, dict):
        authentication = login_payload.get("authentication")
        if (isinstance(authentication, dict) and authentication.get("umail") == email
                and isinstance(authentication.get("token"), str)
                and authentication["token"]):
            token = authentication["token"]
    identity_status, identity_payload = client.request(
        "GET", "/rest/user/whoami?fields=id,email,role", token=token,
    )
    identity_present, identity_sha, role, observed_email = _user_identity(identity_payload)
    identity_present = identity_present and identity_status == 200 and observed_email == email
    if not identity_present:
        identity_sha = None
        role = None
    return {
        "register_status": register_status,
        "login_status": login_status,
        "identity_status": identity_status,
        "identity_present": identity_present,
        "identity_sha256": identity_sha,
        "role": role,
        "_token": token,
    }


def run_role_registration(client: FixedHttpClient, config: dict) -> dict:
    generation = config["generation"]
    baseline = _register_login_identity(
        client, generation=generation, label="baseline", requested_role=None,
    )
    candidate = _register_login_identity(
        client, generation=generation, label="candidate", requested_role="admin",
    )
    trial = {
        "schema_version": "juice.role_registration.trial.v1",
        "generation_sha256": _digest(generation),
        "source_snapshot_sha256": config["source_snapshot_sha256"],
        "profile_sha256": config["profile_sha256"],
        "worker_sha256": config["worker_sha256"],
        "baseline_registration_status": baseline["register_status"],
        "baseline_login_status": baseline["login_status"],
        "baseline_identity_status": baseline["identity_status"],
        "baseline_identity_sha256": baseline["identity_sha256"],
        "baseline_role": baseline["role"],
        "candidate_registration_status": candidate["register_status"],
        "candidate_login_status": candidate["login_status"],
        "candidate_identity_status": candidate["identity_status"],
        "candidate_identity_present": candidate["identity_present"],
        "candidate_identity_sha256": candidate["identity_sha256"],
        "candidate_role": candidate["role"],
        "identities_distinct": (
            baseline["identity_sha256"] is not None
            and (candidate["identity_sha256"] is None
                 or baseline["identity_sha256"] != candidate["identity_sha256"])
        ),
        "request_order": [
            "baseline-register", "baseline-login", "baseline-identity",
            "candidate-register", "candidate-login", "candidate-identity",
        ],
        "http_exchanges": client.requests,
    }
    return {"status": "completed", "trial": trial}


def _response_data(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        raise ProofFailure("resource_response_shape_invalid")
    return payload["data"]


def _server_id(value: object) -> int:
    if type(value) is not int or not 0 < value < 1_000_000_000:
        raise ProofFailure("server_identifier_invalid")
    return value


def _product(payload: object) -> dict:
    product = _response_data(payload)
    if type(product.get("id")) is not int or not all(field in product for field in PRODUCT_FIELDS):
        raise ProofFailure("product_readback_shape_invalid")
    return product


def _description_digest(product: dict) -> str:
    return _digest(product.get("description"))


def _untouched_digest(product: dict) -> str:
    return _digest({field: product.get(field) for field in ("name", "price", "deluxePrice", "image")})


def _new_product(client: FixedHttpClient, *, token: str, generation: str,
                 label: str) -> tuple[int, int, dict]:
    name = f"CFT-J01-{label}-{generation}"
    description = f"CFT-J01-baseline-{label}-{generation}"
    status, payload = client.request("POST", "/api/Products", {
        "name": name,
        "description": description,
        "price": 1.25,
        "deluxePrice": 1.0,
        "image": "/assets/public/images/products/1.jpg",
    }, token)
    if status not in {200, 201}:
        return status, 0, {}
    product_id = _server_id(_response_data(payload).get("id"))
    read_status, read_payload = client.request("GET", f"/api/Products/{product_id}")
    if read_status != 200:
        raise ProofFailure("product_initial_readback_failed")
    product = _product(read_payload)
    if product["id"] != product_id or product.get("name") != name:
        raise ProofFailure("product_fixture_identity_mismatch")
    return status, product_id, product


def _visible_product_names(payload: object) -> set[str]:
    if not isinstance(payload, dict):
        raise ProofFailure("product_list_shape_invalid")
    data = payload.get("data")
    if not isinstance(data, list) or len(data) > 2_000:
        raise ProofFailure("product_list_shape_invalid")
    names = set()
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.add(item["name"])
    return names


def run_product_put(client: FixedHttpClient, config: dict) -> dict:
    generation = config["generation"]
    user = _register_login_identity(
        client, generation=generation, label="product", requested_role=None,
    )
    if not user["identity_present"] or user["role"] != "customer":
        raise ProofFailure("synthetic_customer_identity_not_ready")

    # Recover the private token only in worker memory: repeat registration/login with
    # the same account is deliberately avoided. The account helper therefore returns
    # its token internally in a local-only field removed before trial serialization.
    token = user.pop("_token", None)
    if not token:
        raise ProofFailure("synthetic_customer_session_missing")

    positive_create_status, positive_id, positive_before = _new_product(
        client, token=token, generation=generation, label="positive",
    )
    if positive_create_status not in {200, 201} or not positive_id:
        raise ProofFailure("authenticated_product_create_failed")
    positive_before_hash = _description_digest(positive_before)
    positive_untouched_before = _untouched_digest(positive_before)
    positive_marker = f"CFT-J01-authenticated-{generation}"
    positive_put_status, _ = client.request(
        "PUT", f"/api/Products/{positive_id}", {"description": positive_marker}, token,
    )
    positive_read_status, positive_read_payload = client.request(
        "GET", f"/api/Products/{positive_id}",
    )
    positive_after = _product(positive_read_payload) if positive_read_status == 200 else {}
    positive_persisted = (
        bool(positive_after)
        and positive_before_hash != _description_digest(positive_after)
        and positive_after.get("description") == positive_marker
    )
    positive_untouched_stable = (
        bool(positive_after)
        and positive_untouched_before == _untouched_digest(positive_after)
    )

    candidate_create_status, candidate_id, candidate_before = _new_product(
        client, token=token, generation=generation, label="candidate",
    )
    if candidate_create_status not in {200, 201} or not candidate_id:
        raise ProofFailure("candidate_product_create_failed")
    candidate_before_hash = _description_digest(candidate_before)
    candidate_untouched_before = _untouched_digest(candidate_before)
    candidate_marker = f"CFT-J01-anonymous-{generation}"
    anonymous_put_status, _ = client.request(
        "PUT", f"/api/Products/{candidate_id}", {"description": candidate_marker},
    )
    candidate_read_status, candidate_read_payload = client.request(
        "GET", f"/api/Products/{candidate_id}",
    )
    candidate_after = _product(candidate_read_payload) if candidate_read_status == 200 else {}
    candidate_after_hash = _description_digest(candidate_after) if candidate_after else None
    anonymous_persisted = (
        bool(candidate_after)
        and candidate_before_hash != candidate_after_hash
        and candidate_after.get("description") == candidate_marker
    )
    candidate_untouched_stable = (
        bool(candidate_after)
        and candidate_untouched_before == _untouched_digest(candidate_after)
    )

    control_name = f"CFT-J01-anonymous-create-control-{generation}"
    create_control_status, _ = client.request("POST", "/api/Products", {
        "name": control_name, "description": "CFT-J01-control-description",
        "price": 1.25, "deluxePrice": 1.0,
        "image": "/assets/public/images/products/1.jpg",
    })
    query = urlencode({"filter": json.dumps({"where": {"name": control_name}})})
    control_read_status, control_read_payload = client.request(
        "GET", f"/api/Products?{query}",
    )
    control_absent = (
        control_read_status == 200
        and control_name not in _visible_product_names(control_read_payload)
    )

    trial = {
        "schema_version": "juice.product_put.trial.v1",
        "generation_sha256": _digest(generation),
        "source_snapshot_sha256": config["source_snapshot_sha256"],
        "profile_sha256": config["profile_sha256"],
        "worker_sha256": config["worker_sha256"],
        "account_registration_status": user["register_status"],
        "account_login_status": user["login_status"],
        "identity_status": user["identity_status"],
        "identity_sha256": user["identity_sha256"],
        "identity_role": user["role"],
        "positive_create_status": positive_create_status,
        "positive_product_id_sha256": _digest(str(positive_id)),
        "positive_authenticated_put_status": positive_put_status,
        "positive_readback_status": positive_read_status,
        "positive_mutation_persisted": positive_persisted,
        "positive_untouched_fields_stable": positive_untouched_stable,
        "candidate_create_status": candidate_create_status,
        "candidate_product_id_sha256": _digest(str(candidate_id)),
        "candidate_before_sha256": candidate_before_hash,
        "anonymous_put_status": anonymous_put_status,
        "candidate_readback_status": candidate_read_status,
        "candidate_after_sha256": candidate_after_hash,
        "anonymous_mutation_persisted": anonymous_persisted,
        "candidate_untouched_fields_stable": candidate_untouched_stable,
        "anonymous_create_control_status": create_control_status,
        "anonymous_create_control_readback_status": control_read_status,
        "anonymous_create_control_absent": control_absent,
        "request_order": [
            "register", "login", "identity", "positive-create", "positive-read-before",
            "positive-authenticated-put", "positive-read-after", "candidate-create",
            "candidate-read-before", "candidate-anonymous-put", "candidate-read-after",
            "anonymous-create-control", "anonymous-create-control-readback",
        ],
        "http_exchanges": client.requests,
    }
    return {"status": "completed", "trial": trial}


def run(config: dict) -> dict:
    protocol = config.get("protocol_id")
    if protocol not in {ROLE_PROTOCOL, PRODUCT_PROTOCOL}:
        raise ProofFailure("protocol_not_registered")
    required = {
        "schema_version", "protocol_id", "generation", "source_snapshot_sha256",
        "source_files", "target_commit", "target_image", "worker_sha256", "worker_image",
        "profile_sha256",
    }
    profile = {key: value for key, value in config.items() if key != "profile_sha256"}
    source_files = config.get("source_files")
    if (set(config) != required
            or config.get("schema_version") != "juice.incremental.proof-profile.v1"
            or not isinstance(config.get("generation"), str)
            or re.fullmatch(r"[a-f0-9]{16}", config["generation"]) is None
            or not isinstance(source_files, dict)
            or set(source_files) != SOURCE_SETS[protocol]
            or any(not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None
                   for value in source_files.values())
            or config.get("source_snapshot_sha256") != _digest(source_files)
            or config.get("target_commit") != TARGET_COMMIT
            or config.get("target_image") != TARGET_IMAGE
            or config.get("worker_image") != WORKER_IMAGE
            or config.get("worker_sha256") != _digest(Path(__file__).read_bytes())
            or config.get("profile_sha256") != _digest(profile)):
        raise ProofFailure("proof_profile_binding_invalid")
    client = FixedHttpClient(max_requests=24)
    if protocol == ROLE_PROTOCOL:
        return run_role_registration(client, config)
    return run_product_put(client, config)


def main() -> int:
    if os.getenv("CFT_JUICE_MINI_CONTAINER") != "1" or not Path("/.dockerenv").is_file():
        print(json.dumps({"status": "failed", "reason": "docker_only"}, separators=(",", ":")))
        return 1
    try:
        result = run(json.loads(CONFIG.read_text(encoding="utf-8")))
    except (ProofFailure, OSError, ValueError, TypeError, KeyError, AttributeError):
        result = {"status": "failed", "reason": "fixed_protocol_failure"}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
