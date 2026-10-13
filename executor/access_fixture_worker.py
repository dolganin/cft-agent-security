"""Fixed operator-only B04 bootstrap/control worker, executed inside Docker.

No tool dispatch from model payloads. Session material lives only in container tmpfs.
No credentials, response bodies, passwords, tokens, URLs or arbitrary writes leave
this worker. This is fixture provisioning, not a vulnerability-verdict capability.
"""
import hashlib
import json
import os
import secrets
import signal
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

BASE = "http://juice:3000"
STATE = Path("/state/session.json")
ROLES = ("role-a", "role-b")
OWNERS = {"basket-a": "role-a", "basket-b": "role-b", "address-a": "role-a",
          "address-b": "role-b", "negative-control-b": "role-b"}


class FixtureFailure(ValueError):
    """Only fixed, secret-free diagnostic codes may be exported."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def integer(value):
    if type(value) is not int or not 0 < value < 1_000_000_000:
        raise FixtureFailure("invalid_server_identifier")
    return value


class FixtureClient:
    def __init__(self, config):
        self.config = config
        self.roles = {}
        self.objects = {}
        self.controls = []
        self.observations = []
        self.exchanges = 0
        self.deadline = time.monotonic() + config["profile"]["wall_time_seconds"]
        self.limit = config["profile"]["prepare_http_budget"]
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method, path, data=None, role=None, *, json_response=True):
        if self.exchanges >= self.limit or time.monotonic() >= self.deadline:
            raise FixtureFailure("fixture_budget_exhausted")
        self.exchanges += 1
        headers = {"Accept": "application/json", "User-Agent": "cft-b04-fixture/1"}
        if role:
            token = self.roles[role]["token"]
            headers.update(Authorization="Bearer " + token, Cookie="token=" + token)
        encoded = json.dumps(data).encode() if data is not None else None
        if encoded is not None:
            if len(encoded) > 4096:
                raise FixtureFailure("request_body_limit")
            headers["Content-Type"] = "application/json"
        request = Request(BASE + path, data=encoded, headers=headers, method=method)
        try:
            try:
                response = self.opener.open(request, timeout=min(
                    self.config["profile"]["request_timeout_seconds"], max(0.01, self.deadline - time.monotonic())))
            except HTTPError as error:
                response = error
            with response:
                status = response.status
                raw = response.read(65_537)
                if len(raw) > 65_536:
                    raise FixtureFailure("response_truncated")
                if 300 <= status < 400:
                    raise FixtureFailure("redirect_not_allowed")
                if not json_response:
                    return status, None
                if "json" not in response.headers.get("Content-Type", "").lower():
                    raise FixtureFailure("non_json_response")
                try:
                    payload = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise FixtureFailure("invalid_json_response") from None
                if not isinstance(payload, dict):
                    raise FixtureFailure("invalid_response_shape")
                return status, payload
        except (OSError, URLError, TimeoutError):
            raise FixtureFailure("target_unavailable") from None

    def identity(self, role):
        status, payload = self.request("GET", "/rest/user/whoami?fields=id,email,role", role=role)
        user = payload.get("user")
        expected = self.roles[role]
        valid = (status == 200 and isinstance(user, dict) and type(user.get("id")) is int
                 and user["id"] == expected["user_id"] and user.get("email") == expected["email"]
                 and user.get("role") == "customer")
        observed_id = user.get("id") if isinstance(user, dict) else None
        observed_email = user.get("email") if isinstance(user, dict) else None
        self.observations.append({"kind": "identity", "exchange": self.exchanges, "http_status": status,
                                  "role_id": role, "registered_user_id": expected["user_id"],
                                  "served_user_id": observed_id if type(observed_id) is int and observed_id > 0 else None,
                                  "registered_identity_sha256": digest([expected["user_id"], expected["email"]]),
                                  "served_identity_sha256": (digest([observed_id, observed_email])
                                      if type(observed_id) is int and isinstance(observed_email, str) else None),
                                  "passed": valid})
        if not valid:
            raise FixtureFailure("server_identity_missing_or_changed:" + role)
        self.roles[role]["verified_role"] = "customer"
        return {"id": role, "server_user_id": user["id"],
                "identity_sha256": digest([user["id"], user["email"]]), "identity_verified": True}

    def object_path(self, object_id):
        obj = self.objects[object_id]
        prefix = "/rest/basket/" if obj["kind"] == "basket" else "/api/Addresss/"
        return prefix + str(integer(obj["server_object_id"]))

    def normalized_object(self, object_id, data):
        obj = self.objects[object_id]
        owner = self.roles[OWNERS[object_id]]["user_id"]
        if (not isinstance(data, dict) or integer(data.get("id")) != obj["server_object_id"]
                or integer(data.get("UserId")) != owner):
            raise FixtureFailure("object_owner_missing_or_changed:" + object_id)
        if obj["kind"] == "address":
            marker = "B04-private-" + object_id
            if data.get("fullName") != marker or data.get("streetAddress") != marker:
                raise FixtureFailure("private_marker_missing:" + object_id)
            return {"owner": OWNERS[object_id], "kind": "address", "marker": marker,
                    "city": data.get("city"), "zipCode": data.get("zipCode"), "country": data.get("country")}
        products = data.get("Products")
        quantity = 1 if object_id == "basket-a" else 2
        if (not isinstance(products, list) or len(products) != 1
                or products[0].get("id") != 1 or not isinstance(products[0].get("BasketItem"), dict)
                or products[0]["BasketItem"].get("quantity") != quantity
                or products[0]["BasketItem"].get("BasketId") != obj["server_object_id"]):
            raise FixtureFailure("basket_marker_missing:" + object_id)
        return {"owner": OWNERS[object_id], "kind": "basket", "product_id": 1, "quantity": quantity}

    def owner_read(self, object_id):
        role = OWNERS[object_id]
        self.identity(role)
        status, payload = self.request("GET", self.object_path(object_id), role=role)
        data = payload.get("data")
        served_owner = data.get("UserId") if isinstance(data, dict) else None
        observation = {"kind": "owner-read", "exchange": self.exchanges, "http_status": status,
                       "role_id": role, "object_id": object_id, "served_owner_id":
                       served_owner if type(served_owner) is int and served_owner > 0 else None,
                       "passed": False}
        self.observations.append(observation)
        if status != 200:
            raise FixtureFailure("owner_availability_failed:" + object_id)
        normalized = self.normalized_object(object_id, payload.get("data"))
        self.identity(role)
        actual = digest(normalized)
        expected = self.objects[object_id].get("baseline_sha256")
        if expected is not None and actual != expected:
            raise FixtureFailure("object_baseline_changed:" + object_id)
        self.objects[object_id].update(baseline_sha256=actual,
                                     server_owner_id=self.roles[role]["user_id"], ownership_verified=True)
        observation.update(object_sha256=actual, passed=True)

    def verify_controls(self):
        status, _ = self.request("GET", "/", json_response=False)
        self.observations.append({"kind": "health", "exchange": self.exchanges,
                                  "http_status": status, "passed": status == 200})
        if status != 200:
            raise FixtureFailure("target_health_failed")
        self.controls.append({"id": "availability", "passed": True, "reason": "Target responds to fixed health request"})
        for role in ROLES:
            self.identity(role)
        for object_id in OWNERS:
            self.owner_read(object_id)
        # Distinct protected object: not the candidate basket-B access in B05.
        self.identity("role-a")
        status, payload = self.request("GET", self.object_path("negative-control-b"), role="role-a")
        negative_exchange = self.exchanges
        self.identity("role-a")
        passed = status == 400 and payload.get("status") == "error" and payload.get("data") == "Malicious activity detected."
        self.observations.append({"kind": "negative-read", "exchange": negative_exchange,
                                  "http_status": status, "role_id": "role-a", "object_id": "negative-control-b",
                                  "passed": passed})
        if not passed:
            raise FixtureFailure("negative_control_failed")
        self.owner_read("negative-control-b")
        self.controls.append({"id": "negative-control", "passed": True,
                              "reason": "A-as-A denied a separate B-owned address, with owner availability proved"})
        status, payload = self.request("GET", "/rest/user/whoami")
        passed = status == 200 and isinstance(payload.get("user"), dict) and payload["user"].get("id") is None
        self.observations.append({"kind": "anonymous", "exchange": self.exchanges,
                                  "http_status": status, "passed": passed})
        if not passed:
            raise FixtureFailure("anonymous_identity_control_failed")
        self.controls.append({"id": "anonymous-identity", "passed": True,
                              "reason": "Anonymous HTTP 200 contains no server identity and is not authenticated"})

    def prepare(self):
        for role in ROLES:
            email = "b04-" + role + "-" + self.config["generation"] + "@invalid.example"
            password = secrets.token_urlsafe(32)
            status, registered = self.request("POST", "/api/Users", {
                "email": email, "password": password, "passwordRepeat": password,
            })
            if status not in {200, 201} or not isinstance(registered.get("data"), dict):
                raise FixtureFailure("user_registration_failed")
            user_id = integer(registered["data"].get("id"))
            if user_id in {r["user_id"] for r in self.roles.values()}:
                raise FixtureFailure("fixture_roles_not_distinct")
            status, logged = self.request("POST", "/rest/user/login", {"email": email, "password": password})
            auth = logged.get("authentication")
            if (status != 200 or not isinstance(auth, dict) or auth.get("umail") != email
                    or not isinstance(auth.get("token"), str) or not auth["token"]):
                raise FixtureFailure("user_login_failed")
            self.roles[role] = {"user_id": user_id, "email": email, "token": auth["token"]}
            self.identity(role)
            object_id = "basket-a" if role == "role-a" else "basket-b"
            basket_id = integer(auth.get("bid"))
            self.objects[object_id] = {"id": object_id, "kind": "basket", "owner_role_id": role,
                                       "server_object_id": basket_id}
            status, _ = self.request("POST", "/api/BasketItems", {
                "BasketId": basket_id, "ProductId": 1, "quantity": 1 if role == "role-a" else 2,
            }, role=role)
            if status not in {200, 201}:
                raise FixtureFailure("basket_item_creation_failed")
        for object_id in ("address-a", "address-b", "negative-control-b"):
            role, marker = OWNERS[object_id], "B04-private-" + object_id
            self.identity(role)
            status, payload = self.request("POST", "/api/Addresss", {
                "fullName": marker, "streetAddress": marker, "mobileNum": 10000000,
                "zipCode": "10000", "city": "Fixture", "state": "Fixture", "country": "Fixture",
            }, role=role)
            if status not in {200, 201} or not isinstance(payload.get("data"), dict):
                raise FixtureFailure("address_creation_failed")
            self.objects[object_id] = {"id": object_id, "kind": "address", "owner_role_id": role,
                                       "server_object_id": integer(payload["data"].get("id"))}
        self.verify_controls()
        STATE.write_text(json.dumps({"roles": self.roles, "objects": self.objects,
                                     "generation": self.config["generation"]}), encoding="utf-8")
        STATE.chmod(0o600)

    def public(self, status, reason):
        roles = [{"id": role, "server_user_id": value["user_id"],
                  "identity_sha256": digest([value["user_id"], value["email"]]),
                  "identity_verified": status == "ready", "server_role": value.get("verified_role")}
                 for role, value in self.roles.items()]
        objects = [dict(obj, ownership_verified=status == "ready" and obj.get("ownership_verified", False))
                   for obj in self.objects.values() if "baseline_sha256" in obj]
        return {"schema_version": "access.fixture.b04.v1", "fixture_id": self.config["fixture_id"],
                "generation": self.config["generation"], "profile_id": self.config["profile"]["id"],
                "source_snapshot": self.config["source_snapshot"],
                "profile_sha256": digest(self.config["profile"]),
                "permissions": self.config["profile"]["permissions"],
                "status": status, "roles": roles, "objects": objects, "controls": self.controls,
                "observations": sorted(self.observations, key=lambda o: o["exchange"]),
                "http_exchanges": self.exchanges, "reason": reason}


def execute(config, operation):
    client = FixtureClient(config)
    try:
        if operation == "prepare":
            if STATE.exists():
                raise FixtureFailure("fixture_already_prepared")
            client.prepare()
        elif operation in {"control", "lost-session", "changed-identity"}:
            saved = json.loads(STATE.read_text())
            if saved["generation"] != config["generation"]:
                raise FixtureFailure("stale_fixture_generation")
            client.roles, client.objects = saved["roles"], saved["objects"]
            client.limit = config["profile"]["control_http_budget"]
            if operation == "lost-session":
                client.roles["role-a"]["token"] = "invalid-fixture-session"
            if operation == "changed-identity":
                client.roles["role-a"]["token"] = client.roles["role-b"]["token"]
            client.verify_controls()
        else:
            raise FixtureFailure("unknown_operator_operation")
        return client.public("ready", "Independent identity, owner and availability controls passed")
    except FixtureFailure as error:
        client.controls.append({"id": "failure", "passed": False, "reason": str(error)})
        return client.public("inconclusive", str(error))
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        client.controls.append({"id": "failure", "passed": False, "reason": "fixture_technical_error"})
        return client.public("inconclusive", "fixture_technical_error")


def main():
    if os.getenv("CFT_B04_CONTAINER") != "1" or not Path("/.dockerenv").is_file():
        raise RuntimeError("B04 worker is Docker-only")
    config = json.loads(Path("/input/profile.json").read_text())
    # Linux Docker worker: bound the entire operation, including a slow streamed
    # response whose individual reads could each satisfy a socket timeout.
    def expired(*args):
        raise FixtureFailure("fixture_wall_time_exhausted")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(config["profile"]["wall_time_seconds"])
    try:
        result = execute(config, sys.argv[1] if len(sys.argv) == 2 else "invalid")
    finally:
        signal.alarm(0)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
