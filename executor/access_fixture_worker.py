"""Fixed operator-only B04 bootstrap/control worker, executed inside Docker.

No tool dispatch from model payloads. Session material lives only in container tmpfs.
No credentials, response bodies, passwords, tokens, URLs or arbitrary writes leave
this worker. This is fixture provisioning, not a vulnerability-verdict capability.
"""
import hashlib
import hmac
import json
import os
import secrets
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

BASE = "http://juice:3000"
STATE = Path("/state/session.json")
ROLES = ("role-a", "role-b")
OWNERS = {"basket-a": "role-a", "basket-b": "role-b", "address-a": "role-a",
          "address-b": "role-b", "negative-control-b": "role-b"}
B05_OWNERS = {**OWNERS, "write-candidate-b": "role-b"}
B05_WRITE_MARKER = "CFT-B05-FIXED-CITY-MARKER"


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
        self.basket_item_ids = {}
        self.controls = []
        self.observations = []
        self.exchanges = 0
        self.operation_exchanges = 0
        self.deadline = time.monotonic() + config["profile"]["wall_time_seconds"]
        self.opaque_key = None
        self.limit = config["profile"]["prepare_http_budget"]
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method, path, data=None, role=None, *, json_response=True, raw_body=None,
                allow_error_response=False):
        if self.operation_exchanges >= self.limit or time.monotonic() >= self.deadline:
            raise FixtureFailure("fixture_budget_exhausted")
        if data is not None and raw_body is not None:
            raise FixtureFailure("ambiguous_request_body")
        self.exchanges += 1
        self.operation_exchanges += 1
        headers = {"Accept": "application/json", "User-Agent": "cft-b04-fixture/1"}
        if role:
            token = self.roles[role]["token"]
            headers.update(Authorization="Bearer " + token, Cookie="token=" + token)
        if raw_body is not None and not isinstance(raw_body, str):
            raise FixtureFailure("invalid_raw_json_request")
        encoded = raw_body.encode() if raw_body is not None else json.dumps(data).encode() if data is not None else None
        if encoded is not None:
            if len(encoded) > 4096:
                raise FixtureFailure("request_body_limit")
            headers["Content-Type"] = "application/json"
        request = Request(BASE + path, data=encoded, headers=headers, method=method)
        is_http_error = False
        try:
            try:
                response = self.opener.open(request, timeout=min(
                    self.config["profile"]["request_timeout_seconds"], max(0.01, self.deadline - time.monotonic())))
            except HTTPError as error:
                response = error
                is_http_error = True
            with response:
                status = response.status
                if allow_error_response and is_http_error and status >= 400:
                    return status, None
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
        owner = self.roles[B05_OWNERS[object_id]]["user_id"]
        if (not isinstance(data, dict) or integer(data.get("id")) != obj["server_object_id"]
                or integer(data.get("UserId")) != owner):
            raise FixtureFailure("object_owner_missing_or_changed:" + object_id)
        if obj["kind"] == "address":
            marker = ("B05-private-write-candidate" if object_id == "write-candidate-b"
                      else "B04-private-" + object_id)
            if data.get("fullName") != marker or data.get("streetAddress") != marker:
                raise FixtureFailure("private_marker_missing:" + object_id)
            return {"owner": B05_OWNERS[object_id], "kind": "address", "marker": marker,
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
        self.opaque_key = secrets.token_bytes(32)
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
            self.roles[role] = {
                "user_id": user_id, "email": email, "token": auth["token"],
                **({"password_value_sha256": digest(hashlib.md5(password.encode("utf-8")).hexdigest())}
                   if self.config.get("active_check_id") == "juice-user-private-fields-v1" else {}),
                "session_binding_sha256": hmac.new(
                    self.opaque_key, auth["token"].encode("utf-8"), hashlib.sha256,
                ).hexdigest(),
            }
            self.identity(role)
            object_id = "basket-a" if role == "role-a" else "basket-b"
            basket_id = integer(auth.get("bid"))
            self.objects[object_id] = {"id": object_id, "kind": "basket", "owner_role_id": role,
                                       "server_object_id": basket_id}
            status, basket_payload = self.request("POST", "/api/BasketItems", {
                "BasketId": basket_id, "ProductId": 1, "quantity": 1 if role == "role-a" else 2,
            }, role=role)
            if status not in {200, 201}:
                raise FixtureFailure("basket_item_creation_failed")
            object_id = "basket-a" if role == "role-a" else "basket-b"
            basket_data = basket_payload.get("data") if isinstance(basket_payload, dict) else None
            if not isinstance(basket_data, dict):
                raise FixtureFailure("basket_item_id_unavailable")
            self.basket_item_ids[object_id] = integer(basket_data.get("id"))
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
        self._save_state()

    def _save_state(self):
        STATE.write_text(json.dumps({"roles": self.roles, "objects": self.objects,
                                     "opaque_key": self.opaque_key.hex() if self.opaque_key else None,
                                     "basket_item_ids": self.basket_item_ids,
                                     "basket_write_items": getattr(self, "basket_write_items", {}),
                                     "basket_write_baseline": getattr(self, "basket_write_baseline", {}),
                                     "controls": self.controls,
                                     "observations": self.observations,
                                     "exchanges": self.exchanges,
                                     "generation": self.config["generation"]}), encoding="utf-8")
        STATE.chmod(0o600)

    def provision_b05(self):
        """Provision B05-only candidates after the unchanged B04 control suite."""
        if self.config.get("active_check_id") == "juice-address-own-write-v1":
            self._create_b05_write_candidate()
        if self.config.get("active_check_id") in {
            "juice-basket-own-write-v2", "juice-basket-own-write-v3",
            "juice-basket-insert-owner-check-v1",
        }:
            self._create_b05_basket_write_items()
        self._save_state()

    def public(self, status, reason):
        roles = [{"id": role, "server_user_id": value["user_id"],
                  "identity_sha256": digest([value["user_id"], value["email"]]),
                  "identity_verified": status == "ready", "server_role": value.get("verified_role")}
                 for role, value in self.roles.items()]
        objects = [dict(obj, ownership_verified=status == "ready" and obj.get("ownership_verified", False))
                   for name, obj in self.objects.items() if name in OWNERS and "baseline_sha256" in obj]
        return {"schema_version": "access.fixture.b04.v1", "fixture_id": self.config["fixture_id"],
                "generation": self.config["generation"], "profile_id": self.config["profile"]["id"],
                "source_snapshot": self.config["source_snapshot"],
                "profile_sha256": digest(self.config["profile"]),
                "permissions": self.config["profile"]["permissions"],
                "status": status, "roles": roles, "objects": objects, "controls": self.controls,
                "observations": sorted(self.observations, key=lambda o: o["exchange"]),
                "http_exchanges": self.exchanges, "reason": reason}

    def _create_b05_write_candidate(self):
        object_id = "write-candidate-b"
        marker = "B05-private-write-candidate"
        self.identity("role-b")
        status, payload = self.request("POST", "/api/Addresss", {
            "fullName": marker, "streetAddress": marker, "mobileNum": 10000001,
            "zipCode": "10001", "city": "Fixture", "state": "Fixture", "country": "Fixture",
        }, role="role-b")
        if status not in {200, 201} or not isinstance(payload.get("data"), dict):
            raise FixtureFailure("b05_write_fixture_creation_failed")
        obj = {"id": object_id, "kind": "address", "owner_role_id": "role-b",
               "server_object_id": integer(payload["data"].get("id"))}
        self.objects[object_id] = obj
        self.identity("role-b")
        status, response = self.request("GET", self.object_path(object_id), role="role-b")
        data = response.get("data")
        if (status != 200 or not isinstance(data, dict)
                or integer(data.get("UserId")) != self.roles["role-b"]["user_id"]
                or integer(data.get("id")) != obj["server_object_id"]
                or data.get("fullName") != marker or data.get("streetAddress") != marker):
            raise FixtureFailure("b05_write_fixture_owner_proof_failed")
        obj["baseline_sha256"] = digest(self.normalized_object(object_id, data))
        obj["server_owner_id"] = self.roles["role-b"]["user_id"]
        obj["ownership_verified"] = True

    def _create_b05_basket_write_items(self):
        specs = {
            "basket-write-self-a": ("role-a", 2),
            "basket-write-candidate-b": ("role-b", 2),
            "basket-write-control-b": ("role-b", 3),
            "basket-write-negative-b": ("role-b", 4),
        }
        self.basket_write_items = {}
        for item_ref, (role, product_id) in specs.items():
            basket_ref = "basket-a" if role == "role-a" else "basket-b"
            basket_id = self.objects[basket_ref]["server_object_id"]
            self.identity(role)
            status, payload = self.request("POST", "/api/BasketItems", {
                "BasketId": basket_id, "ProductId": product_id, "quantity": 1,
            }, role=role)
            data = payload.get("data") if isinstance(payload, dict) else None
            if status not in {200, 201} or not isinstance(data, dict):
                raise FixtureFailure("basket_write_fixture_creation_failed")
            self.basket_write_items[item_ref] = {
                "id": integer(data.get("id")), "basket_id": basket_id,
                "product_id": product_id, "quantity": 1, "owner_role": role,
            }
        self.basket_write_items["basket-write-default-b"] = {
            "id": self.basket_item_ids["basket-b"],
            "basket_id": self.objects["basket-b"]["server_object_id"],
            "product_id": 1, "quantity": 2, "owner_role": "role-b",
        }
        self.basket_write_baseline = {}
        for role in ROLES:
            basket_ref = "basket-a" if role == "role-a" else "basket-b"
            rows, owner_ok = self._read_basket_rows(basket_ref)
            if not owner_ok:
                raise FixtureFailure("basket_write_owner_baseline_failed")
            self.basket_write_baseline[basket_ref] = rows
        self._save_state()

    def _read_basket_rows(self, basket_ref):
        role = OWNERS[basket_ref]
        status, payload = self.request("GET", self.object_path(basket_ref), role=role)
        data = payload.get("data") if isinstance(payload, dict) else None
        if status != 200 or not isinstance(data, dict):
            return {}, False
        if (integer(data.get("id")) != self.objects[basket_ref]["server_object_id"]
                or integer(data.get("UserId")) != self.roles[role]["user_id"]):
            return {}, False
        products = data.get("Products")
        if not isinstance(products, list):
            return {}, False
        registered = dict(self.basket_write_items) if hasattr(self, "basket_write_items") else {}
        if basket_ref == "basket-a":
            refs = ["basket-write-self-a"]
        else:
            refs = ["basket-write-candidate-b", "basket-write-control-b", "basket-write-negative-b"]
        expected_ids = {self.basket_item_ids[basket_ref], *[registered[ref]["id"] for ref in refs if ref in registered]}
        rows = {}
        for product in products:
            if not isinstance(product, dict) or not isinstance(product.get("BasketItem"), dict):
                return {}, False
            item = product["BasketItem"]
            try:
                item_id = integer(item.get("id"))
                row = {
                    "id": item_id, "BasketId": integer(item.get("BasketId")),
                    "ProductId": integer(item.get("ProductId")),
                    "quantity": integer(item.get("quantity")),
                    "createdAt": item.get("createdAt"), "updatedAt": item.get("updatedAt"),
                }
            except FixtureFailure:
                return {}, False
            if (product.get("id") != row["ProductId"] or row["BasketId"] != data.get("id")
                    or not isinstance(row["createdAt"], str) or not isinstance(row["updatedAt"], str)):
                return {}, False
            rows[str(item_id)] = row
        return rows, {int(key) for key in rows} == expected_ids

    @staticmethod
    def _timestamp(value):
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def _basket_item_exchange(self, exchange_id, role, item_ref, method, quantity=None):
        item = self.basket_write_items[item_ref]
        basket_ref = "basket-a" if role == "role-a" else "basket-b"
        if method == "PUT":
            time.sleep(1.05)
            path = "/api/BasketItems/" + str(item["id"])
            status, payload = self.request("PUT", path, {"quantity": quantity}, role=role)
        else:
            status, payload = self.request("GET", self.object_path(basket_ref), role=role)
        response = payload.get("data") if isinstance(payload, dict) else None
        after_rows = {}
        if method == "GET" and status == 200:
            after_rows, owner_ok = self._read_basket_rows_from_payload(basket_ref, response)
        else:
            owner_ok = False
        row = after_rows.get(str(item["id"])) if after_rows else None
        baseline = self.basket_write_baseline.get(basket_ref, {}).get(str(item["id"]), {})
        changed_fields = sorted(key for key in ("quantity", "updatedAt", "createdAt", "BasketId", "ProductId", "id")
                                if row is not None and key in baseline and row.get(key) != baseline.get(key))
        timestamp_before = self._timestamp(baseline.get("updatedAt"))
        timestamp_after = self._timestamp(row.get("updatedAt")) if row else None
        timestamp_ok = bool(timestamp_before and timestamp_after and timestamp_after > timestamp_before)
        created_ok = bool(row and row.get("createdAt") == baseline.get("createdAt"))
        relations_ok = bool(row and all(row.get(key) == baseline.get(key) for key in ("id", "BasketId", "ProductId")))
        other_items_unchanged = bool(after_rows) and all(
            other_id == str(item["id"]) or other_row == self.basket_write_baseline.get(basket_ref, {}).get(other_id)
            for other_id, other_row in after_rows.items()
        )
        event = {
            "exchange_id": exchange_id, "index": self.exchanges, "role_id": role,
            "object_ref": item_ref, "method": method,
            "endpoint_id": "basket-write" if method == "PUT" else "basket-read",
            "status": status, "value_sha256": digest(row.get("quantity")) if row else None,
            "object_sha256": digest(row) if row else None, "private_marker_match": False,
            "owner_data_present": owner_ok, "mutation_effect": "unknown",
            "independent_readback": method == "GET", "changed_fields": changed_fields,
            "timestamp_update_proven": timestamp_ok if row else None,
            "created_at_unchanged": created_ok if row else None,
            "relationships_unchanged": relations_ok if row else None,
            "other_items_unchanged": other_items_unchanged if row else None,
        }
        if self.config.get("active_check_id") == "juice-basket-own-write-v3":
            event.update(self._bind_v3_exchange(event, item_ref, item))
            phase = {
                "oc-b-readback": "baseline-t1",
                "authn-b-readback": "after-authn",
                "probe-b-t1-readback": "probe-t1-readback",
                "baseline-b-t2": "baseline-t2",
                "probe-b-t2-readback": "probe-t2-readback",
                "cleanup-b-baseline": "cleanup",
            }.get(exchange_id)
            if phase is not None and method == "GET" and status == 200 and isinstance(response, dict):
                snapshot = self._v3_basket_snapshot(phase, exchange_id, response)
                if snapshot is not None:
                    self.basket_snapshots.append(snapshot)
                    if exchange_id in {"oc-b-readback", "baseline-b-t2"}:
                        rows, owner_ok = self._read_basket_rows_from_payload("basket-b", response)
                        if owner_ok:
                            self.basket_write_baseline["basket-b"] = rows
        return event, row, baseline, payload

    def _basket_insert_exchange(self, exchange_id, role, basket_ref, *, request_shape=None,
                                data=None, raw_body=None):
        basket = self.objects[basket_ref]
        basket_id = basket["server_object_id"]
        if data is not None or raw_body is not None:
            status, payload = self.request(
                "POST", "/api/BasketItems", data, role=role, raw_body=raw_body,
                json_response=request_shape != "single-foreign-basket-insert",
            )
            row = payload.get("data") if isinstance(payload, dict) else None
            row_id = row.get("id") if isinstance(row, dict) else None
            valid = (status in {200, 201} and isinstance(row, dict) and type(row_id) is int
                     and row.get("BasketId") == basket_id and row.get("ProductId") == 5
                     and row.get("quantity") == 1)
            item_hash = self._opaque_identity("item", row_id) if valid else None
            effect = "changed" if valid else "unchanged" if status in {400, 401, 403, 404} else "unknown"
            event = {"exchange_id": exchange_id, "index": self.exchanges, "role_id": role,
                "object_ref": basket_ref, "method": "POST", "endpoint_id": "basket-write",
                "status": status, "value_sha256": item_hash, "object_sha256": None,
                "private_marker_match": False, "owner_data_present": valid,
                "mutation_effect": effect, "independent_readback": False,
                "changed_fields": [], "request_shape": request_shape,
                "product_id": 5,
                "added_item_count": 1 if valid else 0}
            event.update(self._bind_basket_insert_event(event, basket_id, request_shape))
            return event, (row_id if valid else None), payload

        status, payload = self.request("GET", self.object_path(basket_ref), role=role)
        data_payload = payload.get("data") if isinstance(payload, dict) else None
        rows, owner_ok = self._basket_rows_for_insert(basket_ref, data_payload)
        row_map = {str(row["id"]): row for row in rows} if owner_ok else {}
        event = {"exchange_id": exchange_id, "index": self.exchanges, "role_id": role,
            "object_ref": basket_ref, "method": "GET", "endpoint_id": "basket-read",
            "status": status, "value_sha256": digest(sorted(row_map)),
            "object_sha256": digest(row_map) if owner_ok else None,
            "private_marker_match": False, "owner_data_present": owner_ok,
            "mutation_effect": "unknown", "independent_readback": status == 200 and owner_ok,
            "changed_fields": [], "product_id": None, "added_item_count": 0}
        event.update(self._bind_basket_insert_event(event, basket_id, None))
        return event, row_map, data_payload

    def _basket_rows_for_insert(self, basket_ref, data):
        role = OWNERS[basket_ref]
        if (not isinstance(data, dict) or integer(data.get("id")) != self.objects[basket_ref]["server_object_id"]
                or integer(data.get("UserId")) != self.roles[role]["user_id"]):
            return [], False
        products = data.get("Products")
        if not isinstance(products, list):
            return [], False
        rows = []
        for product in products:
            item = product.get("BasketItem") if isinstance(product, dict) else None
            if not isinstance(item, dict):
                return [], False
            try:
                row = {"id": integer(item.get("id")), "BasketId": integer(item.get("BasketId")),
                    "ProductId": integer(item.get("ProductId")), "quantity": integer(item.get("quantity")),
                    "createdAt": item.get("createdAt"), "updatedAt": item.get("updatedAt")}
            except FixtureFailure:
                return [], False
            if (product.get("id") != row["ProductId"]
                    or row["BasketId"] != self.objects[basket_ref]["server_object_id"]
                    or not isinstance(row["createdAt"], str) or not isinstance(row["updatedAt"], str)):
                return [], False
            rows.append(row)
        return rows, len({row["id"] for row in rows}) == len(rows)

    def _bind_basket_insert_event(self, event, basket_id, request_shape):
        role = event["role_id"]
        role_data = self.roles[role]
        identity = self._opaque_identity("basket", basket_id)
        return {"actor_kind": "authenticated", "generation_sha256": digest(self.config["generation"]),
            "actor_identity_sha256": digest([role_data["user_id"], role_data["email"]]),
            "actor_session_binding_sha256": role_data["session_binding_sha256"],
            "object_identity_sha256": identity, "parent_basket_identity_sha256": identity,
            "request_sha256": digest({"method": event["method"], "endpoint_id": event["endpoint_id"],
                "object_ref": event["object_ref"], "basket_identity_sha256": identity,
                "request_shape": request_shape,
                "product_id": event.get("product_id"),
                "quantity": 1 if event["method"] == "POST" else None})}

    def _opaque_identity(self, kind, value):
        if not isinstance(self.opaque_key, bytes) or len(self.opaque_key) < 32:
            raise FixtureFailure("v3_opaque_identity_key_missing")
        return hmac.new(self.opaque_key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()

    def _bind_v3_exchange(self, event, item_ref, item):
        role = event.get("role_id")
        role_data = self.roles.get(role) if role in self.roles else None
        basket_id = item.get("basket_id")
        return {
            "actor_kind": "authenticated" if role_data else "anonymous",
            "generation_sha256": digest(self.config["generation"]),
            "actor_identity_sha256": (digest([role_data["user_id"], role_data["email"]])
                                       if role_data else None),
            "actor_session_binding_sha256": (role_data.get("session_binding_sha256")
                                              if role_data else None),
            "request_sha256": digest({
                "method": event["method"], "endpoint_id": event["endpoint_id"],
                "object_ref": item_ref, "object_identity_sha256": self._opaque_identity("item", item["id"]),
                "parent_basket_identity_sha256": self._opaque_identity("basket", basket_id),
                "body": {"quantity": 2} if event["method"] == "PUT" else None,
            }),
            "object_identity_sha256": self._opaque_identity("item", item["id"]),
            "parent_basket_identity_sha256": self._opaque_identity("basket", basket_id),
        }

    def _v3_basket_snapshot(self, phase, exchange_id, data):
        rows, owner_ok = self._read_basket_rows_from_payload("basket-b", data)
        if not owner_ok or set(self.basket_write_items) != {
            "basket-write-candidate-b", "basket-write-control-b", "basket-write-negative-b",
            "basket-write-self-a", "basket-write-default-b",
        }:
            return None
        refs = ["basket-write-candidate-b", "basket-write-control-b",
                "basket-write-negative-b", "basket-write-default-b"]
        owner = self.roles["role-b"]
        owner_identity = digest([owner["user_id"], owner["email"]])
        basket_id = self.objects["basket-b"]["server_object_id"]
        basket_identity = self._opaque_identity("basket", basket_id)
        items = []
        for ref in refs:
            spec = self.basket_write_items[ref]
            row = rows.get(str(spec["id"]))
            if (row is None or row["BasketId"] != basket_id or row["ProductId"] != spec["product_id"]
                    or spec["owner_role"] != "role-b"):
                return None
            state = {
                "object_ref": ref,
                "object_identity_sha256": self._opaque_identity("item", row["id"]),
                "parent_basket_identity_sha256": basket_identity,
                "product_id": row["ProductId"], "owner_role_id": "role-b",
                "owner_identity_sha256": owner_identity,
                "quantity": row["quantity"], "created_at": row["createdAt"],
                "updated_at": row["updatedAt"], "membership_verified": True,
            }
            state["state_sha256"] = digest(state)
            items.append(state)
        snapshot = {
            "phase": phase, "generation_sha256": digest(self.config["generation"]),
            "exchange_id": exchange_id,
            "reader_identity_sha256": owner_identity,
            "reader_session_binding_sha256": owner["session_binding_sha256"],
            "basket_identity_sha256": basket_identity,
            "basket_owner_user_id": owner["user_id"],
            "basket_owner_identity_sha256": owner_identity,
            "items": items,
        }
        snapshot["snapshot_sha256"] = digest(snapshot)
        return snapshot

    @staticmethod
    def _v3_state_map(snapshot):
        return {item["object_ref"]: item for item in snapshot["items"]}

    def _v3_non_interference(self, baseline, *after):
        if baseline is None or not after:
            return False
        base = self._v3_state_map(baseline)
        if len(base) != 4 or "basket-write-candidate-b" not in base:
            return False
        for snapshot in after:
            current = self._v3_state_map(snapshot)
            if set(current) != set(base):
                return False
            for ref in set(base) - {"basket-write-candidate-b"}:
                if current[ref] != base[ref]:
                    return False
        return True

    def _read_basket_rows_from_payload(self, basket_ref, data):
        role = OWNERS[basket_ref]
        if (not isinstance(data, dict) or integer(data.get("id")) != self.objects[basket_ref]["server_object_id"]
                or integer(data.get("UserId")) != self.roles[role]["user_id"]):
            return {}, False
        products = data.get("Products")
        if not isinstance(products, list):
            return {}, False
        expected_ids = {self.basket_item_ids[basket_ref]}
        refs = ["basket-write-self-a"] if basket_ref == "basket-a" else [
            "basket-write-candidate-b", "basket-write-control-b", "basket-write-negative-b"]
        expected_ids.update(self.basket_write_items[ref]["id"] for ref in refs)
        rows = {}
        for product in products:
            if not isinstance(product, dict) or not isinstance(product.get("BasketItem"), dict):
                return {}, False
            item = product["BasketItem"]
            row = {"id": item.get("id"), "BasketId": item.get("BasketId"),
                   "ProductId": item.get("ProductId"), "quantity": item.get("quantity"),
                   "createdAt": item.get("createdAt"), "updatedAt": item.get("updatedAt")}
            try:
                row["id"] = integer(row["id"])
                row["BasketId"] = integer(row["BasketId"])
                row["ProductId"] = integer(row["ProductId"])
                row["quantity"] = integer(row["quantity"])
            except FixtureFailure:
                return {}, False
            if (product.get("id") != row["ProductId"] or row["BasketId"] != data["id"]
                    or not isinstance(row["createdAt"], str) or not isinstance(row["updatedAt"], str)):
                return {}, False
            rows[str(row["id"])] = row
        return rows, {int(key) for key in rows} == expected_ids

    def _b05_exchange(self, exchange_id, role_id, object_ref, method, endpoint_id,
                      path, data=None):
        status, payload = self.request(method, path, data, role=role_id)
        response = payload.get("data") if isinstance(payload, dict) else None
        observation = {
            "exchange_id": exchange_id, "index": self.exchanges, "role_id": role_id,
            "object_ref": object_ref, "method": method, "endpoint_id": endpoint_id,
            "status": status, "object_sha256": None, "value_sha256": None,
            "private_marker_match": False, "mutation_effect": "unknown",
            "owner_data_present": None, "independent_readback": False,
        }
        if method == "GET" and isinstance(response, dict):
            try:
                normal = self.normalized_object(object_ref, response)
                observation["object_sha256"] = digest(normal)
                expected_owner = self.roles[B05_OWNERS[object_ref]]["user_id"]
                observation["owner_data_present"] = (
                    response.get("UserId") == expected_owner
                    and response.get("id") == self.objects[object_ref].get("server_object_id")
                )
                expected = self.objects[object_ref].get("baseline_sha256")
                observation["private_marker_match"] = expected is not None and observation["object_sha256"] == expected
                if object_ref in {"address-a", "address-b", "negative-control-b", "write-candidate-b"}:
                    observation["value_sha256"] = digest(response.get("city"))
            except (FixtureFailure, KeyError, TypeError, ValueError):
                pass
        if method == "PUT":
            returned = response if isinstance(response, dict) else None
            observation["value_sha256"] = (
                digest(returned["city"]) if returned and isinstance(returned.get("city"), str) else None
            )
        return observation, payload

    def b05(self, operation):
        """Run one closed, registry-selected R01 schedule fragment."""
        if operation not in {"b05-own-read-first", "b05-own-read-second",
                             "b05-own-write-first", "b05-own-write-second",
                             "b05-own-write-cleanup", "b05-basket-write-first",
                             "b05-basket-write-second", "b05-basket-write-cleanup",
                             "b05-basket-write-v3-first", "b05-basket-write-v3-second",
                             "b05-basket-write-v3-cleanup",
                             "b05-basket-insert-first", "b05-basket-insert-second",
                             "b05-ownership-transfer-first", "b05-ownership-transfer-second"}:
            raise FixtureFailure("unknown_b05_operation")
        saved = json.loads(STATE.read_text(encoding="utf-8"))
        if saved.get("generation") != self.config["generation"]:
            raise FixtureFailure("stale_fixture_generation")
        self.roles, self.objects = saved["roles"], saved["objects"]
        self.opaque_key = bytes.fromhex(saved["opaque_key"]) if saved.get("opaque_key") else None
        self.basket_item_ids = saved.get("basket_item_ids", {})
        self.basket_write_items = saved.get("basket_write_items", {})
        self.basket_write_baseline = saved.get("basket_write_baseline", {})
        is_insert = self.config.get("active_check_id") == "juice-basket-insert-owner-check-v1"
        self.limit = 14 if is_insert else 12
        self.deadline = time.monotonic() + 20
        self.exchanges = 0
        self.operation_exchanges = 0
        events = []
        self.basket_snapshots = []
        is_v3 = self.config.get("active_check_id") == "juice-basket-own-write-v3"
        controls = {}
        permissions = self.config["profile"]["permissions"]
        if operation.startswith("b05-own-read"):
            controls["permission_relation"] = any(
                item["role_id"] == "role-a" and item["object_id"] == "basket-b"
                and item["read"] is False for item in permissions
            )
            controls["ownership"] = self.objects.get("basket-b", {}).get("ownership_verified") is True
        elif operation.startswith("b05-basket-write"):
            controls["permission_relation"] = any(
                item["role_id"] == "role-a" and item["object_id"] == "basket-b"
                and item["update"] is False for item in permissions
            )
            controls["ownership"] = all(ref in self.basket_write_items for ref in (
                "basket-write-candidate-b", "basket-write-control-b",
                "basket-write-negative-b", "basket-write-self-a"))
        elif operation.startswith("b05-basket-insert"):
            controls["permission_relation"] = any(
                item["role_id"] == "role-a" and item["object_id"] == "basket-b"
                and item["update"] is False for item in permissions
            )
            controls["ownership"] = (
                self.objects.get("basket-b", {}).get("ownership_verified") is True
                and self.objects.get("basket-a", {}).get("ownership_verified") is True
            )
        elif operation.startswith("b05-ownership-transfer"):
            controls["permission_relation"] = any(
                item["role_id"] == "role-a" and item["object_id"] == "address-b"
                and item["update"] is False for item in permissions
            )
            controls["ownership"] = self.objects.get("address-b", {}).get("ownership_verified") is True
        else:
            controls["permission_relation"] = any(
                item["role_id"] == "role-a" and item["object_id"] == "address-b"
                and item["update"] is False for item in permissions
            )
            candidate = self.objects.get("write-candidate-b", {})
            controls["ownership"] = (candidate.get("ownership_verified") is True
                                      and candidate.get("server_owner_id") == self.roles["role-b"]["user_id"])

        def get(exchange_id, role, object_ref, endpoint_id, path):
            item, payload = self._b05_exchange(exchange_id, role, object_ref, "GET", endpoint_id, path)
            events.append(item)
            return item, payload

        def put(exchange_id, role, object_ref, endpoint_id, path, value):
            before = self.objects[object_ref].get("baseline_sha256")
            item, payload = self._b05_exchange(exchange_id, role, object_ref, "PUT", endpoint_id,
                                               path, {"city": value})
            events.append(item)
            return item, payload, before

        if operation == "b05-own-read-first":
            owner, _ = get("oc-r-read", "role-b", "basket-b", "basket-read",
                           self.object_path("basket-b"))
            controls["owner_availability"] = owner["status"] == 200 and owner["private_marker_match"]
            negative, payload = get("nc-r-deny", "role-a", "negative-control-b", "address-read",
                                    self.object_path("negative-control-b"))
            controls["negative_control"] = (negative["status"] == 400 and isinstance(payload, dict)
                                                and payload.get("status") == "error")
            self_read, _ = get("sc-r-self", "role-a", "basket-a", "basket-read",
                               self.object_path("basket-a"))
            controls["attacker_self"] = self_read["status"] == 200 and self_read["private_marker_match"]
            baseline, _ = get("baseline-r-digest", "role-b", "basket-b", "basket-read",
                              self.object_path("basket-b"))
            controls["ownership"] = baseline["status"] == 200 and baseline["private_marker_match"]
            probe, _ = get("probe-r-t1", "role-a", "basket-b", "basket-read",
                           self.object_path("basket-b"))
            events[-1]["private_marker_match"] = (probe["status"] == 200 and
                                                    probe.get("object_sha256") == baseline.get("object_sha256"))
        elif operation == "b05-own-read-second":
            probe, _ = get("probe-r-t2", "role-a", "basket-b", "basket-read",
                           self.object_path("basket-b"))
            events[-1]["private_marker_match"] = (probe["status"] == 200 and
                                                    probe.get("object_sha256") == self.objects["basket-b"].get("baseline_sha256"))
            cleanup, _ = get("cleanup-r-verify", "role-b", "basket-b", "basket-read",
                             self.object_path("basket-b"))
            controls["cleanup_baseline"] = cleanup["status"] == 200 and cleanup["private_marker_match"]
        elif operation == "b05-own-write-first":
            control, _, _ = put("oc-w-update", "role-b", "address-b", "address-write",
                                self.object_path("address-b"), B05_WRITE_MARKER)
            control_read, _ = get("oc-w-readback", "role-b", "address-b", "address-read",
                                  self.object_path("address-b"))
            controls["owner_write_control"] = (control["status"] in {200, 201} and
                                                  control_read["status"] == 200 and
                                                  control_read.get("value_sha256") == digest(B05_WRITE_MARKER))
            self_control, _, _ = put("sc-w-self", "role-a", "address-a", "address-write",
                                     self.object_path("address-a"), B05_WRITE_MARKER)
            controls["attacker_self"] = self_control["status"] in {200, 201}
            negative, _, _ = put("nc-w-deny", "role-a", "negative-control-b", "address-write",
                                 self.object_path("negative-control-b"), B05_WRITE_MARKER)
            negative_read, _ = get("nc-w-readback", "role-b", "negative-control-b", "address-read",
                                   self.object_path("negative-control-b"))
            negative_effect = "unchanged" if (
                negative_read["status"] == 200
                and negative_read.get("value_sha256") == digest("Fixture")
                and negative_read.get("object_sha256") == self.objects["negative-control-b"].get("baseline_sha256")
            ) else "changed" if negative_read["status"] == 200 else "unknown"
            events[-1]["mutation_effect"] = negative_effect
            controls["negative_control"] = (negative_read["status"] == 200 and
                                                negative_read.get("value_sha256") == digest("Fixture") and
                                                negative_read.get("object_sha256") == self.objects["negative-control-b"].get("baseline_sha256"))
            baseline, _ = get("baseline-w-digest", "role-b", "write-candidate-b", "address-read",
                              self.object_path("write-candidate-b"))
            controls["ownership"] = baseline["status"] == 200 and baseline["private_marker_match"]
            probe, _, _ = put("probe-w-t1", "role-a", "write-candidate-b", "address-write",
                              self.object_path("write-candidate-b"), B05_WRITE_MARKER)
            readback, _ = get("probe-w-t1-readback", "role-b", "write-candidate-b", "address-read",
                              self.object_path("write-candidate-b"))
            events[-1]["independent_readback"] = True
            effect = "changed" if (
                readback["status"] == 200 and readback.get("value_sha256") == digest(B05_WRITE_MARKER)
                and readback.get("owner_data_present") is True
            ) else "unchanged" if (
                readback["status"] == 200 and readback.get("value_sha256") == digest("Fixture")
                and readback.get("object_sha256") == self.objects["write-candidate-b"].get("baseline_sha256")
            ) else "unknown"
            events[-1]["mutation_effect"] = effect
            events[-2]["mutation_effect"] = effect
            controls["trial1_mutation_ack"] = probe["status"] in {200, 201}
        elif operation == "b05-own-write-second":
            probe, _, _ = put("probe-w-t2", "role-a", "write-candidate-b", "address-write",
                              self.object_path("write-candidate-b"), B05_WRITE_MARKER)
            readback, _ = get("probe-w-t2-readback", "role-b", "write-candidate-b", "address-read",
                              self.object_path("write-candidate-b"))
            events[-1]["independent_readback"] = True
            effect = "changed" if (
                readback["status"] == 200 and readback.get("value_sha256") == digest(B05_WRITE_MARKER)
                and readback.get("owner_data_present") is True
            ) else "unchanged" if (
                readback["status"] == 200 and readback.get("value_sha256") == digest("Fixture")
                and readback.get("object_sha256") == self.objects["write-candidate-b"].get("baseline_sha256")
            ) else "unknown"
            events[-1]["mutation_effect"] = effect
            events[-2]["mutation_effect"] = effect
            controls["trial2_mutation_ack"] = probe["status"] in {200, 201}
        elif operation.startswith("b05-basket-write"):
            provisioned = self.config["profile"].get(
                "b05_basket_write_v3_candidate" if is_v3 else "b05_basket_write_candidate", False,
            )
            if not provisioned:
                raise FixtureFailure("basket_write_candidate_not_registered")
            schedule = []

            def action(exchange_id, role, item_ref, method, quantity=None):
                item, row, baseline, _payload = self._basket_item_exchange(
                    exchange_id, role, item_ref, method, quantity)
                events.append(item)
                schedule.append((item, row, baseline))
                return item

            if not is_v3 and operation == "b05-basket-write-first":
                control = action("oc-b-update", "role-b", "basket-write-control-b", "PUT", 2)
                control_read = action("oc-b-readback", "role-b", "basket-write-control-b", "GET")
                controls["owner_write_control"] = (
                    control["status"] in {200, 201} and control_read["status"] == 200
                    and control_read["changed_fields"] == ["quantity", "updatedAt"]
                    and control_read["timestamp_update_proven"] is True
                    and control_read["created_at_unchanged"] is True
                    and control_read["relationships_unchanged"] is True
                    and control_read["other_items_unchanged"] is True
                )
                self_control = action("sc-a-update", "role-a", "basket-write-self-a", "PUT", 2)
                self_read = action("sc-a-readback", "role-a", "basket-write-self-a", "GET")
                controls["attacker_self"] = (
                    self_control["status"] in {200, 201} and self_read["status"] == 200
                    and self_read["changed_fields"] == ["quantity", "updatedAt"]
                    and self_read["timestamp_update_proven"] is True
                    and self_read["created_at_unchanged"] is True
                    and self_read["relationships_unchanged"] is True
                    and self_read["other_items_unchanged"] is True
                )
                negative = action("nc-a-update", "role-a", "basket-write-negative-b", "PUT", 2)
                negative_read = action("nc-b-readback", "role-b", "basket-write-negative-b", "GET")
                controls["negative_control"] = (
                    negative["status"] in {400, 401, 403, 404} and negative_read["status"] == 200
                    and negative_read["changed_fields"] == [] and negative_read["relationships_unchanged"] is True
                )
                baseline, _row, _old, baseline_payload = self._basket_item_exchange(
                    "baseline-b-state", "role-b", "basket-write-candidate-b", "GET")
                events.append(baseline)
                controls["ownership"] = baseline["status"] == 200 and baseline["owner_data_present"] is True
                # Baseline after controls makes the candidate delta object-local.
                baseline_data = baseline_payload.get("data") if isinstance(baseline_payload, dict) else None
                baseline_rows, owner_ok = self._read_basket_rows_from_payload("basket-b", baseline_data)
                self.basket_write_baseline["basket-b"] = baseline_rows
                if not owner_ok:
                    raise FixtureFailure("basket_candidate_baseline_unavailable")
                time.sleep(1.05)
                probe = action("probe-b-t1", "role-a", "basket-write-candidate-b", "PUT", 2)
                readback = action("probe-b-t1-readback", "role-b", "basket-write-candidate-b", "GET")
                effect = "changed" if (
                    readback["status"] == 200 and readback["changed_fields"] == ["quantity", "updatedAt"]
                    and readback["timestamp_update_proven"] is True
                    and readback["created_at_unchanged"] is True
                    and readback["relationships_unchanged"] is True
                    and readback["other_items_unchanged"] is True
                ) else "unchanged" if readback["status"] == 200 and readback["changed_fields"] == [] else "unknown"
                events[-1]["mutation_effect"] = effect
                events[-2]["mutation_effect"] = effect
                controls["trial1_mutation_ack"] = probe["status"] in {200, 201}
            elif is_v3 and operation == "b05-basket-write-v3-first":
                control = action("oc-b-update", "role-b", "basket-write-control-b", "PUT", 2)
                control_read = action("oc-b-readback", "role-b", "basket-write-control-b", "GET")
                controls["owner_write_control"] = (
                    control["status"] in {200, 201} and control_read["status"] == 200
                    and control_read["changed_fields"] == ["quantity", "updatedAt"]
                    and control_read["timestamp_update_proven"] is True
                    and control_read["created_at_unchanged"] is True
                    and control_read["relationships_unchanged"] is True
                    and control_read["other_items_unchanged"] is True
                )
                controls["ownership"] = control_read["owner_data_present"] is True

                candidate = self.basket_write_items["basket-write-candidate-b"]
                status, _ = self.request(
                    "PUT", "/api/BasketItems/" + str(candidate["id"]), {"quantity": 2}, role=None,
                )
                anonymous = {
                    "exchange_id": "authn-anon-put", "index": self.exchanges,
                    "role_id": None, "actor_kind": "anonymous",
                    "object_ref": "basket-write-candidate-b", "method": "PUT",
                    "endpoint_id": "basket-write", "status": status,
                    "object_sha256": None, "value_sha256": None, "private_marker_match": False,
                    "owner_data_present": None, "mutation_effect": "unknown",
                    "independent_readback": False, "changed_fields": [],
                    "timestamp_update_proven": None, "created_at_unchanged": None,
                    "relationships_unchanged": None, "other_items_unchanged": None,
                }
                anonymous.update(self._bind_v3_exchange(
                    anonymous, "basket-write-candidate-b", candidate,
                ))
                events.append(anonymous)

                auth_read = action("authn-b-readback", "role-b", "basket-write-candidate-b", "GET")
                baseline = next((item for item in self.basket_snapshots
                                 if item["phase"] == "baseline-t1"), None)
                after_auth = next((item for item in self.basket_snapshots
                                   if item["phase"] == "after-authn"), None)
                auth_unchanged = bool(
                    baseline and after_auth
                    and self._v3_state_map(baseline) == self._v3_state_map(after_auth)
                )
                controls["authentication_control"] = status in {401, 403} and auth_read["status"] == 200 and auth_unchanged
                controls["non_interference"] = bool(
                    baseline and after_auth and self._v3_non_interference(baseline, after_auth)
                )

                self_control = action("sc-a-update", "role-a", "basket-write-self-a", "PUT", 2)
                self_read = action("sc-a-readback", "role-a", "basket-write-self-a", "GET")
                controls["attacker_self"] = (
                    self_control["status"] in {200, 201} and self_read["status"] == 200
                    and self_read["changed_fields"] == ["quantity", "updatedAt"]
                    and self_read["timestamp_update_proven"] is True
                    and self_read["created_at_unchanged"] is True
                    and self_read["relationships_unchanged"] is True
                    and self_read["other_items_unchanged"] is True
                )
                time.sleep(1.05)
                probe = action("probe-b-t1", "role-a", "basket-write-candidate-b", "PUT", 2)
                readback = action("probe-b-t1-readback", "role-b", "basket-write-candidate-b", "GET")
                effect = "changed" if (
                    readback["status"] == 200 and readback["changed_fields"] == ["quantity", "updatedAt"]
                    and readback["timestamp_update_proven"] is True
                    and readback["created_at_unchanged"] is True
                    and readback["relationships_unchanged"] is True
                    and readback["other_items_unchanged"] is True
                ) else "unchanged" if readback["status"] == 200 and readback["changed_fields"] == [] else "unknown"
                events[-1]["mutation_effect"] = effect
                events[-2]["mutation_effect"] = effect
                controls["trial1_mutation_ack"] = probe["status"] in {200, 201}
                controls["non_interference"] = controls["non_interference"] and bool(
                    baseline and after_auth and self.basket_snapshots
                    and self._v3_non_interference(baseline, after_auth, self.basket_snapshots[-1])
                )
            elif is_v3 and operation == "b05-basket-write-v3-second":
                baseline = action("baseline-b-t2", "role-b", "basket-write-candidate-b", "GET")
                controls["ownership"] = baseline["status"] == 200 and baseline["owner_data_present"] is True
                time.sleep(1.05)
                probe = action("probe-b-t2", "role-a", "basket-write-candidate-b", "PUT", 2)
                readback = action("probe-b-t2-readback", "role-b", "basket-write-candidate-b", "GET")
                effect = "changed" if (
                    readback["status"] == 200 and readback["changed_fields"] == ["quantity", "updatedAt"]
                    and readback["timestamp_update_proven"] is True
                    and readback["created_at_unchanged"] is True
                    and readback["relationships_unchanged"] is True
                    and readback["other_items_unchanged"] is True
                ) else "unchanged" if readback["status"] == 200 and readback["changed_fields"] == [] else "unknown"
                events[-1]["mutation_effect"] = effect
                events[-2]["mutation_effect"] = effect
                baseline_state = next((item for item in self.basket_snapshots
                                       if item["phase"] == "baseline-t2"), None)
                controls["non_interference"] = bool(
                    baseline_state and self._v3_non_interference(baseline_state, self.basket_snapshots[-1])
                )
                controls["repeat_reset"] = (
                    baseline["status"] == 200 and baseline["owner_data_present"] is True
                    and readback["status"] == 200
                )
                controls["trial2_mutation_ack"] = probe["status"] in {200, 201}
            elif is_v3 and operation == "b05-basket-write-v3-cleanup":
                cleanup = action("cleanup-b-baseline", "role-b", "basket-write-candidate-b", "GET")
                expected = self.basket_write_baseline.get("basket-b", {})
                snapshot = self.basket_snapshots[-1] if self.basket_snapshots else None
                cleanup_states = self._v3_state_map(snapshot) if snapshot else {}
                cleanup_expected = all(
                    cleanup_states.get(ref, {}).get("quantity") == expected.get(str(spec["id"]), {}).get("quantity")
                    and cleanup_states.get(ref, {}).get("created_at") == expected.get(str(spec["id"]), {}).get("createdAt")
                    for ref, spec in self.basket_write_items.items() if ref != "basket-write-self-a"
                )
                controls["cleanup_baseline"] = (
                    cleanup["status"] == 200 and cleanup["changed_fields"] == []
                    and cleanup["relationships_unchanged"] is True
                    and cleanup["other_items_unchanged"] is True and cleanup_expected
                )
                controls["ownership"] = cleanup["owner_data_present"] is True
            elif operation == "b05-basket-write-second":
                probe = action("probe-b-t2", "role-a", "basket-write-candidate-b", "PUT", 2)
                readback = action("probe-b-t2-readback", "role-b", "basket-write-candidate-b", "GET")
                effect = "changed" if (
                    readback["status"] == 200 and readback["changed_fields"] == ["quantity", "updatedAt"]
                    and readback["timestamp_update_proven"] is True
                    and readback["created_at_unchanged"] is True
                    and readback["relationships_unchanged"] is True
                    and readback["other_items_unchanged"] is True
                ) else "unchanged" if readback["status"] == 200 and readback["changed_fields"] == [] else "unknown"
                events[-1]["mutation_effect"] = effect
                events[-2]["mutation_effect"] = effect
                controls["trial2_mutation_ack"] = probe["status"] in {200, 201}
            else:
                cleanup = action("cleanup-b-baseline", "role-b", "basket-write-candidate-b", "GET")
                controls["cleanup_baseline"] = (
                    cleanup["status"] == 200 and cleanup["changed_fields"] == []
                    and cleanup["relationships_unchanged"] is True and cleanup["other_items_unchanged"] is True
                )
        elif operation.startswith("b05-ownership-transfer"):
            if not self.config["profile"].get("b05_ownership_transfer_candidate", False):
                raise FixtureFailure("ownership_transfer_candidate_not_registered")

            def owner_exchange(exchange_id, role, object_ref, method, body=None):
                path = self.object_path(object_ref)
                status, payload = self.request(method, path, body, role=role)
                data = payload.get("data") if isinstance(payload, dict) else None
                user_id = data.get("UserId") if isinstance(data, dict) else None
                owner_roles = {value["user_id"]: key for key, value in self.roles.items()}
                valid_data = (isinstance(data, dict) and data.get("id") == self.objects[object_ref]["server_object_id"]
                              and type(user_id) is int and user_id in owner_roles)
                event = {
                    "exchange_id": exchange_id, "index": self.exchanges, "role_id": role,
                    "object_ref": object_ref, "method": method, "endpoint_id": "address-write" if method == "PUT" else "address-read",
                    "status": status, "object_sha256": digest([data.get("id"), user_id]) if valid_data else None,
                    "value_sha256": None, "private_marker_match": False,
                    "owner_data_present": valid_data, "mutation_effect": "unknown",
                    "independent_readback": method == "GET",
                    "observed_owner_role": owner_roles.get(user_id) if valid_data else None,
                }
                events.append(event)
                return event

            suffix = "-t2" if operation.endswith("second") else ""
            owner = owner_exchange("oc-t-owner" + suffix, "role-b", "address-b", "GET")
            denied = owner_exchange("nc-t-deny" + suffix, "role-a", "negative-control-b", "GET")
            negative_owner = owner_exchange("nc-t-owner" + suffix, "role-b", "negative-control-b", "GET")
            controls["owner_availability"] = owner["status"] == 200 and owner["observed_owner_role"] == "role-b"
            controls["negative_control"] = (
                denied["status"] in {400, 401, 403, 404}
                and negative_owner["status"] == 200 and negative_owner["observed_owner_role"] == "role-b"
            )
            controls["attacker_identity"] = bool(self.roles["role-a"].get("verified_role") == "customer")
            controls["ownership"] = owner["observed_owner_role"] == "role-b"
            controls["permission_relation"] = controls["permission_relation"]
            probe = owner_exchange("probe-t-transfer" + suffix, "role-a", "address-b", "PUT", {})
            attacker_after = owner_exchange("probe-t-attacker-read" + suffix, "role-a", "address-b", "GET")
            owner_after = owner_exchange("probe-t-owner-read" + suffix, "role-b", "address-b", "GET")
            controls["attacker_observed_owner"] = (
                attacker_after["status"] == 200 and attacker_after["observed_owner_role"] == "role-a"
            )
            controls["old_owner_observed_denied"] = owner_after["status"] in {400, 401, 403, 404}
            if operation == "b05-ownership-transfer-first":
                controls["trial1_mutation_ack"] = probe["status"] in {200, 201}
            else:
                controls["trial2_mutation_ack"] = probe["status"] in {200, 201}
        elif operation.startswith("b05-basket-insert"):
            suffix = "-t2" if operation.endswith("second") else "-t1"
            target_id = self.objects["basket-b"]["server_object_id"]
            attacker_basket_id = self.objects["basket-a"]["server_object_id"]
            baseline, baseline_rows, _ = self._basket_insert_exchange(
                "baseline-b" + suffix, "role-b", "basket-b")
            controls["ownership"] = controls["ownership"] and baseline["owner_data_present"] is True

            owner_write, owner_item_id, _ = self._basket_insert_exchange(
                "owner-a-insert" + suffix, "role-a", "basket-a",
                request_shape="owned-basket-insert",
                data={"BasketId": attacker_basket_id, "ProductId": 5, "quantity": 1})
            owner_read, owner_rows, _ = self._basket_insert_exchange(
                "owner-a-readback" + suffix, "role-a", "basket-a")
            owner_row = owner_rows.get(str(owner_item_id)) if isinstance(owner_rows, dict) else None
            owner_ok = (owner_write["status"] in {200, 201} and owner_item_id is not None
                and owner_read["status"] == 200 and owner_read["owner_data_present"] is True
                and owner_row is not None and owner_row["BasketId"] == attacker_basket_id
                and owner_row["ProductId"] == 5 and owner_row["quantity"] == 1)
            owner_read.update({"private_marker_match": owner_ok,
                "value_sha256": self._opaque_identity("item", owner_item_id) if owner_ok else None,
                "added_item_count": 1 if owner_ok else 0,
                "mutation_effect": "changed" if owner_ok else "unknown",
                "changed_fields": ["BasketItems"] if owner_ok else []})
            controls["owner_write_control"] = owner_ok
            controls["attacker_self"] = owner_ok

            denied, _, _ = self._basket_insert_exchange(
                "denied-b-insert" + suffix, "role-a", "basket-b",
                request_shape="single-foreign-basket-insert",
                data={"BasketId": target_id, "ProductId": 5, "quantity": 1})
            denied_read, denied_rows, _ = self._basket_insert_exchange(
                "denied-b-readback" + suffix, "role-b", "basket-b")
            denied_unchanged = (isinstance(baseline_rows, dict) and denied_rows == baseline_rows)
            denied_effect = "unchanged" if denied_unchanged else "changed" if denied_rows else "unknown"
            denied.update({"mutation_effect": denied_effect})
            denied_read.update({"mutation_effect": denied_effect,
                "changed_fields": [] if denied_unchanged else ["BasketItems"],
                "added_item_count": 0 if denied_unchanged else max(0, len(denied_rows) - len(baseline_rows))})
            controls["negative_control"] = (
                denied["status"] in {400, 401, 403, 404}
                and denied_read["status"] == 200 and denied_read["owner_data_present"] is True
                and denied_unchanged
            )

            raw_body = (f'{{"BasketId":{attacker_basket_id},"ProductId":5,"quantity":1,'
                        f'"BasketId":{target_id}}}')
            probe, probe_item_id, _ = self._basket_insert_exchange(
                "probe-duplicate-basket" + suffix, "role-a", "basket-b",
                request_shape="duplicate-own-first-foreign-last-insert", raw_body=raw_body)
            probe_read, probe_rows, _ = self._basket_insert_exchange(
                "probe-b-readback" + suffix, "role-b", "basket-b")
            new_ids = set(probe_rows) - set(baseline_rows) if isinstance(probe_rows, dict) else set()
            removed_ids = set(baseline_rows) - set(probe_rows) if isinstance(probe_rows, dict) else set()
            changed_existing = isinstance(probe_rows, dict) and any(
                probe_rows.get(key) != row for key, row in baseline_rows.items())
            inserted = probe_rows.get(str(probe_item_id)) if isinstance(probe_rows, dict) else None
            exact_insert = (len(new_ids) == 1 and not removed_ids and not changed_existing
                and probe_item_id is not None and inserted is not None
                and inserted["BasketId"] == target_id and inserted["ProductId"] == 5
                and inserted["quantity"] == 1)
            unchanged = isinstance(probe_rows, dict) and probe_rows == baseline_rows
            effect = "changed" if exact_insert else "unchanged" if unchanged else "unknown"
            controls["trial1_mutation_ack" if suffix == "-t1" else "trial2_mutation_ack"] = (
                probe["status"] in {200, 201} if exact_insert else probe["status"] in {400, 401, 403, 404, 200}
            )
            probe.update({"mutation_effect": effect})
            probe_read.update({"private_marker_match": exact_insert,
                "value_sha256": self._opaque_identity("item", probe_item_id) if exact_insert else None,
                "mutation_effect": effect,
                "changed_fields": ["BasketItems"] if exact_insert else [],
                "added_item_count": len(new_ids) if isinstance(probe_rows, dict) else None})
            controls["ownership"] = controls["ownership"] and probe_read["owner_data_present"] is True
            events.extend((baseline, owner_write, owner_read, denied, denied_read, probe, probe_read))
            controls["permission_relation"] = controls["permission_relation"]
        else:
            cleanup, _ = get("cleanup-w-verify", "role-b", "write-candidate-b", "address-read",
                             self.object_path("write-candidate-b"))
            controls["cleanup_baseline"] = cleanup["status"] == 200 and cleanup["private_marker_match"]
        return {"schema_version": "b05.worker-step.v1", "operation": operation,
                "generation_sha256": digest(self.config["generation"]),
                "source_snapshot_digest": self.config["source_snapshot"],
                "profile_sha256": digest(self.config["profile"]), "status": "completed",
                "http_exchanges": self.exchanges, "controls": controls,
                "exchanges": events,
                "basket_snapshots": self.basket_snapshots if is_v3 else [],
                "role_a_session_binding_sha256": (self.roles.get("role-a", {}).get("session_binding_sha256")
                                                   if is_v3 or is_insert else None),
                "role_b_session_binding_sha256": (self.roles.get("role-b", {}).get("session_binding_sha256")
                                                   if is_v3 or is_insert else None),
                "technical_error": None}


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
            client.opaque_key = bytes.fromhex(saved["opaque_key"]) if saved.get("opaque_key") else None
            client.basket_item_ids = saved.get("basket_item_ids", {})
            client.basket_write_items = saved.get("basket_write_items", {})
            client.basket_write_baseline = saved.get("basket_write_baseline", {})
            # This phase is a fresh full control suite; retain its own complete
            # observations, then candidate provisioning appends to these.
            client.exchanges = 0
            client.operation_exchanges = 0
            client.controls = []
            client.observations = []
            client.limit = config["profile"]["control_http_budget"]
            if operation == "lost-session":
                client.roles["role-a"]["token"] = "invalid-fixture-session"
            if operation == "changed-identity":
                client.roles["role-a"]["token"] = client.roles["role-b"]["token"]
            client.verify_controls()
            if operation == "control":
                client._save_state()
        elif operation == "b05-provision":
            saved = json.loads(STATE.read_text())
            if saved["generation"] != config["generation"]:
                raise FixtureFailure("stale_fixture_generation")
            client.roles, client.objects = saved["roles"], saved["objects"]
            client.opaque_key = bytes.fromhex(saved["opaque_key"]) if saved.get("opaque_key") else None
            client.basket_item_ids = saved["basket_item_ids"]
            client.basket_write_items = saved.get("basket_write_items", {})
            client.basket_write_baseline = saved.get("basket_write_baseline", {})
            client.controls = saved.get("controls", [])
            client.observations = saved.get("observations", [])
            client.exchanges = saved.get("exchanges", 0)
            client.operation_exchanges = 0
            client.limit = config["profile"]["control_http_budget"]
            client.provision_b05()
        elif operation.startswith("b05-"):
            return client.b05(operation)
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
    return 0 if result.get("status") in {"ready", "completed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
