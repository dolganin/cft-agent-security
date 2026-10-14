"""Fixed Docker-only B06 protocol; private credentials never leave tmpfs."""
import hashlib
import importlib.util
import json
import os
import secrets
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

BASE = "http://juice:3000"
APPROVED = "https://github.com/juice-shop/juice-shop"
NEGATIVE = "http://b06-sink:18080/negative"
PROBE = "http://b06-sink:18080/landing?allowed=" + APPROVED


class Failure(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def prepare(config):
    spec = importlib.util.spec_from_file_location("b04_fixture", "/app/b04.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class CredentialFixture(module.FixtureClient):
        def __init__(self, cfg):
            super().__init__(cfg)
            self.credentials = {}

        def request(self, method, path, data=None, role=None, **kwargs):
            if method == "POST" and path == "/api/Users":
                self.credentials[data["email"]] = data["password"]
            return super().request(method, path, data, role, **kwargs)

    client = CredentialFixture(config)
    client.prepare()
    state = json.loads(module.STATE.read_text())
    for role in state["roles"].values():
        role["password"] = client.credentials[role["email"]]
    module.STATE.write_text(json.dumps(state), encoding="utf-8")
    return client.public("ready", "B04 identity and ownership controls passed")


class Protocol:
    def __init__(self):
        self.ledger = []
        self.deadline = time.monotonic() + 20
        self.limit = 17
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, operation, method, path, *, token=None, data=None):
        if len(self.ledger) >= self.limit or time.monotonic() >= self.deadline:
            raise Failure("budget_exhausted")
        headers = {"User-Agent": "cft-b06-verifier/1", "Accept": "application/json"}
        if token:
            headers.update(Authorization="Bearer " + token, Cookie="token=" + token)
        encoded = json.dumps(data).encode() if data is not None else None
        if len(path.encode()) + len(encoded or b"") > 4096:
            raise Failure("budget_exhausted")
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        event = {"sequence": len(self.ledger) + 1, "operation": operation,
                 "status_code": 599, "response_bytes": 0, "truncated": False}
        self.ledger.append(event)
        try:
            try:
                response = self.opener.open(Request(BASE + path, data=encoded, headers=headers,
                                                    method=method), timeout=min(3, max(.01, self.deadline - time.monotonic())))
            except HTTPError as error:
                response = error
            with response:
                raw = response.read(65537)
                event.update(status_code=int(response.status), response_bytes=len(raw),
                             truncated=len(raw) > 65536)
                if event["truncated"]:
                    raise Failure("response_truncated")
                location = response.headers.get_all("Location", [])
                if len(location) > 1 or any(len(v) > 4096 or "\r" in v or "\n" in v for v in location):
                    event["location"] = "ambiguous"
                elif location:
                    value = location[0]
                    event["location"] = "approved" if value == APPROVED else "probe" if value == PROBE else "other"
                    event["location_sha256"] = hashlib.sha256(value.encode()).hexdigest()
                else:
                    event["location"] = "none"
                return event, raw
        except (OSError, URLError, TimeoutError):
            raise Failure("timeout") from None

    def login(self, operation, actor, password):
        event, raw = self.request(operation, "POST", "/rest/user/login",
                                  data={"email": actor["email"], "password": password})
        try:
            auth = json.loads(raw).get("authentication", {})
        except (ValueError, AttributeError):
            auth = {}
        accepted = (event["status_code"] == 200 and isinstance(auth, dict)
                    and auth.get("umail") == actor["email"] and isinstance(auth.get("token"), str)
                    and bool(auth["token"]))
        event["login_accepted"] = accepted
        if operation in {"baseline_login", "positive_login", "baseline_relogin"} and not accepted:
            raise Failure("control_failed")
        return auth["token"] if accepted else None

    def identity(self, operation, actor, token):
        event, raw = self.request(operation, "GET", "/rest/user/whoami?fields=id,email,role", token=token)
        try:
            user = json.loads(raw).get("user", {})
        except (ValueError, AttributeError):
            user = {}
        event.update(expected_identity_id=actor["user_id"],
                     expected_identity_sha256=digest([actor["user_id"], actor["email"]]))
        if (isinstance(user, dict) and type(user.get("id")) is int and user["id"] > 0
                and isinstance(user.get("email"), str) and user.get("role") == "customer"):
            event.update(identity_id=user["id"], identity_sha256=digest([user["id"], user["email"]]))
        if (event.get("identity_id") != actor["user_id"]
                or event.get("identity_sha256") != event["expected_identity_sha256"]):
            raise Failure("control_failed")

    def change(self, operation, actor, new, current=None, anonymous=False):
        values = {"new": new, "repeat": new}
        if current is not None:
            values["current"] = current
        event, raw = self.request(operation, "GET", "/rest/user/change-password?" + urlencode(values),
                                  token=None if anonymous else actor["token"])
        if event["status_code"] == 500 and b"Blocked illegal activity" in raw and anonymous:
            event["denial"] = "auth_required"
        elif event["status_code"] == 401 and b"Current password is not correct" in raw:
            event["denial"] = "wrong_current"
        if ((operation == "positive_change" and event["status_code"] != 200)
                or (operation == "anonymous_change" and event.get("denial") != "auth_required")
                or (operation == "wrong_password_change" and event.get("denial") != "wrong_current")):
            raise Failure("control_failed")

    def auth(self, config):
        state = json.loads(Path("/state/session.json").read_text())
        if state["generation"] != config["generation"]:
            raise Failure("technical_failure")
        a, b = state["roles"]["role-a"], state["roles"]["role-b"]
        new_a, new_b = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        a["token"] = self.login("baseline_login", a, a["password"])
        self.identity("baseline_identity", a, a["token"])
        self.identity("positive_identity", b, b["token"])
        self.change("positive_change", b, new_b, current=b["password"])
        b["token"] = self.login("positive_login", b, new_b)
        self.identity("positive_readback", b, b["token"])
        self.change("anonymous_change", a, secrets.token_urlsafe(32), anonymous=True)
        self.change("wrong_password_change", a, secrets.token_urlsafe(32), current=secrets.token_urlsafe(32))
        a["token"] = self.login("baseline_relogin", a, a["password"])
        self.identity("baseline_reidentity", a, a["token"])
        self.change("omission_change", a, new_a)
        new_token = self.login("new_credential_login", a, new_a)
        old_token = self.login("old_credential_login", a, a["password"])
        if bool(new_token) == bool(old_token):
            raise Failure("control_failed")
        self.identity("effect_identity", a, new_token if new_token and not old_token else old_token)
        self.identity("other_identity_before", b, b["token"])
        object_id = state["objects"]["negative-control-b"]["server_object_id"]
        if type(object_id) is not int or not 0 < object_id < 1_000_000_000:
            raise Failure("technical_failure")
        event, raw = self.request("other_owner_read", "GET", "/api/Addresss/" + str(object_id), token=b["token"])
        try:
            data = json.loads(raw)["data"]
            owner = data["UserId"]
            marker = "B04-private-negative-control-b"
            event["expected_object_sha256"] = state["objects"]["negative-control-b"]["baseline_sha256"]
            if (type(owner) is int and owner > 0 and data.get("id") == object_id
                    and data.get("fullName") == marker and data.get("streetAddress") == marker):
                event.update(owner_id=owner, object_sha256=digest({
                    "owner": "role-b", "kind": "address", "marker": marker,
                    "city": data.get("city"), "zipCode": data.get("zipCode"), "country": data.get("country")}))
        except (ValueError, TypeError, KeyError):
            pass
        self.identity("other_identity_after", b, b["token"])

    def redirect(self):
        counter = {"requests": 0}

        class Sink(BaseHTTPRequestHandler):
            def do_GET(self):
                counter["requests"] += 1
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("0.0.0.0", 18080), Sink)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for operation, destination in (("positive_redirect", APPROVED),
                                            ("negative_redirect", NEGATIVE), ("probe_redirect", PROBE)):
                event, _ = self.request(operation, "GET", "/redirect?" + urlencode({"to": destination}))
                if ((operation == "positive_redirect" and (
                        event["status_code"] not in {301, 302, 303, 307, 308} or event.get("location") != "approved"))
                        or (operation == "negative_redirect" and (
                            event["status_code"] != 406 or event.get("location") != "none"))):
                    raise Failure("control_failed")
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        return counter["requests"]


def main():
    if os.getenv("CFT_B06_CONTAINER") != "1" or not Path("/.dockerenv").is_file():
        raise RuntimeError("B06 worker requires Docker")
    config = json.loads(Path("/input/profile.json").read_text())
    operation = sys.argv[1] if len(sys.argv) == 2 else "invalid"

    def expired(*args):
        raise Failure("timeout")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(120 if operation == "prepare" else 20)
    protocol = Protocol()
    error, sink_requests = "none", 0
    try:
        if operation == "prepare":
            result = prepare(config)
        else:
            if operation == "auth":
                protocol.auth(config)
            elif operation == "redirect":
                sink_requests = protocol.redirect()
            else:
                raise Failure("technical_failure")
            result = None
    except Failure as exc:
        error, result = str(exc), None
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError):
        error, result = "technical_failure", None
    finally:
        signal.alarm(0)
    if result is None:
        result = {"generation": config["generation"], "exchanges": protocol.ledger,
                  "http_exchanges": len(protocol.ledger), "setup_http_exchanges": 0,
                  "sink_requests": sink_requests, "redirect_followed": False, "destination_dns": False,
                  "cleanup_complete": False, "error": error}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if error == "none" else 2


if __name__ == "__main__":
    raise SystemExit(main())
