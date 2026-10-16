#!/usr/bin/env python3
"""Opt-in local live interop: Hopae (groups + lifecycle owner) <-> Pumgye policy v2.

Runs a real Hopae binary and a real Pumgye binary as loopback processes and
checks that Pumgye consumes Hopae's signed membership projection and subject
lifecycle feed:

  1. group-based allow (Hopae local group -> v2 group binding);
  2. explicit deny precedence over a group allow;
  3. staleness fail-closed when Hopae becomes unreachable, and recovery;
  4. disable -> subject_disabled, store deletion -> orphaned binding;
  5. 410 cursor_expired recovery after the projection journal is pruned.

No cluster or OIDC provider is needed. People are laid down in Hopae's store
with SQL exactly as Hopae's own scenario tests do (sign-in is out of scope);
every group, membership and disable operation goes through Hopae's real admin
API. Pumgye reaches Hopae's admin listener through a loopback mTLS relay that
holds the delegation key and admits only the four read routes Pumgye needs —
the shape of the dedicated read-only, route-scoped credential documented in
docs/MODEL_V2.md (Hopae has no such service credential yet).

Requires: Python 3.11+, the `cryptography` package, `openssl` is not needed.

  python3 tools/hopae_v2_interop.py --hopae ~/hopae-target/debug/hopae \
      --pumgye target/debug/pumgye [--workdir DIR] [--keep]

Exit status 0 when every check passes. Nothing is installed or deployed.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import http.client
import http.server
import json
import os
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

ADMIN_TOKEN = "interop-admin-credential-0123456789"
DECISION_TOKEN = "interop-decision-credential-0123456789"
DELEGATION_KEY = "interop-delegation-key-" + "k" * 24
GATEWAY_KEY = "interop-gateway-caller-key-0123456789abcdef"
PUMGYE_ROUTES = {
    "/v1/groups/projection/snapshot",
    "/v1/groups/projection/changes",
    "/v1/subjects/lifecycle",
    "/v1/subjects/lifecycle/snapshot",
}
CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail and not ok else ""), flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def ed25519_pair() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64(seed), b64(public)


def write_pki(directory: str) -> dict[str, str]:
    """A throwaway CA, a relay server certificate and a Pumgye client certificate."""
    now = datetime.datetime.now(datetime.timezone.utc)

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder().subject_name(name("interop-ca")).issuer_name(name("interop-ca"))
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    out = {}

    def leaf(cn: str, server: bool) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                critical=False,
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        for suffix, data in (
            ("pem", cert.public_bytes(serialization.Encoding.PEM)),
            ("key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        ):
            path = os.path.join(directory, f"{cn}.{suffix}")
            with open(path, "wb") as f:
                f.write(data)
            os.chmod(path, 0o600)
            out[f"{cn}.{suffix}"] = path

    leaf("relay", True)
    leaf("pumgye", False)
    path = os.path.join(directory, "ca.pem")
    with open(path, "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    out["ca.pem"] = path
    return out


def sign_delegation(method: str, path: str, body: bytes) -> dict[str, str]:
    assertion = {
        "authority": "hangang",
        "actor_id": 7,
        "actor_name": "pumgye-interop",
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(16),
        "method": method,
        "path": path,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "handle_sha256": hashlib.sha256(b"").hexdigest(),
        "client_ip": "127.0.0.1",
        "user_agent": None,
    }
    raw = json.dumps(assertion, separators=(",", ":")).encode()
    mac = hmac.new(DELEGATION_KEY.encode(), raw, hashlib.sha256).digest()
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    return {"x-hopae-delegation": enc(raw), "x-hopae-delegation-mac": enc(mac)}


def hopae_admin(port: int, path: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", path, data, {"content-type": "application/json", **sign_delegation("POST", path, data)})
    r = conn.getresponse()
    text = r.read()
    try:
        return r.status, json.loads(text or b"{}")
    except json.JSONDecodeError:
        return r.status, {"raw": text.decode(errors="replace")}


class Relay:
    """Loopback mTLS relay: Pumgye's scoped read-only path to Hopae's admin API."""

    def __init__(self, pki: dict[str, str], hopae_admin_port: int):
        self.port = free_port()
        self.statuses: list[tuple[str, int]] = []
        self.blocked = False
        relay = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length)
                if relay.blocked or self.path not in PUMGYE_ROUTES:
                    self.send_response(503 if relay.blocked else 403)
                    self.end_headers()
                    return
                conn = http.client.HTTPConnection("127.0.0.1", hopae_admin_port, timeout=10)
                conn.request("POST", self.path, body, {"content-type": "application/json", **sign_delegation("POST", self.path, body)})
                r = conn.getresponse()
                data = r.read()
                relay.statuses.append((self.path, r.status))
                self.send_response(r.status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(pki["relay.pem"], pki["relay.key"])
        context.load_verify_locations(pki["ca.pem"])
        context.verify_mode = ssl.CERT_REQUIRED
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def pumgye(port: int, method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method)
    req.add_header("authorization", f"Bearer {ADMIN_TOKEN}")
    if data is not None:
        req.add_header("content-type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        text = e.read()
        try:
            return e.code, json.loads(text or b"{}")
        except json.JSONDecodeError:
            return e.code, {}


def wait(what: str, predicate, timeout: float = 60.0, interval: float = 0.5):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(interval)
    raise TimeoutError(f"{what}: {last}")


def hopae_config(work: str, ports: dict[str, int], projection_public: str, receipt_public: str, pki: dict[str, str]) -> dict:
    return {
        "listen": {"portal": f"127.0.0.1:{ports['portal']}", "gateway": f"127.0.0.1:{ports['gateway']}", "admin": f"127.0.0.1:{ports['admin']}",
                   # Human subjects need the native receipt issuer, which requires mTLS gRPC.
                   "grpc_gateway": f"127.0.0.1:{ports['grpc']}",
                   "native_gateway_tls": {"certificate": pki["relay.pem"], "key": pki["relay.key"], "client_ca": pki["ca.pem"]}},
        "state_dir": os.path.join(work, "hopae-state"),
        "portal": {"public_url": "http://auth.interop.test"},
        "gateway": {"kind": "hangang", "caller_key_env": "INTEROP_GATEWAY_KEY", "verify_budget_ms": 400},
        "session": {"idle": "24h", "absolute": "30d"},
        "cookie": {"name": "hopae", "secure": False},
        "apps": [
            {"app_id": "orders", "display_name": "orders", "hosts": ["orders.interop.test"], "ports": [80],
             "session": {"idle": "12h", "absolute": "7d"}, "on_authz_change": "refresh", "verify_cache_seconds": 0},
            {"app_id": "default", "display_name": "default"},
        ],
        "providers": [{"provider_id": "mock", "kind": "oidc", "display_name": "Mock", "client_id": "interop",
                       "client_secret_env": "INTEROP_MOCK_SECRET", "issuer": "http://127.0.0.1:9",
                       "allow_private_endpoints": True, "scope": "openid email profile", "auto_link": False}],
        "trusted_proxies": ["127.0.0.1/32"],
        "admin": {"public_url": "http://hopae-admin.interop.test",
                  "hangang_delegation": {"authority": "hangang", "key_env": "INTEROP_DELEGATION_KEY"}},
        "groups": {"maintenance_interval_secs": 60,
                   "projection": {"issuer_ref": "hopae-groups", "key_epoch": 1, "public_key": projection_public,
                                  "seed_env": "INTEROP_PROJECTION_SEED", "audience": "pumgye"}},
        "receipt_issuer": {
            "issuer_ref": "hopae-interop", "key_epoch": 1, "identity_authority_epoch": "interop-human",
            "public_key": receipt_public, "seed_env": "INTEROP_RECEIPT_SEED",
            "scopes": [{"service": "orders", "audience": "orders-api"}],
            "human_receipts": {"source_revision": 1, "scopes": [{
                "service": "orders", "audience": "orders-api", "application": "orders", "route": "orders-route",
                "route_revision": 1, "destination_sha256": "12" * 32, "header_revision": 1, "headers": [],
                "reserved_headers": [], "maximum_entity_bytes": 1048576}]},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hopae", required=True)
    parser.add_argument("--pumgye", required=True)
    parser.add_argument("--workdir")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    work = args.workdir or tempfile.mkdtemp(prefix="pumgye-hopae-interop-", dir=os.path.expanduser("~"))
    os.makedirs(work, exist_ok=True)
    os.chmod(work, 0o700)
    procs: list[subprocess.Popen] = []
    try:
        return run(args, work, procs)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


def run(args, work: str, procs: list) -> int:
    pki = write_pki(work)
    projection_seed, projection_public = ed25519_pair()
    receipt_seed, receipt_public = ed25519_pair()
    ports = {"portal": free_port(), "gateway": free_port(), "admin": free_port(), "grpc": free_port(), "pumgye": free_port()}
    config = os.path.join(work, "hopae.json")
    with open(config, "w") as f:
        json.dump(hopae_config(work, ports, projection_public, receipt_public, pki), f)
    env = dict(os.environ, INTEROP_GATEWAY_KEY=GATEWAY_KEY, INTEROP_DELEGATION_KEY=DELEGATION_KEY,
               INTEROP_PROJECTION_SEED=projection_seed, INTEROP_RECEIPT_SEED=receipt_seed,
               INTEROP_MOCK_SECRET="interop-mock-secret-0123456789")
    hopae_log = open(os.path.join(work, "hopae.log"), "w")
    procs.append(subprocess.Popen([args.hopae, "--config", config], env=env, stdout=hopae_log, stderr=subprocess.STDOUT))
    wait("hopae admin listener", lambda: socket.create_connection(("127.0.0.1", ports["admin"]), timeout=1).close() or True)

    # People: laid down in the store as Hopae's scenario tests do (no sign-in).
    db = os.path.join(work, "hopae-state", "hopae.db")
    now = int(time.time())
    with sqlite3.connect(db, timeout=5) as sql:
        for uid, name in (("u_alice", "Alice"), ("u_bob", "Bob"), ("u_carol", "Carol"), ("u_dave", "Dave")):
            sql.execute("INSERT INTO users (user_id, primary_email, email_verified, display_name, status, created_at, updated_at) VALUES (?,?,1,?,'active',?,?)",
                        (uid, f"{uid[2:]}@interop.test", name, now, now))

    # Human subjects come from Hopae (lifecycle snapshot), never computed by Pumgye.
    status, snap = hopae_admin(ports["admin"], "/v1/subjects/lifecycle/snapshot", {"cursor": None, "limit": 200})
    check("hopae lifecycle snapshot answers through delegation", status == 200, f"{status} {snap}")
    subjects = {item["user_id"]: item["human_subject"] for item in snap.get("items", [])}
    check("human subjects are configured", all(str(subjects.get(u, "")).startswith("human1:") for u in ("u_alice", "u_bob", "u_carol", "u_dave")), str(subjects))
    alice, bob, carol, dave = (subjects[u] for u in ("u_alice", "u_bob", "u_carol", "u_dave"))

    # Groups through the real admin API.
    status, created = hopae_admin(ports["admin"], "/v1/groups/create", {"key": "eng.orders", "name": "Orders engineers", "reason": "interop"})
    check("group created", status == 201, f"{status} {created}")
    group = created["group"]
    for user in ("u_alice", "u_bob"):
        status, out = hopae_admin(ports["admin"], "/v1/groups/members/add",
                                  {"group_id": group["group_id"], "expected_revision": group["revision"], "user_id": user, "reason": "interop"})
        check(f"member {user} added", status == 200, f"{status} {out}")
        group = out.get("group", group)

    # Pumgye with the Hopae owner pointed at the relay.
    relay = Relay(pki, ports["admin"])
    owner = os.path.join(work, "owner.json")
    with open(owner, "w") as f:
        json.dump({"address": f"https://127.0.0.1:{relay.port}", "ca": pki["ca.pem"], "certificate": pki["pumgye.pem"], "key": pki["pumgye.key"],
                   "projection": {"audience": "pumgye", "keys": [{"issuer_ref": "hopae-groups", "key_epoch": 1, "public_key": projection_public}],
                                  "max_age_secs": 60, "max_staleness_secs": 6, "poll_interval_secs": 2},
                   "lifecycle": {"poll_interval_secs": 2, "reconcile_interval_secs": 4}}, f)
    v1 = os.path.join(work, "policy-v1.json")
    with open(v1, "w") as f:
        json.dump({"revision": 0, "policy": {"version": 1, "information_classes": ["public"], "services": {}}}, f)
    pumgye_log = open(os.path.join(work, "pumgye.log"), "w")
    procs.append(subprocess.Popen([args.pumgye, "--listen", f"127.0.0.1:{ports['pumgye']}", "--database", os.path.join(work, "pumgye.sqlite3"),
                                   "--policy", v1, "--hopae-owner", owner, "--shadow-window-days", "1"],
                                  env=dict(os.environ, PUMGYE_ADMIN_TOKEN=ADMIN_TOKEN, PUMGYE_DECISION_TOKEN=DECISION_TOKEN),
                                  stdout=pumgye_log, stderr=subprocess.STDOUT))
    wait("pumgye lifecycle complete", lambda: pumgye(ports["pumgye"], "GET", "/v2/status")[1].get("lifecycle", {}) and
         pumgye(ports["pumgye"], "GET", "/v2/status")[1]["lifecycle"]["complete"])

    gid = group["group_id"]
    document = {
        "version": 2,
        "catalog": {"levels": ["public", "internal"], "resources": {}},
        "zones": {"zones": {"loopback": {"prefixes": ["127.0.0.0/8"]}}},
        "templates": {"writer": {"permissions": ["read", "write"], "clearance_ceiling": {"level": "internal"}, "minimum_aal": 1}},
        "services": {"orders": {"permissions": ["read", "write"], "network_ceiling": [{"zone": "loopback", "max": "writer"}]}},
        "bindings": [
            {"id": "bnd_group_writers", "effect": "allow", "subjects": [{"group": gid}], "role": "writer", "scope": {"services": ["orders"]},
             "metadata": {"reason": "interop group grant"}},
            {"id": "bnd_freeze_bob", "effect": "deny", "subjects": [{"kind": "human", "ref": bob}], "permissions": ["write"],
             "scope": {"services": ["orders"]}, "metadata": {"reason": "interop deny precedence"}},
            {"id": "bnd_carol_direct", "effect": "allow", "subjects": [{"kind": "human", "ref": carol}], "role": "writer",
             "scope": {"services": ["orders"]}, "metadata": {"reason": "interop direct grant"}},
            {"id": "bnd_dave_direct", "effect": "allow", "subjects": [{"kind": "human", "ref": dave}], "role": "writer",
             "scope": {"services": ["orders"]}, "metadata": {"reason": "interop orphan"}},
        ],
    }
    status, published = pumgye(ports["pumgye"], "PUT", "/v2/policy", {"revision": 0, "policy": document}, {"if-match": '"0"'})
    check("v2 document published (refs resolved against the lifecycle)", status == 200, f"{status} {published}")

    def explain(subject: str, permission: str) -> dict:
        case = {"subject": {"kind": "human", "id": subject}, "service": "orders", "permission": permission,
                "information_class": "internal", "ip": "127.0.0.1", "aal": 1, "guard": "enforced_allow"}
        return pumgye(ports["pumgye"], "POST", "/v2/explain", {"case": case, "trace": True})[1]["result"]

    wait("membership projection fresh", lambda: pumgye(ports["pumgye"], "GET", "/v2/status")[1]["v2"]["membership"]["fresh"])
    r = explain(alice, "write")
    groups = next((s["detail"]["groups"] for s in r.get("trace", []) if s["stage"] == "principal"), None)
    check("group-based allow from the signed projection", r["outcome"]["decision"] == "Allow" and groups == [gid], json.dumps(r["outcome"]))
    r = explain(bob, "write")
    check("explicit deny overrides the group allow", r["outcome"]["decision"] == "ExplicitDenied", json.dumps(r["outcome"]))
    check("deny does not leak to other permissions", explain(bob, "read")["outcome"]["decision"] == "Allow")
    check("no binding, no rights", explain(subjects["u_carol"], "write")["outcome"]["decision"] == "Allow" and
          pumgye(ports["pumgye"], "POST", "/v2/explain", {"case": {"subject": {"kind": "human", "id": "human1:" + "f" * 64}, "service": "orders",
                 "permission": "read", "information_class": "public", "ip": "127.0.0.1", "aal": 1, "guard": "enforced_allow"}})[1]["result"]["outcome"]["decision"] == "Guest")
    statuses = {p for p, _ in relay.statuses}
    check("Pumgye used only the scoped read routes", statuses <= PUMGYE_ROUTES and "/v1/groups/projection/snapshot" in statuses, str(statuses))

    # Membership removal propagates through the feed.
    status, out = hopae_admin(ports["admin"], "/v1/groups/members/remove",
                              {"group_id": gid, "expected_revision": group["revision"], "user_id": "u_alice", "reason": "interop"})
    group = out.get("group", group)
    check("member removed in Hopae", status == 200, f"{status} {out}")
    wait("removal applied", lambda: explain(alice, "write")["outcome"]["decision"] == "Guest", timeout=30)
    check("feed removal revokes the group grant", True)

    # Staleness: Hopae unreachable -> fail closed after max_staleness_secs; recovery after.
    relay.blocked = True
    wait("stale projection fails closed", lambda: explain(bob, "read")["outcome"]["detail_code"] == "pumgye.detail.membership_unavailable", timeout=30)
    check("stale projection fails closed (decision unavailable)", True)
    relay.blocked = False
    wait("projection recovers", lambda: explain(bob, "read")["outcome"]["decision"] == "Allow", timeout=30)
    check("projection recovers after Hopae returns", True)

    # Lifecycle: disable -> subject_disabled; deletion from the store -> orphaned.
    status, out = hopae_admin(ports["admin"], "/v1/users/disable", {"id": "u_carol"})
    check("user disabled in Hopae", status in (200, 204), f"{status} {out}")
    wait("disabled subject reconciled", lambda: "bnd_carol_direct" in (pumgye(ports["pumgye"], "GET", "/v2/status")[1]["v2"]["subject_disabled_bindings"] or []), timeout=30)
    check("disabled principal marked subject_disabled (no rights change)", explain(carol, "write")["outcome"]["decision"] == "Allow")
    with sqlite3.connect(db, timeout=5) as sql:
        sql.execute("DELETE FROM users WHERE user_id='u_dave'")
    wait("deleted subject orphaned", lambda: "bnd_dave_direct" in (pumgye(ports["pumgye"], "GET", "/v2/status")[1]["v2"]["orphaned_bindings"] or []), timeout=30)
    check("deleted principal's binding is orphaned and grants nothing", explain(dave, "write")["outcome"]["decision"] == "Guest")
    status, _ = pumgye(ports["pumgye"], "PUT", "/v2/policy", {"revision": published.get("revision", 0), "policy": dict(document, bindings=document["bindings"] + [
        {"id": "bnd_dave_again", "effect": "allow", "subjects": [{"kind": "human", "ref": dave}], "role": "writer", "scope": {"services": ["orders"]},
         "metadata": {"reason": "must be refused"}}])}, {"if-match": f'"{published.get("revision", 0)}"'})
    check("new binding to a deleted principal is refused", status == 422, str(status))

    # 410 cursor_expired: prune the projection journal behind Pumgye's cursor.
    before = pumgye(ports["pumgye"], "GET", "/v2/status")[1]["projection"]["cursor"]
    relay.blocked = True
    for user in ("u_alice",):
        status, out = hopae_admin(ports["admin"], "/v1/groups/members/add",
                                  {"group_id": gid, "expected_revision": group["revision"], "user_id": user, "reason": "interop"})
        group = out.get("group", group)
    status, out = hopae_admin(ports["admin"], "/v1/groups/members/remove",
                              {"group_id": gid, "expected_revision": group["revision"], "user_id": "u_bob", "reason": "interop"})
    group = out.get("group", group)
    # Keep only the newest journal row: Pumgye's cursor now lies before the oldest
    # retained revision with a gap (Hopae answers 410 cursor_expired).
    with sqlite3.connect(db, timeout=5) as sql:
        newest = sql.execute("SELECT max(revision) FROM group_changes").fetchone()[0]
        sql.execute("DELETE FROM group_changes WHERE revision < ?", (newest,))
    relay.blocked = False
    wait("resnapshot after 410", lambda: any(s == 410 for _, s in relay.statuses), timeout=30)
    wait("state converged after 410", lambda: explain(alice, "write")["outcome"]["decision"] == "Allow" and explain(bob, "read")["outcome"]["decision"] == "Guest", timeout=30)
    after = pumgye(ports["pumgye"], "GET", "/v2/status")[1]["projection"]["cursor"]
    check("410 cursor_expired triggers a resnapshot and converges", before != after, f"{before} -> {after}")

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed; logs in {work}" + ("" if args.keep else " (removed)"))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TimeoutError as exc:
        print(f"FAIL timeout: {exc}")
        sys.exit(1)
