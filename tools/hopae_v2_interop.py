#!/usr/bin/env python3
"""Opt-in local live interop: Hopae (groups + lifecycle owner) <-> Pumgye policy v2.

Runs a real Hopae binary and a real Pumgye binary as loopback processes and
checks that Pumgye consumes Hopae's signed membership projection and subject
lifecycle feed:

  1. group-based allow (Hopae local group -> v2 group binding);
  2. explicit deny precedence over a group allow;
  3. staleness fail-closed when Hopae becomes unreachable, and recovery;
  4. disable -> subject_disabled, store deletion -> orphaned binding;
  5. 410 cursor_expired recovery after the projection journal is pruned;
  6. Kubernetes workload principals (Hopae `kubernetes_workload`, offline JWKS):
     a ServiceAccount token authenticated by Hopae's gateway verify endpoint
     surfaces as `workload_observed` in the lifecycle feed, and Pumgye's v2
     bindings by `wk2:` principal and by SPIFFE ID apply to the wire subject.
     Needs a Hopae with workload identity (`feat/k8s-workload-identity`);
     skip with --skip-workloads for older builds.

No cluster or OIDC provider is needed. People are laid down in Hopae's store
with SQL exactly as Hopae's own scenario tests do (sign-in is out of scope);
every group, membership and disable operation goes through Hopae's real admin
API (the tool signs them with Hopae's unified delegation key over the admin
mTLS listener). Pumgye calls Hopae's admin mTLS listener **directly** with a
route-scoped, read-only Hopae service credential (`hsc1.…`, preset
`pumgye-v2`, pinned to Pumgye's client certificate, `x-hopae-audience`),
minted by `hopae admin service-credentials create`. A transparent TCP fault
injector in front of the listener (TLS passes through end to end) simulates
Hopae outages for the staleness and cursor-expiry checks.

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

WORKLOAD_ISSUER = "https://kubernetes.default.svc.cluster.local"
WORKLOAD_AUDIENCE = "world.hangang.dev/interop-cluster"
WORKLOAD_HOST = "wl.interop.test"
SPIFFE = "spiffe://cluster.interop.test/ns/blue/sa/worker"
ADMIN_HOST = "hopae-admin.interop.test"
SERVICE_AUDIENCE = "hopae-interop"
ADMIN_TOKEN = "interop-admin-credential-0123456789"
DECISION_TOKEN = "interop-decision-credential-0123456789"
DELEGATION_KEY = "interop-delegation-key-" + "k" * 24
GATEWAY_KEY = "interop-gateway-caller-key-0123456789abcdef"
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
    """A throwaway CA, server certificates (Hopae admin, gRPC) and client certificates."""
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

    def leaf(cn: str, server: bool, dns: str = "localhost") -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(dns), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                critical=False,
            )
        cert = builder.sign(ca_key, hashes.SHA256())
        out[f"{cn}.spki"] = hashlib.sha256(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        for suffix, data in (
            ("pem", cert.public_bytes(serialization.Encoding.PEM)),
            ("key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        ):
            path = os.path.join(directory, f"{cn}.{suffix}")
            with open(path, "wb") as f:
                f.write(data)
            os.chmod(path, 0o600)
            out[f"{cn}.{suffix}"] = path

    leaf("gateway", True)
    leaf("hopae-admin", True, ADMIN_HOST)
    leaf("pumgye", False)
    leaf("operator", False)
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


ADMIN: dict = {}


def admin_request(path: str, body: dict, headers: dict, cert: str, key: str) -> tuple[int, dict]:
    """POST to Hopae's admin mTLS listener (the Host is the console host)."""
    context = ssl.create_default_context(cafile=ADMIN["ca"])
    context.check_hostname = False
    context.load_cert_chain(cert, key)
    data = json.dumps(body).encode()
    conn = http.client.HTTPSConnection("127.0.0.1", ADMIN["port"], timeout=10, context=context)
    conn.request("POST", path, data, {"host": ADMIN["host"], "content-type": "application/json", **headers})
    r = conn.getresponse()
    text = r.read()
    try:
        return r.status, json.loads(text or b"{}")
    except json.JSONDecodeError:
        return r.status, {"raw": text.decode(errors="replace")}


def hopae_admin(_port: int, path: str, body: dict) -> tuple[int, dict]:
    """Operator calls: unified delegation over the admin mTLS listener."""
    data = json.dumps(body).encode()
    return admin_request(path, body, sign_delegation("POST", path, data), ADMIN["operator.pem"], ADMIN["operator.key"])


class FaultProxy:
    """Transparent TCP forwarder (TLS passes through); `block` drops all traffic."""

    def __init__(self, target: int, port: int):
        self.port = port
        self.blocked = False
        self.target = target
        self.conns: list[socket.socket] = []
        self.listener = socket.create_server(("127.0.0.1", self.port))
        threading.Thread(target=self._accept, daemon=True).start()

    def block(self, on: bool) -> None:
        self.blocked = on
        if on:
            for c in self.conns:
                try:
                    c.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self.conns.clear()

    def _accept(self) -> None:
        while True:
            client, _ = self.listener.accept()
            if self.blocked:
                client.close()
                continue
            upstream = socket.create_connection(("127.0.0.1", self.target))
            self.conns += [client, upstream]
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        finally:
            for x in (a, b):
                try:
                    x.close()
                except OSError:
                    pass


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


def workload_key() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    enc = lambda n: base64.urlsafe_b64encode(n.to_bytes(32, "big")).decode().rstrip("=")  # noqa: E731
    jwks = json.dumps({"keys": [{"use": "sig", "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "k1", "x": enc(nums.x), "y": enc(nums.y)}]})
    return key, jwks


def mint_serviceaccount_token(key: ec.EllipticCurvePrivateKey, pod: str, pod_uid: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    now = int(time.time())
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    header = enc(json.dumps({"alg": "ES256", "kid": "k1", "typ": "JWT"}).encode())
    claims = enc(json.dumps({
        "iss": WORKLOAD_ISSUER, "sub": "system:serviceaccount:blue:worker", "aud": [WORKLOAD_AUDIENCE],
        "exp": now + 600, "iat": now, "nbf": now,
        "kubernetes.io": {"namespace": "blue", "serviceaccount": {"name": "worker", "uid": "sa-uid-1"},
                          "pod": {"name": pod, "uid": pod_uid}}}).encode())
    r, s_ = decode_dss_signature(key.sign(f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{header}.{claims}.{enc(r.to_bytes(32, 'big') + s_.to_bytes(32, 'big'))}"


def gateway_verify(port: int, token: str) -> tuple[int, dict[str, str]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/_hopae/verify", headers={
        "host": WORKLOAD_HOST, "x-original-url": f"https://{WORKLOAD_HOST}/x", "x-forwarded-host": WORKLOAD_HOST,
        "x-forwarded-proto": "https", "x-forwarded-port": "443", "x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1",
        "x-original-method": "GET", "sec-fetch-dest": "empty", "accept": "application/json",
        "x-hopae-gateway-key": GATEWAY_KEY, "authorization": f"Bearer k8s:{token}"})
    r = conn.getresponse()
    r.read()
    return r.status, {k.lower(): v for k, v in r.getheaders()}


def hopae_config(work: str, ports: dict[str, int], projection_public: str, receipt_public: str, pki: dict[str, str], workloads: bool) -> dict:
    config = {
        "listen": {"portal": f"127.0.0.1:{ports['portal']}", "gateway": f"127.0.0.1:{ports['gateway']}", "admin": f"127.0.0.1:{ports['admin']}",
                   # Human subjects need the native receipt issuer, which requires mTLS gRPC.
                   "grpc_gateway": f"127.0.0.1:{ports['grpc']}",
                   "native_gateway_tls": {"certificate": pki["gateway.pem"], "key": pki["gateway.key"], "client_ca": pki["ca.pem"]},
                   # Service credentials require the admin listener's mutual TLS.
                   "admin_tls": {"certificate": pki["hopae-admin.pem"], "key": pki["hopae-admin.key"], "client_ca": pki["ca.pem"]}},
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
        # The externally visible console origin is the fault-injection front.
        "admin": {"public_url": f"https://{ADMIN_HOST}:{ports['front']}", "service_audience": SERVICE_AUDIENCE,
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
    if workloads:
        config["apps"].append({"app_id": "wl", "display_name": "wl", "hosts": [WORKLOAD_HOST], "ports": [443]})
        config["authentication_gateway"] = {"authority_id": "interop", "profiles": [{
            "service_id": "wl", "host": WORKLOAD_HOST, "ports": [443], "realm": "interop-cluster", "networks": ["127.0.0.0/8"],
            "kubernetes_workload": {"issuer": WORKLOAD_ISSUER, "cluster_id": "interop-cluster", "trust_domain": "cluster.interop.test",
                                    "audience": WORKLOAD_AUDIENCE, "namespaces": ["blue"],
                                    "keys": {"source": "static", "jwks_env": "INTEROP_WORKLOAD_JWKS"}, "token_prefix": "k8s:"}}]}
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hopae", required=True)
    parser.add_argument("--pumgye", required=True)
    parser.add_argument("--workdir")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--skip-workloads", action="store_true", help="Hopae without kubernetes_workload support")
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
    ports = {"portal": free_port(), "gateway": free_port(), "admin": free_port(), "grpc": free_port(), "pumgye": free_port(), "front": free_port()}
    ADMIN.update({"ca": pki["ca.pem"], "port": ports["admin"], "host": f"{ADMIN_HOST}:{ports['front']}",
                  "operator.pem": pki["operator.pem"], "operator.key": pki["operator.key"]})
    config = os.path.join(work, "hopae.json")
    workloads = not args.skip_workloads
    wl_key, wl_jwks = workload_key()
    with open(config, "w") as f:
        json.dump(hopae_config(work, ports, projection_public, receipt_public, pki, workloads), f)
    env = dict(os.environ, INTEROP_GATEWAY_KEY=GATEWAY_KEY, INTEROP_DELEGATION_KEY=DELEGATION_KEY, INTEROP_WORKLOAD_JWKS=wl_jwks,
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

    # A route-scoped, read-only service credential pinned to Pumgye's certificate.
    minted = subprocess.run([args.hopae, "admin", "service-credentials", "create", "pumgye-v2", "--preset", "pumgye-v2",
                             "--client-spki-sha256", pki["pumgye.spki"], "--audience", SERVICE_AUDIENCE,
                             "--rate-per-minute", "6000", "--burst", "1000", "--note", "interop", "--config", config],
                            env=env, capture_output=True, text=True, timeout=60)
    token = next((w for w in minted.stdout.split() if w.startswith("hsc1.")), "")
    check("service credential minted by the Hopae CLI", minted.returncode == 0 and bool(token), minted.stderr[-400:])
    token_file = os.path.join(work, "hopae-service-token")
    with open(token_file, "w") as f:
        f.write(token + "\n")
    os.chmod(token_file, 0o600)
    service = lambda aud=SERVICE_AUDIENCE: {"authorization": f"Bearer {token}", "x-hopae-audience": aud, "x-hopae-admin-request": "1"}  # noqa: E731
    status, out = admin_request("/v1/groups/create", {"key": "x", "name": "x", "reason": "x"}, service(), pki["pumgye.pem"], pki["pumgye.key"])
    check("service credential cannot reach a write route", status == 403 and "service_route_forbidden" in json.dumps(out), f"{status} {out}")
    status, out = admin_request("/v1/subjects/lifecycle", {"cursor": None, "limit": 1}, service(), pki["operator.pem"], pki["operator.key"])
    check("service credential is bound to Pumgye's certificate", status == 403 and "service_binding_mismatch" in json.dumps(out), f"{status} {out}")
    status, out = admin_request("/v1/subjects/lifecycle", {"cursor": None, "limit": 1}, service("other"), pki["pumgye.pem"], pki["pumgye.key"])
    check("service credential is bound to the audience", status == 403 and "service_audience_mismatch" in json.dumps(out), f"{status} {out}")

    # Pumgye calls Hopae's admin mTLS listener directly, through a transparent fault injector.
    front = FaultProxy(ports["admin"], ports["front"])
    owner = os.path.join(work, "owner.json")
    with open(owner, "w") as f:
        json.dump({"address": f"https://{ADMIN_HOST}:{ports['front']}", "connect_address": f"127.0.0.1:{ports['front']}",
                   "token_file": token_file, "audience": SERVICE_AUDIENCE,
                   "ca": pki["ca.pem"], "certificate": pki["pumgye.pem"], "key": pki["pumgye.key"],
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

    # Membership removal propagates through the feed.
    status, out = hopae_admin(ports["admin"], "/v1/groups/members/remove",
                              {"group_id": gid, "expected_revision": group["revision"], "user_id": "u_alice", "reason": "interop"})
    group = out.get("group", group)
    check("member removed in Hopae", status == 200, f"{status} {out}")
    wait("removal applied", lambda: explain(alice, "write")["outcome"]["decision"] == "Guest", timeout=30)
    check("feed removal revokes the group grant", True)

    # Staleness: Hopae unreachable -> fail closed after max_staleness_secs; recovery after.
    front.block(True)
    wait("stale projection fails closed", lambda: explain(bob, "read")["outcome"]["detail_code"] == "pumgye.detail.membership_unavailable", timeout=30)
    check("stale projection fails closed (decision unavailable)", True)
    front.block(False)
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
    front.block(True)
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
    front.block(False)
    wait("state converged after 410", lambda: explain(alice, "write")["outcome"]["decision"] == "Allow" and explain(bob, "read")["outcome"]["decision"] == "Guest", timeout=30)
    after = pumgye(ports["pumgye"], "GET", "/v2/status")[1]["projection"]["cursor"]
    check("410 cursor_expired triggers a resnapshot and converges", before != after, f"{before} -> {after}")

    if workloads:
        run_workloads(ports, wl_key, published_revision=pumgye(ports["pumgye"], "GET", "/v2/status")[1]["v2"]["revision"])

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed; logs in {work}" + ("" if args.keep else " (removed)"))
    return 1 if failed else 0


def run_workloads(ports: dict[str, int], key, published_revision: int) -> None:
    # Two Pods of one ServiceAccount (a rollout) authenticate as one principal.
    status, first = gateway_verify(ports["gateway"], mint_serviceaccount_token(key, "worker-a", "pod-uid-1"))
    check("workload token verified offline by Hopae", status == 200 and first.get("x-hopae-principal", "").startswith("wk2:"), f"{status} {first}")
    if status != 200:
        return
    wire, principal = first["x-forwarded-user"], first["x-hopae-principal"]
    check("SPIFFE ID reported", first.get("x-hopae-workload-spiffe-id") == SPIFFE, str(first))
    status, rolled = gateway_verify(ports["gateway"], mint_serviceaccount_token(key, "worker-b", "pod-uid-2"))
    check("rollout keeps the principal", status == 200 and rolled.get("x-hopae-principal") == principal and rolled.get("x-forwarded-user") == wire)
    wait("workload_observed reaches Pumgye", lambda: any(p["principal"] == principal and p["status"] == "active"
         for p in pumgye(ports["pumgye"], "GET", "/v2/workloads")[1]["principals"]), timeout=30)
    check("workload principal consumed from the lifecycle feed", True)
    _, current = pumgye(ports["pumgye"], "GET", "/v2/policy")
    policy = current["policy"]
    policy["bindings"] = policy["bindings"] + [
        {"id": "bnd_wk2_reader", "effect": "allow", "subjects": [{"kind": "workload", "ref": principal}],
         "role": "writer", "scope": {"services": ["orders"]}, "metadata": {"reason": "interop workload pin"}},
        {"id": "bnd_spiffe_deny", "effect": "deny", "subjects": [{"kind": "workload", "ref": SPIFFE}],
         "permissions": ["write"], "scope": {"services": ["orders"]}, "metadata": {"reason": "interop name deny"}},
    ]
    for b in policy["bindings"]:
        b.get("metadata", {}).pop("granted_by", None)
    # Machines present AAL0.
    policy["templates"]["writer"]["minimum_aal"] = 0
    status, out = pumgye(ports["pumgye"], "PUT", "/v2/policy", {"revision": published_revision, "policy": policy}, {"if-match": f'"{published_revision}"'})
    check("v2 bindings by wk2 principal and SPIFFE ID published", status == 200, f"{status} {out}")

    def explain(subject: str, permission: str) -> dict:
        case = {"subject": {"kind": "workload", "id": subject}, "service": "orders", "permission": permission,
                "information_class": "internal", "ip": "127.0.0.1", "aal": 0, "guard": "enforced_allow"}
        return pumgye(ports["pumgye"], "POST", "/v2/explain", {"case": case})[1]["result"]
    r = explain(wire, "read")
    alias = next((s["detail"].get("workload_alias") for s in r.get("trace", []) if s["stage"] == "principal"), None)
    check("wire subject inherits the wk2 binding", r["outcome"]["decision"] == "Allow" and alias and alias["principal"] == principal, json.dumps(r["outcome"]))
    check("SPIFFE-name deny applies to the wire subject", explain(wire, "write")["outcome"]["decision"] == "ExplicitDenied")
    check("SVID caller named by SPIFFE ID: name deny applies, wk2 pin does not",
          explain(SPIFFE, "write")["outcome"]["decision"] == "ExplicitDenied" and explain(SPIFFE, "read")["outcome"]["decision"] == "Guest")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TimeoutError as exc:
        print(f"FAIL timeout: {exc}")
        sys.exit(1)
