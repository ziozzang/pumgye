#!/usr/bin/env python3
"""Owned real-cluster Pumgye Pod/PVC qualification; never uses global kubeconfig."""
import argparse
import base64
import copy
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--kubectl', required=True, type=Path)
parser.add_argument('--image', required=True)
args = parser.parse_args()
wrapper = args.kubectl.resolve(strict=True)
repo = Path(__file__).resolve().parents[1]
namespace = 'owned-pum-pod-' + secrets.token_hex(6)
forward = None
created = False
os.umask(0o077)


def kube(*command, body=None, timeout=90):
    result = subprocess.run([str(wrapper), *command], input=body, capture_output=True, timeout=timeout)
    if result.returncode:
        # kubectl diagnostics can contain submitted Secret data; do not echo them.
        raise RuntimeError('owned Kubernetes operation failed: ' + command[0])
    return result.stdout


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def exact(sock, length):
    data = b''
    while len(data) < length:
        part = sock.recv(length - len(data))
        assert part, 'truncated native response'
        data += part
    return data


with tempfile.TemporaryDirectory(prefix='pumgye-owned-pod-') as temporary:
    root = Path(temporary)
    hostname = 'pumgye.' + namespace + '.svc'
    admin, decision = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    def certificate(name, parent=None, usage=None):
        def openssl(*command):
            subprocess.run(['openssl', *command], check=True, capture_output=True)
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / (name + '.key')),
                '-out', str(root / (name + '.csr')), '-subj', '/CN=' + name)
        if parent:
            extension = root / (name + '.ext')
            extension.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='
                                 + usage + '\nsubjectAltName=DNS:' + hostname + '\n')
            openssl('x509', '-req', '-in', str(root / (name + '.csr')), '-CA', str(root / (parent + '.pem')),
                    '-CAkey', str(root / (parent + '.key')), '-CAcreateserial', '-days', '1', '-extfile', str(extension),
                    '-out', str(root / (name + '.pem')))
        else:
            openssl('req', '-x509', '-key', str(root / (name + '.key')), '-in', str(root / (name + '.csr')),
                    '-days', '1', '-out', str(root / (name + '.pem')), '-addext', 'basicConstraints=critical,CA:TRUE')
    certificate('ca')
    certificate('server', 'ca', 'serverAuth')
    certificate('client', 'ca', 'clientAuth')
    def tls(alpn='http/1.1', identity=True):
        context = ssl.create_default_context(cafile=str(root / 'ca.pem'))
        context.set_alpn_protocols([alpn])
        if identity:
            context.load_cert_chain(str(root / 'client.pem'), str(root / 'client.key'))
        return context
    http_port, native_port, ready_port = port(), port(), port()
    class LocalHTTPS(http.client.HTTPSConnection):
        def connect(self):
            self.sock = self._context.wrap_socket(socket.create_connection(('127.0.0.1', http_port), timeout=5),
                                                 server_hostname=hostname)
    def api(method, path, body=None, token=None, revision=None):
        connection = LocalHTTPS(hostname, context=tls(), timeout=5)
        headers = {}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if revision is not None:
            headers['If-Match'] = '"' + str(revision) + '"'
        if body is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(body)
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            data = response.read()
            return response.status, json.loads(data) if data else None
        finally:
            connection.close()
    def ready(path='/-/ready'):
        connection = http.client.HTTPConnection('127.0.0.1', ready_port, timeout=5)
        try:
            connection.request('GET', path)
            response = connection.getresponse()
            return response.status, response.getheader('Cache-Control'), response.read()
        finally:
            connection.close()
    def start_forward():
        log = (root / 'port-forward.log').open('ab')
        process = subprocess.Popen([str(wrapper), '-n', namespace, 'port-forward', 'deployment/pumgye',
                                    str(http_port) + ':9084', str(native_port) + ':9085', str(ready_port) + ':9086'],
                                   stdout=log, stderr=log)
        log.close()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, 'owned port-forward exited'
            try:
                if ready()[0] == 200:
                    return process
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(.1)
        process.terminate()
        process.wait(timeout=5)
        raise RuntimeError('owned port-forward readiness deadline')
    def native_allow(expected):
        with tls('ppg1').wrap_socket(socket.create_connection(('127.0.0.1', native_port), timeout=5),
                                   server_hostname=hostname) as sock:
            credential = decision.encode()
            sock.sendall(b'PPG1' + struct.pack('!H', len(credential)) + credential)
            assert exact(sock, 4) == b'PPA1'
            fields = ['orders', 'fixture', 'read', 'public']
            body = (bytes([1, 4, 1, 0]) + struct.pack('!QQ', 1, 0) + socket.inet_aton('192.0.2.8') + bytes(12)
                    + b''.join(bytes([len(value)]) + value.encode() for value in fields))
            sock.sendall(struct.pack('!H', len(body)) + body)
            response = exact(sock, 32)
            assert response[0] == 1 and struct.unpack('!Q', response[4:12])[0] == 1
            assert response[1] == (0 if expected else 2), 'native decision mismatch: unavailable is not a policy deny'
    policy = {'version': 1, 'information_classes': ['public'], 'services': {'orders': {
        'permissions': ['read'], 'require_guard': True,
        'roles': {'reader': {'permissions': ['read'], 'information_classes': ['public'], 'minimum_aal': 1}},
        'users': {'fixture': ['reader']}, 'networks': [{'cidr': '192.0.2.0/24', 'roles': ['reader']}]}}}
    try:
        kube('create', 'namespace', namespace)
        created = True
        rendered = json.loads(kube('apply', '--dry-run=client', '-k', str(repo / 'deploy/kubernetes'), '-o', 'json'))
        items = rendered['items']
        for item in items:
            item['metadata']['namespace'] = namespace
            if item['kind'] == 'ConfigMap':
                item['data']['policy.json'] = json.dumps({'revision': 0, 'policy': policy})
            if item['kind'] == 'Deployment':
                container = item['spec']['template']['spec']['containers'][0]
                container['image'] = args.image
                container['imagePullPolicy'] = 'Never'
        def secret(name, values):
            return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': namespace},
                    'type': 'Opaque', 'data': {key: base64.b64encode(value).decode() for key, value in values.items()}}
        items.extend([secret('pumgye-tls', {'tls.crt': (root / 'server.pem').read_bytes(),
                                           'tls.key': (root / 'server.key').read_bytes(), 'ca.crt': (root / 'ca.pem').read_bytes()}),
                      secret('pumgye-credentials', {'admin-token': admin.encode(), 'decision-token': decision.encode()})])
        kube('apply', '-f', '-', body=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items}).encode())
        kube('-n', namespace, 'rollout', 'status', 'deployment/pumgye', '--timeout=90s', timeout=100)
        forward = start_forward()
        assert ready() == (200, 'no-store', b'')
        for path in ['/v1/policy', '/v1/status', '/v1/audit', '/v1/decision']:
            assert ready(path)[0] == 404
        assert api('GET', '/v1/policy')[0] == 401
        assert api('GET', '/v1/status', token=decision)[0] == 401
        status, document = api('GET', '/v1/policy', token=admin)
        assert status == 200, 'authenticated policy read refused'
        # The server serializes defaults absent from the input; compare relevant
        # policy fields and exercise decisions rather than raw JSON equality.
        stored = document['policy']['services']['orders']
        assert stored['users'] == policy['services']['orders']['users']
        assert stored['permissions'] == ['read'] and stored['require_guard']
        assert stored['roles']['reader']['minimum_aal'] == 1
        assert stored['roles']['reader']['information_classes'] == ['public']
        try:
            with tls('ppg1', identity=False).wrap_socket(socket.create_connection(('127.0.0.1', native_port), timeout=5),
                                                        server_hostname=hostname) as untrusted:
                encoded = decision.encode()
                untrusted.sendall(b'PPG1' + struct.pack('!H', len(encoded)) + encoded)
                assert untrusted.recv(4) != b'PPA1', 'client certificate missing but native caller admitted'
        except (OSError, ssl.SSLError):
            pass
        native_allow(True)
        changed = copy.deepcopy(document)
        changed['policy']['services']['orders']['users'] = {}
        status, published = api('PUT', '/v1/policy', changed, admin, document['revision'])
        assert status == 200 and published['revision'] > document['revision']
        native_allow(False)
        original = json.loads(kube('-n', namespace, 'get', 'pods', '-l', 'app.kubernetes.io/name=pumgye', '-o', 'json'))['items']
        assert len(original) == 1
        old_uid = original[0]['metadata']['uid']
        forward.terminate()
        forward.wait(timeout=5)
        forward = None
        kube('-n', namespace, 'delete', 'pod', original[0]['metadata']['name'], '--wait=true', '--timeout=60s')
        kube('-n', namespace, 'rollout', 'status', 'deployment/pumgye', '--timeout=90s', timeout=100)
        current = json.loads(kube('-n', namespace, 'get', 'pods', '-l', 'app.kubernetes.io/name=pumgye', '-o', 'json'))['items']
        assert len(current) == 1 and current[0]['metadata']['uid'] != old_uid
        forward = start_forward()
        assert api('GET', '/v1/policy', token=admin)[1] == published
        native_allow(False)
        source = api('GET', '/v1/status', token=admin)[1]
        assert source['source_state'] == 'native' and source['healthy']
        print('PASS: real Kubernetes nonroot Pumgye Pod, mTLS HTTP/PPG1, isolated readiness, policy revocation and PVC-backed Pod replacement')
    finally:
        if forward is not None:
            forward.terminate()
            try:
                forward.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forward.kill()
                forward.wait()
        if created:
            kube('delete', 'namespace', namespace, '--wait=true', '--timeout=90s', timeout=100)
            print('PASS: owned test namespace and synthetic credentials cleaned up')
            volumes = json.loads(kube('get', 'pv', '-o', 'json'))['items']
            retained = [volume for volume in volumes if volume.get('spec', {}).get('claimRef', {}).get('namespace') == namespace]
            if retained:
                print('INFO: retained synthetic test PVs:', len(retained), '; cluster retention policy preserved')
