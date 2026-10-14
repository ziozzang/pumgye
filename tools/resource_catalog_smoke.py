#!/usr/bin/env python3
"""Owned actual resource API, CAS revocation and durable restart qualification."""
import argparse
import copy
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/pumgye'))
    args = parser.parse_args()
    binary = args.binary.resolve()
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='owned-resource-catalog-') as folder:
        state = Path(folder)
        admin, decision = 'owned-catalog-admin-at-least-thirty-two-bytes', 'owned-catalog-decision-at-least-thirty-two-bytes'
        env = dict(os.environ, PUMGYE_ADMIN_TOKEN=admin, PUMGYE_DECISION_TOKEN=decision)
        process = None
        def api(path, token, body=None, method='GET', revision=None):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
            headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
            if revision is not None:
                headers['If-Match'] = f'"{revision}"'
            connection.request(method, path, None if body is None else json.dumps(body), headers)
            response = connection.getresponse()
            status, content = response.status, response.read()
            connection.close()
            return status, json.loads(content) if status == 200 else None
        def start():
            process = subprocess.Popen([str(binary), '--listen', f'127.0.0.1:{port}', '--database', str(state / 'state.db'), '--policy', str(root / 'examples/resource-catalog.json')], env=env, stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('owned server startup failed')
                try:
                    status, _ = api('/v1/policy', admin)
                    if status == 200:
                        return process
                except OSError:
                    pass
                time.sleep(.05)
            process.kill()
            process.wait()
            raise RuntimeError('owned server readiness timeout')
        query = {'service_id': 'orders', 'resource': 'db:orders', 'action': 'select', 'subject': 'fixture', 'ip': '192.0.2.9', 'aal': 2, 'guard': 'enforced_allow'}
        with (state / 'server.log').open('wb') as log:
            try:
                process = start()
                endpoint = '/v1/resource/decision'
                assert api(endpoint, admin, query, 'POST')[0] == 401
                assert api(endpoint, decision, query, 'POST')[1]['allow'] is True
                assert api(endpoint, decision, dict(query, service_id='billing'), 'POST')[1]['reason'] == 'UnknownService'
                missing = dict(query); del missing['service_id']
                assert api(endpoint, decision, missing, 'POST')[0] == 422
                assert api(endpoint, decision, dict(query, information_class='public'), 'POST')[0] == 422
                assert api(endpoint, decision, dict(query, aal=1), 'POST')[1]['reason'] == 'AssuranceDenied'
                status, document = api('/v1/policy', admin)
                assert status == 200
                original = copy.deepcopy(document['policy']['resources'])
                document['policy']['resources'] = {}
                status, published = api('/v1/policy', admin, document, 'PUT', document['revision'])
                assert status == 200
                assert api(endpoint, decision, query, 'POST')[1]['reason'] == 'UnknownResource'
                process.terminate()
                assert process.wait(timeout=8) == 0
                process = start()
                assert api(endpoint, decision, query, 'POST')[1]['reason'] == 'UnknownResource'
                status, current = api('/v1/policy', admin)
                assert status == 200 and current['revision'] == published['revision']
                current['policy']['resources'] = original
                assert api('/v1/policy', admin, current, 'PUT', current['revision'])[0] == 200
                assert api(endpoint, decision, query, 'POST')[1]['allow'] is True
                assert api(endpoint, decision, dict(query, service_id='billing'), 'POST')[1]['reason'] == 'UnknownService'
                missing = dict(query); del missing['service_id']
                assert api(endpoint, decision, missing, 'POST')[0] == 422
                print('PASS: actual resource API, decision-role isolation, owner class/assurance, CAS catalog revocation, restart tombstone and restoration')
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == '__main__':
    main()
