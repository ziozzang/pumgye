#!/usr/bin/env python3
"""Owned HTTPS Kubernetes collector fixture; never uses operational credentials."""
import argparse
import copy
import http.server
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True, type=Path)
parser.add_argument('--mapping', action='store_true')
args = parser.parse_args()
binary = args.binary.resolve()

with tempfile.TemporaryDirectory(prefix='pumgye-kubernetes-owned-') as directory:
    root = Path(directory)
    def run(*argv):
        subprocess.run(argv, check=True, capture_output=True)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=fixture-ca', '-keyout', str(root/'ca.key'), '-out', str(root/'ca.pem'), '-addext', 'basicConstraints=critical,CA:TRUE')
    run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', str(root/'server.key'), '-out', str(root/'server.csr'))
    (root/'server.ext').write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
    run('openssl', 'x509', '-req', '-in', str(root/'server.csr'), '-CA', str(root/'ca.pem'), '-CAkey', str(root/'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(root/'server.ext'), '-out', str(root/'server.pem'))
    credential = secrets.token_urlsafe(32)
    token_file = root/'token'; token_file.write_text(credential); token_file.chmod(0o600)
    state = {'mode': 'valid', 'revision': 1, 'redirect_hits': 0, 'continuations': 0}
    group = 'rbac.authorization.k8s.io'
    def role(name, uid):
        return {'apiVersion':group+'/v1','kind':'Role','metadata':{'namespace':'blue','name':name,'uid':uid,'resourceVersion':'object:'+str(state['revision'])},'rules':[{'apiGroups':[''],'resources':['pods/log'],'verbs':['get']}]}
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            url = urlsplit(self.path)
            if url.path == '/stolen':
                state['redirect_hits'] += 1
            if self.headers.get('Authorization') != 'Bearer '+credential:
                self.send_response(401); self.end_headers(); return
            if state['mode'] == 'redirect':
                self.send_response(302);self.send_header('Location','https://127.0.0.1:'+str(self.server.server_port)+'/stolen');self.end_headers();return
            if state['mode'] == 'expired':
                self.send_response(410);self.end_headers();return
            resource = url.path.rsplit('/',1)[-1]
            kinds = {'roles':'Role','rolebindings':'RoleBinding','clusterroles':'ClusterRole','clusterrolebindings':'ClusterRoleBinding'}
            if resource not in kinds:
                self.send_response(404);self.end_headers();return
            query = parse_qs(url.query)
            assert query.get('limit') == ['256']
            items = []
            continuation = ''
            rv = 'collection:'+str(state['revision'])
            if state['mode'] != 'deleted':
                if resource == 'roles':
                    if 'continue' not in query:
                        items = [role('reader','r1')]; continuation = 'opaque+a/b='
                    else:
                        assert query['continue'] == ['opaque+a/b=']
                        state['continuations'] += 1
                        items = [role('spare','r2')]
                        if state['mode'] == 'changed-version': rv = 'changed:rv'
                    if state['mode'] == 'wrong-namespace': items[0]['metadata']['namespace'] = 'red'
                elif resource == 'rolebindings':
                    items = [{'apiVersion':group+'/v1','kind':'RoleBinding','metadata':{'name':'workers','namespace':'blue','uid':'b1','resourceVersion':'object:'+str(state['revision'])},'roleRef':{'apiGroup':group,'kind':'Role','name':'reader'},'subjects':[{'kind':'ServiceAccount','name':'worker','namespace':'blue'}]}]
            value = {'apiVersion':group+'/v1','kind':kinds[resource]+'List','metadata':{'resourceVersion':rv,'continue':continuation},'items':items}
            body = json.dumps(value).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(('127.0.0.1',0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
    thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    db = root/'must-not-open.sqlite3'
    command = [str(binary),'--observe-kubernetes-rbac','--kubernetes-cluster','fixture-cluster','--kubernetes-namespace','blue','--kubernetes-api','https://127.0.0.1:'+str(server.server_port),'--kubernetes-ca',str(root/'ca.pem'),'--kubernetes-token',str(token_file),'--database',str(db)]
    if args.mapping:
        mapping = {'version':1,'cluster':'fixture-cluster','template':{'version':1,'information_classes':['public'],'services':{'logs':{'permissions':['read'],'roles':{'reader':{'permissions':['read'],'information_classes':['public'],'minimum_aal':0}},'users':{},'networks':[{'cidr':'192.0.2.0/24','roles':['reader']}],'require_guard':True}}},'grants':[{'service':'logs','application_role':'reader','native_subject':'native-verified-worker','source_subject':{'kind':'ServiceAccount','name':'worker','namespace':'blue'},'binding':{'kind':'RoleBinding','namespace':'blue','name':'workers','uid':'b1'},'role':{'kind':'Role','namespace':'blue','name':'reader','uid':'r1'},'required_rules':[{'api_group':'','namespace':'blue','resource':'pods/log','verb':'get'}]}]}
        mapping_file=root/'mapping.json';mapping_file.write_text(json.dumps(mapping));command.extend(['--kubernetes-mapping',str(mapping_file)])
    env = {k:v for k,v in os.environ.items() if not k.startswith('PUMGYE_')}
    # An inherited hostile proxy must not receive API credentials or block this source.
    env['HTTPS_PROXY']='http://127.0.0.1:1';env['ALL_PROXY']='http://127.0.0.1:1'
    process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
    output = queue.Queue()
    def read():
        for line in process.stdout:output.put(line)
    threading.Thread(target=read,daemon=True).start()
    def observation(predicate):
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            try:line=output.get(timeout=.5)
            except queue.Empty:
                assert process.poll() is None,'collector exited';continue
            assert credential not in line,'credential exposed'
            value=json.loads(line)
            if 'candidate' in value:
                value=dict(value['source'],candidate=value['candidate'])
            if predicate(value):return value
        raise AssertionError('collector observation deadline')
    def unavailable():return observation(lambda v:v.get('available') is False)
    def available():return observation(lambda v:'inventory' in v)
    try:
        first=available();assert len(first['inventory']['objects'])==3 and first['inventory']['cluster']=='fixture-cluster' and first['inventory']['mode']=='observe';assert len(first['collection_versions'])==4;assert state['continuations']>=1
        if args.mapping:
            assert first['candidate']['mode']=='candidate_only' and first['candidate']['mappings'][0]['active']
            assert first['candidate']['policy']['services']['logs']['users']=={'native-verified-worker':['reader']}
        same=available();assert same['revision']==first['revision']
        state.update(mode='deleted',revision=2)
        deleted=observation(lambda v:'inventory' in v and not v['inventory']['objects']);assert deleted['revision']>first['revision']
        if args.mapping:
            assert deleted['candidate']['policy']['services']['logs']['users']=={} and not deleted['candidate']['mappings'][0]['active']
        for mode in ['changed-version','wrong-namespace','redirect','expired']:
            state['mode']=mode;unavailable()
        assert state['redirect_hits']==0
        state.update(mode='valid',revision=3);recovered=available();assert recovered['revision']>deleted['revision']
        token_file.write_text('invalid-fixture-credential');unavailable();token_file.write_text(credential);available()
        ca=(root/'ca.pem').read_bytes();(root/'ca.pem').write_text('invalid projected CA');unavailable();(root/'ca.pem').write_bytes(ca);available()
        assert not db.exists()
        process.send_signal(signal.SIGINT);assert process.wait(timeout=5)==0
        errors=process.stderr.read();assert credential not in errors
        print('PASS: owned HTTPS paginated RBAC collection, encoded continuation, stable/change/delete revisions, source failure fencing and recovery, scope/version/redirect rejection, token/CA rotation, proxy isolation, no credential output or authority DB')
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=5)
        server.shutdown();server.server_close()
