#!/usr/bin/env python3
"""Owned mTLS server fixtures: no operational credentials or external targets."""
import argparse, concurrent.futures, copy, http.client, json, os, secrets, socket, sqlite3, ssl, struct, subprocess, tempfile, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',required=True,type=Path);p.add_argument('--client',type=Path);p.add_argument('--benchmark',type=int,default=0);p.add_argument('--benchmark-cardinality',type=int,default=0);p.add_argument('--benchmark-batch',type=int,default=64);p.add_argument('--benchmark-concurrency',type=int,default=16);p.add_argument('--benchmark-seconds',type=int,default=10);args=p.parse_args();binary=args.binary.resolve()
def run(*argv):return subprocess.run(argv,check=True,capture_output=True)
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def exact(s,n):
    out=b''
    while len(out)<n:
        part=s.recv(n-len(out));assert part,'truncated native reply';out+=part
    return out
with tempfile.TemporaryDirectory(prefix='pumgye-owned-') as tmp:
    root=Path(tmp)
    def certificate(name,ca=None,kind=None):
        key=root/(name+'.key');csr=root/(name+'.csr');cert=root/(name+'.pem')
        run('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN='+name)
        if ca:
            ext=root/(name+'.ext');ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+kind+'\nsubjectAltName=DNS:pumgye.example.test\n')
            run('openssl','x509','-req','-in',str(csr),'-CA',str(root/(ca+'.pem')),'-CAkey',str(root/(ca+'.key')),'-CAcreateserial','-days','1','-extfile',str(ext),'-out',str(cert))
        else:run('openssl','req','-x509','-key',str(key),'-in',str(csr),'-days','1','-out',str(cert),'-addext','basicConstraints=critical,CA:TRUE')
    certificate('ca');certificate('server','ca','serverAuth');certificate('client','ca','clientAuth');certificate('other-ca');certificate('untrusted','other-ca','clientAuth')
    def context(identity='client'):
        c=ssl.create_default_context(cafile=str(root/'ca.pem'));c.set_alpn_protocols(['ppg1'])
        if identity:c.load_cert_chain(str(root/(identity+'.pem')),str(root/(identity+'.key')))
        return c
    def http_context():
        c=context();c.set_alpn_protocols(['http/1.1']);return c
    admin=secrets.token_urlsafe(32);decision=secrets.token_urlsafe(32);env=dict(os.environ,PUMGYE_ADMIN_TOKEN=admin,PUMGYE_DECISION_TOKEN=decision)
    policy={'version':1,'information_classes':['public','internal'],'services':{'orders':{'permissions':['read'],'require_guard':True,'roles':{'reader':{'permissions':['read'],'information_classes':['public'],'minimum_aal':1}},'users':{'fixture':['reader']},'networks':[{'cidr':'192.0.2.0/24','roles':['reader']}]}}}
    assert 0<=args.benchmark_cardinality<=4096 and (not args.benchmark_cardinality or args.benchmark_batch==1)
    for i in range(args.benchmark_cardinality):
        policy['services']['orders']['users']['fixture-'+str(i)]=['reader']
        policy['services']['orders']['networks'].append({'cidr':f'198.18.{i//256}.{i%256}/32','roles':['reader']})
    initial=root/'initial.json';initial.write_text(json.dumps({'revision':500,'policy':policy}));database=root/'pumgye.sqlite3';http_port,native_port,readiness_port=port(),port(),port()
    argv=[str(binary),'--listen',f'0.0.0.0:{http_port}','--decision-listen',f'0.0.0.0:{native_port}','--readiness-listen',f'0.0.0.0:{readiness_port}','--database',str(database),'--policy',str(initial),'--tls-cert',str(root/'server.pem'),'--tls-key',str(root/'server.key'),'--client-ca',str(root/'ca.pem')]
    rejected=subprocess.run([str(binary),'--listen','0.0.0.0:0','--database',str(root/'rejected.db'),'--policy',str(initial)],env=env,capture_output=True);assert rejected.returncode!=0 and not (root/'rejected.db').exists()
    class LocalHTTPS(http.client.HTTPSConnection):
        def connect(self):self.sock=self._context.wrap_socket(socket.create_connection(('127.0.0.1',http_port),timeout=3),server_hostname='pumgye.example.test')
    def api(method,path,body=None,token=None,match=None):
        c=LocalHTTPS('pumgye.example.test',http_port,context=http_context(),timeout=3);headers={}
        if token:headers['Authorization']='Bearer '+token
        if match is not None:headers['If-Match']=f'"{match}"'
        if body is not None:headers['Content-Type']='application/json';body=json.dumps(body)
        c.request(method,path,body,headers);r=c.getresponse();status=r.status;body=r.read();c.close();return status,json.loads(body) if body else None
    def start():
        log=open(root/'server.log','ab');process=subprocess.Popen(argv,env=env,stdout=log,stderr=log)
        for _ in range(120):
            if process.poll() is not None:raise RuntimeError('fixture failed to start: '+(root/'server.log').read_text())
            try:
                if api('GET','/healthz')[0]==200:return process
            except (OSError,http.client.HTTPException):pass
            time.sleep(.05)
        raise RuntimeError('fixture health deadline')
    def connect(token=decision,identity='client',hostname='pumgye.example.test'):
        s=context(identity).wrap_socket(socket.create_connection(('127.0.0.1',native_port),timeout=3),server_hostname=hostname)
        encoded=token.encode();s.sendall(b'PPG1'+struct.pack('!H',len(encoded))+encoded);assert exact(s,4)==b'PPA1';return s
    def frame(i,subject='fixture',guard=0,minimum=0):
        names=['orders',subject,'read','public'];body=bytes([1,4,1,guard])+struct.pack('!QQ',i,minimum)+socket.inet_aton('192.0.2.8')+bytes(12)+b''.join(bytes([len(v)])+v.encode() for v in names);return struct.pack('!H',len(body))+body
    def reply(s,i):
        data=exact(s,32);assert data[0]==1 and struct.unpack('!Q',data[4:12])[0]==i and data[2:4]==bytes(2) and data[20:]==bytes(12);return data[1],struct.unpack('!Q',data[12:20])[0]
    def readiness_get(path):
        c=http.client.HTTPConnection('127.0.0.1',readiness_port,timeout=3)
        try:
            c.request('GET',path);response=c.getresponse()
            return response.status,response.getheader('Cache-Control'),response.read()
        finally:c.close()
    process=start()
    try:
        assert readiness_get('/-/ready')==(200,'no-store',b'')
        for forbidden in ['/v1/policy','/v1/status','/v1/decision','/v1/audit','/healthz']:
            assert readiness_get(forbidden)[0]==404

        assert api('GET','/v1/policy')[0]==401
        assert api('GET','/v1/status',token=decision)[0]==401
        assert api('GET','/v1/audit')[0]==401
        assert api('GET','/v1/policy',token=decision)[0]==401
        status,doc=api('GET','/v1/policy',token=admin);assert status==200 and doc['revision']==1
        probe={'service_id':'orders','subject':'fixture','ip':'192.0.2.8','permission':'read','information_class':'public','aal':1,'guard':'enforced_allow'}
        assert api('POST','/v1/decision',probe,admin)[0]==401
        status,result=api('POST','/v1/decision',probe,decision);assert status==200 and result['allow'] and result['revision']==1 and result['ttl_ms']==0
        assert api('POST','/v1/decision',dict(probe,minimum_revision=2),decision)[0]==503
        for identity in [None,'untrusted']:
            try:
                s=connect(identity=identity);s.close();raise AssertionError('untrusted TLS identity admitted')
            except (OSError,AssertionError) as e:
                if str(e)=='untrusted TLS identity admitted':raise
        try:
            s=connect(hostname='wrong.example.test');s.close();raise AssertionError('wrong server name admitted')
        except ssl.SSLCertVerificationError:pass
        try:
            s=connect(token=admin);s.close();raise AssertionError('admin token admitted on decision channel')
        except (OSError,AssertionError) as e:
            if str(e)=='admin token admitted on decision channel':raise
        if args.client:
            subprocess.run([str(args.client.resolve()),'--address',f'127.0.0.1:{native_port}','--ca',str(root/'ca.pem'),'--cert',str(root/'client.pem'),'--key',str(root/'client.key'),'--requests','512','--concurrency','8'],env=env,check=True,capture_output=True)
        if args.client and args.benchmark:
            assert 1000<=args.benchmark<=10000000
            assert 1<=args.benchmark_batch<=64 and 1<=args.benchmark_concurrency<=256 and 1<=args.benchmark_seconds<=60
            for trial in range(3):
                measured=subprocess.run([str(args.client.resolve()),'--address',f'127.0.0.1:{native_port}','--ca',str(root/'ca.pem'),'--cert',str(root/'client.pem'),'--key',str(root/'client.key'),'--requests',str(args.benchmark),'--concurrency',str(args.benchmark_concurrency),'--seconds',str(args.benchmark_seconds),'--batch',str(args.benchmark_batch),'--cardinality',str(args.benchmark_cardinality)],env=env,check=True,capture_output=True,text=True)
                result=json.loads(measured.stdout);result['trial']=trial+1
                print(json.dumps(result),flush=True)
        with connect() as s:
            s.sendall(b''.join(frame(i) for i in range(100)));assert all(reply(s,i)==(0,1) for i in range(100))
            s.sendall(frame(100,'unassigned')+frame(101,guard=2)+frame(102,minimum=2));assert reply(s,100)==(2,1) and reply(s,101)==(8,1) and reply(s,102)==(255,1)
            assert api('PUT','/v1/policy',doc,admin)[0]==428
            invalid=copy.deepcopy(doc);invalid['policy']['services']['orders']['roles']['reader']['inherits']=['missing'];assert api('PUT','/v1/policy',invalid,admin,1)[0]==422
            changed=copy.deepcopy(doc);changed['policy']['services']['orders']['users']={}
            assert api('PUT','/v1/policy',changed,decision,1)[0]==401
            status,new=api('PUT','/v1/policy',changed,admin,1);assert status==200 and new['revision']==2
            assert api('PUT','/v1/policy',doc,admin,1)[0]==409
            s.sendall(frame(103));assert reply(s,103)==(2,2)
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                statuses=list(pool.map(lambda _:api('PUT','/v1/policy',new,admin,2)[0],range(8)))
            assert statuses.count(200)==1 and sum(s in (409,503) for s in statuses)==7,statuses
        # Second owner is rejected even with another listener address.
        duplicate=subprocess.run([str(binary),'--listen','127.0.0.1:0','--database',str(database)],env=env,capture_output=True,timeout=5);assert duplicate.returncode!=0
        process.terminate();process.wait(timeout=5)
        process=start()
        status,recovered=api('GET','/v1/policy',token=admin);assert status==200 and recovered['revision']==3 and recovered['policy']['services']['orders']['users']=={}
        with connect() as s:s.sendall(frame(104));assert reply(s,104)==(2,3)
        c=sqlite3.connect(database);assert c.execute('SELECT count(*) FROM audit').fetchone()[0]==3;c.close()
        assert database.stat().st_mode&0o077==0
        status,records=api('GET','/v1/audit?after_revision=1',token=admin);assert status==200 and [r['revision'] for r in records]==[2,3] and all(r['actor'].startswith('mtls:') and len(r['sha256'])==64 for r in records)
        status,result=api('GET','/v1/status',token=admin);assert status==200 and result['healthy'] and result['policy_revision']==3
        print('PASS: independent remote mTLS HTTP/PPG1, trust/token isolation, bounded pipelining, revision floor, CAS races, immediate policy revocation, exclusive DB ownership, audit, restart recovery and isolated no-store readiness.')
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
