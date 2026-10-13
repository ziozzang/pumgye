#!/usr/bin/env python3
"""Real Hangang + Pumgye processes, with owned HOP1/HGD1 contract peers."""
import argparse, copy, http.client, http.server, json, os, pathlib, secrets, socket, ssl, subprocess, tempfile, threading, time, urllib.request, urllib.error
from hangang_smoke import Native, Origin, port
p=argparse.ArgumentParser();p.add_argument('--gateway-binary',required=True,type=pathlib.Path);p.add_argument('--pumgye-binary',required=True,type=pathlib.Path);args=p.parse_args()
def openssl(*argv):subprocess.run(['openssl',*argv],check=True,capture_output=True)
key,system,pum_decision,pum_admin=[secrets.token_hex(32) for _ in range(4)]
hopae=Native(key,True);guard=Native(key,False);origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin);threading.Thread(target=origin.serve_forever,daemon=True).start()
public,admin,pum_http,pum_native=[port() for _ in range(4)]
with tempfile.TemporaryDirectory(prefix='pumgye-remote-gateway-') as tmp:
    root=pathlib.Path(tmp)
    for name,kind in [('server','serverAuth'),('client','clientAuth')]:
        openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.csr')),'-subj','/CN='+name)
        if not (root/'ca.pem').exists():
            openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'ca.key'),'-out',str(root/'ca.pem'),'-days','1','-subj','/CN=owned-ca','-addext','basicConstraints=critical,CA:TRUE')
        ext=root/(name+'.ext');ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+kind+'\nsubjectAltName=DNS:pumgye.example.test,IP:127.0.0.1\n')
        openssl('x509','-req','-in',str(root/(name+'.csr')),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(ext),'-out',str(root/(name+'.pem')))
    context=ssl.create_default_context(cafile=str(root/'ca.pem'));context.load_cert_chain(str(root/'client.pem'),str(root/'client.key'))
    policy={'version':1,'information_classes':['internal'],'services':{'orders':{'permissions':['read'],'roles':{'reader':{'permissions':['read'],'information_classes':['internal']}},'users':{'u_reader':['reader']},'networks':[{'cidr':'127.0.0.1/32','roles':['reader']}],'require_guard':True}}}
    initial=root/'initial.json';initial.write_text(json.dumps({'revision':0,'policy':policy}))
    config={'http':[{'id':'orders','host':'app.example.test','path_prefix':'/secure','path_match':'segment_prefix','access_mode':'protected','backends':[f'http://127.0.0.1:{origin.server_port}'],'auth':{'url':'http://127.0.0.1:8701/_hopae/verify','native':{'address':f'127.0.0.1:{hopae.port}'},'response_headers':['x-forwarded-user','x-hopae-aal'],'static_request_headers':{'x-hopae-gateway-key':{'env':'FIXTURE_KEY'}}},'resource_policy':{'resource_id':'orders','principal':{'source':'external','subject_header':'x-forwarded-user'},'allow':[],'pumgye':{'service_id':'orders','information_class':'internal','permissions':{'GET':['read']}}}}],'pumgye_authority':{'decision_address':f'127.0.0.1:{pum_native}','management_address':f'127.0.0.1:{pum_http}','decision_token_env':'PUMGYE_DECISION_TOKEN','admin_token_env':'PUMGYE_ADMIN_TOKEN','tls':{'server_name':'pumgye.example.test','ca':str(root/'ca.pem'),'certificate':str(root/'client.pem'),'key':str(root/'client.key')},'timeout_ms':500}}
    source=root/'config.json';source.write_text(json.dumps(config));env={**os.environ,'HANGANG_ADMIN_TOKEN':system,'FIXTURE_KEY':key,'PUMGYE_DECISION_TOKEN':pum_decision,'PUMGYE_ADMIN_TOKEN':pum_admin}
    logs=[open(root/'gateway.log','wb'),open(root/'pumgye.log','wb')];processes=[]
    def api(path='/v1/config',method='GET',document=None,revision=None,parent=None,token=system):
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        if revision is not None:headers['If-Match']=f'"{revision}"'
        if parent is not None:headers['x-hangang-config-revision']=parent
        request=urllib.request.Request(f'http://127.0.0.1:{admin}'+path,data=None if document is None else json.dumps(document).encode(),headers=headers,method=method)
        with urllib.request.urlopen(request,timeout=5) as response:return json.loads(response.read()),dict(response.headers)
    def rejected(code,*a,**kw):
        try:api(*a,**kw);raise AssertionError('unexpected admission')
        except urllib.error.HTTPError as error:assert error.code==code,(error.code,error.read())
    def upstream(path='/secure'):
        c=http.client.HTTPConnection('127.0.0.1',public,timeout=3);c.request('GET',path,headers={'Host':'app.example.test','x-forwarded-user':'u_reader'});response=c.getresponse()
        if path.endswith('/stream'):return c,response
        response.read();c.close();return response.status
    def revoked(c,r):
        start=time.monotonic()
        try:assert r.read(1)==b''
        except (http.client.IncompleteRead,ConnectionError):pass
        assert time.monotonic()-start<1.5,'retired stream remained open';c.close()
    try:
        owner=subprocess.Popen([str(args.pumgye_binary.resolve()),'--listen',f'0.0.0.0:{pum_http}','--decision-listen',f'0.0.0.0:{pum_native}','--database',str(root/'pumgye.sqlite3'),'--policy',str(initial),'--tls-cert',str(root/'server.pem'),'--tls-key',str(root/'server.key'),'--client-ca',str(root/'ca.pem')],env=env,stdout=logs[1],stderr=logs[1]);processes.append(owner)
        for _ in range(100):
            if owner.poll() is not None:raise RuntimeError('owned Pumgye startup failed')
            try:
                with urllib.request.urlopen(f'https://127.0.0.1:{pum_http}/healthz',context=context,timeout=1) as response:assert response.status==200;break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('owned Pumgye health deadline')
        gateway=subprocess.Popen([str(args.gateway_binary.resolve()),'--config',str(source),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--threads','2','--lua-workers','1','--guard-url','http://127.0.0.1:1','--guard-decision-tcp',f'127.0.0.1:{guard.port}','--guard-token-env','FIXTURE_KEY'],env=env,stdout=logs[0],stderr=logs[0]);processes.append(gateway)
        for _ in range(120):
            if gateway.poll() is not None:raise RuntimeError('owned Hangang startup failed: '+(root/'gateway.log').read_text())
            try:root_config,_=api();break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('owned Hangang health deadline')
        account_password=secrets.token_urlsafe(24)
        api('/v1/auth/bootstrap','POST',{'username':'fixture-operator','password':account_password})
        api('/v1/users','POST',{'username':'fixture-viewer','password':account_password,'role':'viewer'})
        viewer,_=api('/v1/auth/login','POST',{'username':'fixture-viewer','password':account_password},token='')
        for path in ['/v1/pumgye/policy','/v1/pumgye/status','/v1/pumgye/audit']:
            rejected(403,path,token=viewer['token'])
        assert 'pumgye' not in root_config
        current,headers=api('/v1/pumgye/policy');parent=headers['x-hangang-config-revision'];assert current['revision']==1
        rejected(401,'/v1/pumgye/policy',token='invalid-fixture-credential')
        rejected(400,'/v1/pumgye/policy?url=http://untrusted.example.test')
        assert upstream()==200
        hopae.subject='unassigned';assert upstream()==403;hopae.subject='u_reader'
        guard.mode=0;assert upstream()==403;guard.mode=1
        guard.denied=1;assert upstream()==403;guard.denied=0
        rejected(428,'/v1/pumgye/policy','PUT',current,1)
        rejected(409,'/v1/pumgye/policy','PUT',current,1,'"999"')
        c,r=upstream('/secure/stream');assert r.status==200 and r.read(5)==b'open\n'
        changed=copy.deepcopy(current);changed['policy']['services']['orders']['users']={}
        updated,_=api('/v1/pumgye/policy','PUT',changed,1,parent);assert updated['revision']==2
        revoked(c,r);assert upstream()==403
        now,_=api();assert now['revision']==root_config['revision'] and 'pumgye' not in now
        rejected(409,'/v1/pumgye/policy','PUT',changed,1,parent)
        restored=copy.deepcopy(updated);restored['policy']['services']['orders']['users']={'u_reader':['reader']};restored,_=api('/v1/pumgye/policy','PUT',restored,2,parent);assert restored['revision']==3
        c,r=upstream('/secure/stream');assert r.status==200 and r.read(5)==b'open\n'
        # A publication made directly at the owning authority must retire streams
        # without changing Hangang configuration or relying on console notifications.
        external=copy.deepcopy(restored);external['policy']['services']['orders']['users']={}
        request=urllib.request.Request(f'https://127.0.0.1:{pum_http}/v1/policy',data=json.dumps(external).encode(),headers={'Authorization':'Bearer '+pum_admin,'Content-Type':'application/json','If-Match':'"3"'},method='PUT')
        with urllib.request.urlopen(request,context=context,timeout=3) as response:external=json.loads(response.read());assert external['revision']==4
        revoked(c,r);assert upstream()==403
        audit,_=api('/v1/pumgye/audit');assert [e['revision'] for e in audit]==[1,2,3,4]
        external['policy']['services']['orders']['users']={'u_reader':['reader']};restored,_=api('/v1/pumgye/policy','PUT',external,4,parent);assert restored['revision']==5
        c,r=upstream('/secure/stream');assert r.status==200 and r.read(5)==b'open\n'
        owner.terminate();owner.wait(timeout=5);revoked(c,r);assert upstream()==503
        assert Origin.hits==4,Origin.hits
        print('PASS: real Hangang/Pumgye processes over mTLS PPG1, native evidence gates, delegated policy/status/audit, independent CAS/storage, config-scope fence, direct-owner revocation and authority-outage stream termination.')
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        for log in logs:log.close()
        origin.shutdown();hopae.s.close();guard.s.close()
