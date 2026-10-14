#!/usr/bin/env python3
"""Owned actual four-process HTTPS benchmark; no production state or mock auth peers."""
import argparse,hashlib,json,os,secrets,subprocess,tempfile,time,urllib.request,ssl
from pathlib import Path
from kubernetes_gateway import GatewayFixture,port
p=argparse.ArgumentParser()
for name in ['gateway','hopae','sumunjang','pumgye','generator']:p.add_argument('--'+name,required=True,type=Path)
p.add_argument('--fast-origin',action='store_true');p.add_argument('--seconds',type=int,default=10);p.add_argument('--workers',type=int,default=16);a=p.parse_args();os.umask(0o077)
a.origin_binary=a.generator if a.fast_origin else None;a.gateway_binary=a.gateway;a.hopae_binary=a.hopae;a.sumunjang_binary=a.sumunjang
with tempfile.TemporaryDirectory(prefix='owned-native-chain-')as folder:
 root=Path(folder);owner=None;fixture=None;log=None
 def openssl(*argv):subprocess.run(['openssl',*argv],check=True,capture_output=True)
 openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=owned-ca','-keyout',str(root/'rpc-ca.key'),'-out',str(root/'rpc-ca.pem'),'-addext','basicConstraints=critical,CA:TRUE')
 for name,usage in [('rpc-server','serverAuth'),('rpc-client','clientAuth')]:
  openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+name,'-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.csr')))
  (root/(name+'.ext')).write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=IP:127.0.0.1\n')
  openssl('x509','-req','-in',str(root/(name+'.csr')),'-CA',str(root/'rpc-ca.pem'),'-CAkey',str(root/'rpc-ca.key'),'-CAcreateserial','-days','1','-extfile',str(root/(name+'.ext')),'-out',str(root/(name+'.pem')))
 (root/'ca.pem').write_bytes((root/'rpc-ca.pem').read_bytes());realm='owned-performance';digest=hashlib.sha256(bytes([1]))
 for value in ['hopae:owned-kubernetes',realm,'worker']:
  raw=value.encode();digest.update(len(raw).to_bytes(8,'big'));digest.update(raw)
 subject='s_'+digest.hexdigest()[:48];key=secrets.token_hex(24);admin=secrets.token_hex(24);decision=secrets.token_hex(24);management,native=port(),port()
 policy={'version':1,'information_classes':['public'],'services':{'logs':{'permissions':['read'],'roles':{'reader':{'permissions':['read'],'information_classes':['public'],'minimum_aal':0}},'users':{subject:['reader']},'networks':[{'cidr':'127.0.0.1/32','roles':['reader']}],'require_guard':True}}}
 (root/'initial.json').write_text(json.dumps({'revision':0,'policy':policy}));env={**os.environ,'PUMGYE_ADMIN_TOKEN':admin,'PUMGYE_DECISION_TOKEN':decision}
 try:
  log=open(root/'pumgye.log','wb');owner=subprocess.Popen([str(a.pumgye.resolve()),'--listen',f'127.0.0.1:{management}','--decision-listen',f'127.0.0.1:{native}','--database',str(root/'pumgye.db'),'--policy',str(root/'initial.json'),'--tls-cert',str(root/'rpc-server.pem'),'--tls-key',str(root/'rpc-server.key'),'--client-ca',str(root/'rpc-ca.pem')],env=env,stdout=log,stderr=log)
  ctx=ssl.create_default_context(cafile=str(root/'rpc-ca.pem'));ctx.load_cert_chain(str(root/'rpc-client.pem'),str(root/'rpc-client.key'));deadline=time.monotonic()+10
  while True:
   assert owner.poll()is None,'owned Pumgye startup failure'
   try:
    with urllib.request.urlopen(f'https://127.0.0.1:{management}/healthz',context=ctx,timeout=1)as response:assert response.status==200
    break
   except OSError:assert time.monotonic()<deadline;time.sleep(.05)
  fixture=GatewayFixture.__new__(GatewayFixture);fixture.__init__(a,root,{'cluster_id':realm},management,native,admin,decision,'unused-fixture-reviewer',subject,api_key=key)
  fixture.expect(key,200);fixture.expect(None,401);fixture.expect('invalid-fixture-key',401);fixture.exercise_guard(key)
  for trial in range(3):
   r=subprocess.run([str(a.generator.resolve()),'--origin',f'https://127.0.0.1:{fixture.public}','--ca',str(root/'rpc-ca.pem'),'--workers',str(a.workers),'--seconds',str(a.seconds)],env={**os.environ,'OWNED_CHAIN_TOKEN':key},capture_output=True,text=True,timeout=a.seconds+15)
   assert key not in r.stdout+r.stderr
   result=json.loads(r.stdout);result['trial']=trial+1;result['all_components_real']=True;result['origin']='Go validated origin' if a.fast_origin else 'Python validated origin';print(json.dumps(result),flush=True)
   assert r.returncode==0 and not fixture.forbidden_forwarding,'owned chain load failed verification'
  print('PASS: real four-component native API-key/mTLS chain, every HTTPS response verified; guest/invalid identity/observe/IP block denied; credentials absent upstream; production untouched')
 finally:
  if fixture is not None:fixture.close()
  if owner is not None and owner.poll()is None:owner.terminate();owner.wait(timeout=5)
  if log:log.close()
