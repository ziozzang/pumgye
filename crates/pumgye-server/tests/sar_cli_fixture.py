#!/usr/bin/env python3
"""Owned loopback actual-binary fixture, never operating/Kubernetes configuration."""
import pathlib,tempfile,subprocess,socket,ssl,json,http.client,time,os,sys
ADMIN='owned-administrator-at-least-thirty-two-bytes'
DECISION='owned-decision-at-least-thirty-two-bytes'
TOKEN='owned-sar-caller-at-least-thirty-two-bytes'
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
def main(binary):
 with tempfile.TemporaryDirectory(prefix='owned-sar-cli-') as directory:
  root=pathlib.Path(directory);os.chmod(root,0o700)
  def openssl(*args):subprocess.run(['openssl',*args],cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
  openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1','-subj','/CN=owned-ca','-keyout','ca.key','-out','ca.pem','-addext','basicConstraints=critical,CA:TRUE')
  for name,usage in [('server','serverAuth'),('client','clientAuth')]:
   openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=owned-peer','-keyout',name+'.key','-out',name+'.csr')
   (root/(name+'.ext')).write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:sar.test\n')
   openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile',name+'.ext','-out',name+'.pem')
  import hashlib
  cert=ssl.PEM_cert_to_DER_cert((root/'client.pem').read_text());fingerprint=hashlib.sha256(cert).hexdigest()
  management,sar=port(),port();database=root/'authority.sqlite3'
  cfg={'version':1,'listen':'127.0.0.1:'+str(sar),'cluster':'owned-cluster','authority':'sar.test','certificate':str(root/'server.pem'),'key':str(root/'server.key'),'client_ca':str(root/'ca.pem'),'client_sha256':[fingerprint],'caller_token_env':'OWNED_SAR_TOKEN'}
  (root/'sar.json').write_text(json.dumps(cfg))
  policy={'version':1,'information_classes':['public'],'services':{'api':{'authorization_context':'kubernetes_api','permissions':['read'],'roles':{'reader':{'permissions':['read'],'information_classes':['public']}},'users':{'k8sapi:owned-cluster:reader':['reader']},'networks':[],'require_guard':False}},'resources':{'settings':{'service':'api','information_class':'public','actions':{'read':'read'}}},'kubernetes_authorization':{'version':1,'principals':[{'cluster':'owned-cluster','user':'owned-reader','uid':{'mode':'exact','value':'owned-user-uid'},'required_groups':['owned-readers'],'required_extra':{},'subject':'k8sapi:owned-cluster:reader'}],'routes':[{'cluster':'owned-cluster','attributes':{'kind':'resource','group':'','version':'v1','resource':'configmaps','subresource':'','namespace':'owned-blue','name':'owned-settings','verb':'get'},'service':'api','resource':'settings','action':'read'}]}}
  (root/'policy.json').write_text(json.dumps({'revision':1,'policy':policy}))
  argv=[binary,'--listen','127.0.0.1:'+str(management),'--database',str(database),'--policy',str(root/'policy.json'),'--kubernetes-authorization-config',str(root/'sar.json')]
  env=os.environ.copy();env.update(PUMGYE_ADMIN_TOKEN=ADMIN,PUMGYE_DECISION_TOKEN=DECISION,OWNED_SAR_TOKEN=TOKEN)
  output=subprocess.run([*argv,'--check-kubernetes-authorization'],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
  assert output.returncode==0 and not database.exists(),'preflight failed or opened database'
  missing=env.copy();missing.pop('OWNED_SAR_TOKEN');output=subprocess.run(argv,cwd=root,env=missing,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
  assert output.returncode!=0 and not database.exists(),'missing caller credential did not fail before database'
  assert TOKEN.encode() not in output.stderr
  with (root/'process.log').open('wb') as log:
   proc=subprocess.Popen(argv,cwd=root,env=env,stdout=log,stderr=log)
   try:
    context=ssl.create_default_context(cafile=str(root/'ca.pem'));context.load_cert_chain(str(root/'client.pem'),str(root/'client.key'))
    # Deliberately no ALPN: ordinary verified HTTP1 TLS clients remain supported.
    for _ in range(150):
     try:stream=context.wrap_socket(socket.create_connection(('127.0.0.1',sar),timeout=2),server_hostname='sar.test');break
     except (OSError,ssl.SSLError):
      assert proc.poll() is None,'actual listener process exited';time.sleep(.02)
    else:raise AssertionError('actual SAR listener not ready')
    stream.settimeout(3);file=stream.makefile('rb');payload=(pathlib.Path(__file__).parent/'fixtures/sar-v1-generated-shape.json').read_bytes()
    for index,allow in enumerate([True,False,True]):
     if index:
      policy['services']['api']['users']={} if not allow else {'k8sapi:owned-cluster:reader':['reader']}
      connection=http.client.HTTPConnection('127.0.0.1',management,timeout=3);connection.request('PUT','/v1/policy',json.dumps({'revision':index,'policy':policy}),{'Authorization':'Bearer '+ADMIN,'If-Match':'"'+str(index)+'"','Content-Type':'application/json'});response=connection.getresponse();response.read();assert response.status==200;connection.close()
     stream.sendall(('POST /v1/kubernetes/subjectaccessreviews HTTP/1.1\r\nHost: sar.test\r\nAuthorization: Bearer '+TOKEN+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload))+'\r\n\r\n').encode()+payload)
     assert file.readline().startswith(b'HTTP/1.1 200 ');headers={}
     while True:
      line=file.readline()
      if line==b'\r\n':break
      assert line;key,value=line.split(b':',1);headers[key.lower()]=value.strip()
     value=json.loads(file.read(int(headers[b'content-length'])));assert value['status']['allowed']==allow and value['status']['denied']!=allow
    file.close();stream.close()
   finally:
    proc.terminate()
    try:proc.wait(timeout=8)
    except subprocess.TimeoutExpired:proc.kill();proc.wait();raise AssertionError('owned listener did not terminate')
  assert proc.returncode==0,'owned listener shutdown failed'
 print('PASS: actual binary preflight/no-database refusal and verified mTLS same HTTP1 connection Allow/Deny/Allow; owned process cleanup')
if __name__=='__main__':main(sys.argv[1])
