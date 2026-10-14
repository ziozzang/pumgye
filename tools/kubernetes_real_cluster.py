#!/usr/bin/env python3
"""Qualify RBAC observation or source-authoritative decisions on the owned private kind cluster."""
import argparse,base64,json,os,queue,secrets,signal,subprocess,threading,time,socket,ssl,struct,urllib.request,urllib.error
from pathlib import Path
import yaml
p=argparse.ArgumentParser();p.add_argument('--authority',action='store_true');p.add_argument('--binary',required=True,type=Path);p.add_argument('--state-dir',required=True,type=Path);a=p.parse_args();os.umask(0o077)
state=a.state_dir.resolve();configuration=yaml.safe_load((state/'kubeconfig').read_text());assert configuration['current-context']=='kind-zerotrust-qualification'
c=configuration['clusters'][0]['cluster'];assert c['server'].startswith('https://127.0.0.1:')
root=state/('rbac-'+str(int(time.time()))+'-'+secrets.token_hex(3));root.mkdir(mode=0o700);(root/'ca.pem').write_bytes(base64.b64decode(c['certificate-authority-data']))
container='zerotrust-qualification-control-plane';ns='zt-rbac-'+secrets.token_hex(4);global_role=ns+'-read';process=None;created=False;native=None

def ctl(*argv,body=None):
 r=subprocess.run(['docker','exec',*(['-i']if body is not None else []),container,'kubectl','--kubeconfig','/etc/kubernetes/admin.conf',*argv],input=None if body is None else json.dumps(body),text=True,capture_output=True,timeout=30)
 if r.returncode:raise RuntimeError('owned kubectl operation failed; private details suppressed')
 return r.stdout

def apply(v):ctl('apply','-f','-',body=v)
def resource(kind,name,rules=None):
 v={'apiVersion':'rbac.authorization.k8s.io/v1','kind':kind,'metadata':{'name':name}}
 if not kind.startswith('Cluster'):v['metadata']['namespace']=ns
 if rules is not None:v['rules']=rules
 return v

def binding(kind,name,role_kind,role_name,subject):
 v=resource(kind,name);v.update(roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':role_kind,'name':role_name},subjects=[{'kind':'ServiceAccount','namespace':ns,'name':subject}]);return v
try:
 apply({'apiVersion':'v1','kind':'Namespace','metadata':{'name':ns}});created=True
 for name in ['reader','worker']:apply({'apiVersion':'v1','kind':'ServiceAccount','metadata':{'namespace':ns,'name':name}})
 apply(resource('Role','source-read',[{'apiGroups':['rbac.authorization.k8s.io'],'resources':['roles','rolebindings'],'verbs':['get','list','watch']}]))
 apply(binding('RoleBinding','source-read','Role','source-read','reader'))
 apply(resource('ClusterRole',global_role,[{'apiGroups':['rbac.authorization.k8s.io'],'resources':['clusterroles','clusterrolebindings'],'verbs':['get','list','watch']}]))
 apply(binding('ClusterRoleBinding',global_role,'ClusterRole',global_role,'reader'))
 app_role=resource('Role','app-reader',[{'apiGroups':[''],'resources':['pods/log'],'verbs':['get'],'resourceNames':['worker']}]);app_binding=binding('RoleBinding','app-worker','Role','app-reader','worker');apply(app_role);apply(app_binding)
 role=json.loads(ctl('get','role','app-reader','-n',ns,'-o','json'));bind=json.loads(ctl('get','rolebinding','app-worker','-n',ns,'-o','json'))
 token=ctl('create','token','reader','-n',ns,'--duration=10m').strip();(root/'token').write_text(token)
 subject='fixture-native-subject'
 mapping={'version':1,'cluster':'owned-kind-rbac','template':{'version':1,'information_classes':['public'],'services':{'logs':{'permissions':['read'],'roles':{'reader':{'permissions':['read'],'information_classes':['public'],'minimum_aal':0}},'users':{},'networks':[{'cidr':'192.0.2.0/24','roles':['reader']}],'require_guard':True}}},'grants':[{'service':'logs','application_role':'reader','native_subject':subject,'source_subject':{'kind':'ServiceAccount','namespace':ns,'name':'worker'},'role':{'kind':'Role','namespace':ns,'name':'app-reader','uid':role['metadata']['uid']},'binding':{'kind':'RoleBinding','namespace':ns,'name':'app-worker','uid':bind['metadata']['uid']},'required_rules':[{'api_group':'','namespace':ns,'resource':'pods/log','verb':'get','resource_name':'worker'}]}]}
 (root/'mapping.json').write_text(json.dumps(mapping));db=root/('authority.sqlite3' if a.authority else 'must-not-open.db')
 command=[str(a.binary.resolve()),'--observe-kubernetes-rbac','--kubernetes-cluster','owned-kind-rbac','--kubernetes-namespace',ns,'--kubernetes-api',c['server'],'--kubernetes-ca',str(root/'ca.pem'),'--kubernetes-token',str(root/'token'),'--kubernetes-mapping',str(root/'mapping.json'),'--database',str(db)]
 env=os.environ.copy()
 if a.authority:
  with socket.socket() as listener:
   listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
  admin=secrets.token_hex(24);decision=secrets.token_hex(24);env.update(PUMGYE_ADMIN_TOKEN=admin,PUMGYE_DECISION_TOKEN=decision)
  initial=root/'initial.json';initial.write_text(json.dumps({'revision':0,'policy':mapping['template']}))
  def openssl(*args):subprocess.run(['openssl',*args],check=True,capture_output=True)
  openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fixture-rpc-ca','-keyout',str(root/'rpc-ca.key'),'-out',str(root/'rpc-ca.pem'),'-addext','basicConstraints=critical,CA:TRUE')
  for identity,usage in [('rpc-server','serverAuth'),('rpc-client','clientAuth')]:
   openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+identity,'-keyout',str(root/(identity+'.key')),'-out',str(root/(identity+'.csr')))
   (root/(identity+'.ext')).write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=IP:127.0.0.1\n')
   openssl('x509','-req','-in',str(root/(identity+'.csr')),'-CA',str(root/'rpc-ca.pem'),'-CAkey',str(root/'rpc-ca.key'),'-CAcreateserial','-days','1','-extfile',str(root/(identity+'.ext')),'-out',str(root/(identity+'.pem')))
  with socket.socket() as listener:
   listener.bind(('127.0.0.1',0));native_port=listener.getsockname()[1]
  client_context=ssl.create_default_context(cafile=str(root/'rpc-ca.pem'));client_context.load_cert_chain(str(root/'rpc-client.pem'),str(root/'rpc-client.key'))
  command[1]='--authorize-kubernetes-rbac';command += ['--listen',f'127.0.0.1:{port}','--decision-listen',f'127.0.0.1:{native_port}','--policy',str(initial),'--tls-cert',str(root/'rpc-server.pem'),'--tls-key',str(root/'rpc-server.key'),'--client-ca',str(root/'rpc-ca.pem')]
 def http(path,data=None,management=False,method=None):
  payload=None if data is None else json.dumps(data).encode()
  req=urllib.request.Request(f'https://127.0.0.1:{port}'+path,data=payload,method=method,headers={'Authorization':'Bearer '+(admin if management else decision),'Content-Type':'application/json','If-Match':'"1"'})
  try:
   with urllib.request.urlopen(req,timeout=2,context=client_context) as reply:return reply.status,json.load(reply)
  except urllib.error.HTTPError as error:return error.code,None
 native=None;request_id=0
 def exact(sock,size):
  result=b''
  while len(result)<size:
   chunk=sock.recv(size-len(result));assert chunk;result+=chunk
  return result
 def native_decision(minimum=0):
  global native,request_id
  if native is None:
   ctx=ssl.create_default_context(cafile=str(root/'rpc-ca.pem'));ctx.load_cert_chain(str(root/'rpc-client.pem'),str(root/'rpc-client.key'));ctx.set_alpn_protocols(['ppg1'])
   native=ctx.wrap_socket(socket.create_connection(('127.0.0.1',native_port),timeout=2),server_hostname='127.0.0.1');assert native.selected_alpn_protocol()=='ppg1'
   credential=decision.encode();native.sendall(b'PPG1'+struct.pack('!H',len(credential))+credential);assert exact(native,4)==b'PPA1'
  request_id+=1;names=['logs',subject,'read','public'];body=bytes([1,4,0,0])+struct.pack('!QQ',request_id,minimum)+socket.inet_aton('192.0.2.8')+bytes(12)+b''.join(bytes([len(v)])+v.encode() for v in names)
  native.sendall(struct.pack('!H',len(body))+body);reply=exact(native,32);assert reply[0]==1 and struct.unpack('!Q',reply[4:12])[0]==request_id
  return reply[1],struct.unpack('!Q',reply[12:20])[0]
 query={'service_id':'logs','subject':subject,'ip':'192.0.2.8','permission':'read','information_class':'public','aal':0,'guard':'enforced_allow'}
 process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env);q=queue.Queue()
 def read():
  for line in process.stdout:q.put(line)
 threading.Thread(target=read,daemon=True).start()
 def observation(predicate):
  deadline=time.monotonic()+12
  while time.monotonic()<deadline:
   if a.authority:
    try:
     code,result=http('/v1/decision',query)
     if code==503:
      verdict,_=native_decision()
      if verdict!=255:continue
      value={'available':False}
     elif code==200:
      _,doc=http('/v1/policy',management=True)
      active=doc['policy']['services']['logs']['users']=={subject:['reader']}
      if result['revision']!=doc['revision']:continue
      assert result['allow']==active
      verdict,revision=native_decision(doc['revision'])
      if verdict==255 or revision!=doc['revision']:continue
      assert (verdict==0)==active
      value={'candidate':{'policy':doc['policy'],'mappings':[{'active':active}]},'source':{'revision':doc['revision']}}
     else:raise RuntimeError('unexpected native authority response')
     if predicate(value):return value
    except (ConnectionError,urllib.error.URLError):pass
    assert process.poll() is None,'authority exited'
    time.sleep(.05);continue
   try:line=q.get(timeout=.5)
   except queue.Empty:
    assert process.poll() is None,'collector exited';continue
   assert token not in line
   value=json.loads(line)
   if predicate(value):return value
  raise RuntimeError('real RBAC observation deadline')
 first=observation(lambda v:v.get('candidate',{}).get('mappings',[{}])[0].get('active') is True);assert first['candidate']['policy']['services']['logs']['users']=={subject:['reader']}
 ctl('delete','rolebinding','app-worker','-n',ns);deleted=observation(lambda v:'candidate'in v and not v['candidate']['mappings'][0]['active']);assert deleted['candidate']['policy']['services']['logs']['users']=={} and deleted['source']['revision']>first['source']['revision']
 apply(app_binding);recreated=json.loads(ctl('get','rolebinding','app-worker','-n',ns,'-o','json'));assert recreated['metadata']['uid']!=bind['metadata']['uid']
 observation(lambda v:'candidate'in v and not v['candidate']['mappings'][0]['active']) if a.authority else observation(lambda v:'source'in v and any(o['uid']==recreated['metadata']['uid']for o in v['source']['inventory']['objects']) and not v['candidate']['mappings'][0]['active'])
 (root/'token').write_text('invalid-fixture-token');observation(lambda v:v.get('available') is False);(root/'token').write_text(token);observation(lambda v:'candidate'in v)
 if a.authority:
  code,doc=http('/v1/policy',management=True);assert code==200
  assert http('/v1/policy',doc,management=True,method='PUT')[0]==409
  assert db.exists()
  native.close();native=None
  process.terminate();process.wait(timeout=5)
  (root/'token').write_text('invalid-fixture-token')
  process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
  observation(lambda v:v.get('available') is False)
  (root/'token').write_text(token);observation(lambda v:'candidate'in v and not v['candidate']['mappings'][0]['active'])
  process.terminate();process.wait(timeout=5)
 else:
  assert not db.exists();process.send_signal(signal.SIGINT);assert process.wait(timeout=5)==0
 assert token not in process.stderr.read()
 version=json.loads(ctl('version','-o','json'))['serverVersion']['gitVersion'];report={'cluster_version':version,'read_only_namespaced_and_cluster_rbac':True,'literal_mapping_candidate':True,'binding_delete_withdrawal':True,'recreated_binding_uid_refusal':True,'credential_failure_fence_recovery':True,'authority_database_untouched':not a.authority,'authoritative_native_decisions':a.authority,'pooled_mtls_ppg1_parity':a.authority,'writer_exclusion_and_restart_fence':a.authority,'native_subject_is_fixture_reference':True,'production_changed':False};(root/'report.json').write_text(json.dumps(report,indent=2)+'\n');(state/'rbac-latest.json').write_text(json.dumps({'report':str(root/'report.json')})+'\n')
 success=('PASS: real Kubernetes source-authoritative native decisions, durable deletion, writer exclusion and restart fence; ' if a.authority else 'PASS: real Kubernetes ')+version+' read-only RBAC collection and explicit candidate mapping, Binding deletion/recreation and credential failure recovery; production unchanged'+(' (isolated authority DB)' if a.authority else ' (no authority DB)')
finally:
 if native is not None:native.close()
 if process is not None and process.poll() is None:process.terminate();process.wait(timeout=5)
 (root/'token').unlink(missing_ok=True);failed=False
 if created:
  for argv in [('delete','clusterrolebinding',global_role,'--ignore-not-found'),('delete','clusterrole',global_role,'--ignore-not-found'),('delete','namespace',ns,'--ignore-not-found','--wait=false')]:
   try:ctl(*argv)
   except Exception:failed=True
 if failed:raise RuntimeError('owned RBAC fixture cleanup failed')
print(success)
