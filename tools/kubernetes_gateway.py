"""Owned four-process real Kubernetes enforcement fixture. No production state."""
import http.client,http.server,json,os,secrets,shutil,socket,ssl,struct,subprocess,threading,time,urllib.request,urllib.error
from pathlib import Path

def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

class GatewayFixture:
 def __init__(self,args,root,connection,pum_http,pum_native,admin,decision,token,subject,renew=False,api_key=None):
  self.processes=[];self.logs=[];self.origin=None;self.root=root;self.subject=subject;self.credential_prefix="k8s:" if api_key is None else ""
  self.public,self.admin=port(),port();hop_portal,hop_http,hop_native,guard_http,guard_native=[port()for _ in range(5)]
  self.hits=[];self.forbidden_forwarding=False
  fixture=self
  class Origin(http.server.BaseHTTPRequestHandler):
   protocol_version='HTTP/1.1'
   def setup(self):
    super().setup();self.connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
   def log_message(self,*args):pass
   def do_GET(self):
    fixture.hits.append(self.path)
    fixture.forbidden_forwarding |= ('authorization' in self.headers or self.headers.get('x-forwarded-user')!=subject or self.headers.get('x-hopae-aal')!='0' or self.headers.get('x-hopae-principal-kind')!=('workload' if api_key is None else 'service') or self.headers.get('x-hopae-service-id')!='logs')
    self.send_response(200)
    if self.path=='/secure/stream':
     self.send_header('Transfer-Encoding','chunked');self.end_headers();self.wfile.write(b'5\r\nopen\n\r\n');self.wfile.flush()
     if renew:
      for _ in range(40):
       time.sleep(.25)
       try:self.wfile.write(b'1\r\n.\r\n');self.wfile.flush()
       except OSError:return
     else:time.sleep(3)
     try:self.wfile.write(b'0\r\n\r\n')
     except OSError:pass
    else:self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
  self.origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin);threading.Thread(target=self.origin.serve_forever,daemon=True).start()
  origin_port=self.origin.server_port
  if getattr(args,'origin_binary',None):
   self.origin.shutdown();self.origin.server_close();self.origin=None;origin_port=port()
   log=open(root/'fast-origin.log','wb');self.logs.append(log)
   process=subprocess.Popen([str(args.origin_binary.resolve()),'--serve',f'127.0.0.1:{origin_port}','--subject',subject],stdout=log,stderr=log);self.processes.append(process)
   deadline=time.monotonic()+5
   while True:
    assert process.poll()is None,'owned fast origin exited'
    try:
     with socket.create_connection(('127.0.0.1',origin_port),timeout=.2):pass
     break
    except OSError:assert time.monotonic()<deadline;time.sleep(.02)
  caller,guard_key,guard_admin,gateway_admin=[secrets.token_hex(24)for _ in range(4)]
  tls={'server_name':'127.0.0.1','ca':str(root/'rpc-ca.pem'),'certificate':str(root/'rpc-client.pem'),'key':str(root/'rpc-client.key')}
  hop_state=root/'hopae-state';hop_state.mkdir(mode=0o700)
  hop={'listen':{'portal':f'127.0.0.1:{hop_portal}','gateway':f'127.0.0.1:{hop_http}','native_gateway':f'127.0.0.1:{hop_native}','native_gateway_tls':{'certificate':str(root/'rpc-server.pem'),'key':str(root/'rpc-server.key'),'client_ca':str(root/'rpc-ca.pem')}},'state_dir':str(hop_state),'portal':{'public_url':'https://auth.example.test'},'gateway':{'kind':'hangang','caller_key_env':'OWNED_HOPAE_KEY','verify_budget_ms':1000},'session':{'idle':'24h','absolute':'30d'},'cookie':{'name':'__Host-hopae','secure':True},'trusted_proxies':['127.0.0.1/32'],'apps':[{'app_id':'logs','hosts':['app.example.test'],'ports':[self.public],'binding':{'ip':'strict','ua':'off'},'verify_cache_seconds':0}],'providers':[],'authentication_gateway':{'authority_id':'owned-kubernetes','profiles':[{'service_id':'logs','host':'app.example.test','ports':[self.public],'realm':connection['cluster_id'],'kubernetes_tokenreview':{'connection':connection,'ca_pem_env':'OWNED_KUBE_CA','reviewer_token_env':'OWNED_KUBE_REVIEWER','token_prefix':'k8s:'},'networks':['127.0.0.1/32']}]}}
  if api_key is not None:
   profile=hop['authentication_gateway']['profiles'][0];profile.pop('kubernetes_tokenreview');profile['api_keys']=[{'token_env':'OWNED_CHAIN_KEY','subject':'worker'}]
  (root/'hopae.json').write_text(json.dumps(hop));(root/'guard-policy.json').write_text(json.dumps({'mode':'enforce','auto_block':False}))
  gateway={'http':[{'id':'logs','host':'app.example.test','path_prefix':'/secure','path_match':'segment_prefix','access_mode':'protected','backends':[f'http://127.0.0.1:{origin_port}'],'auth':{'renew_native_evidence':renew,'url':f'http://127.0.0.1:{hop_http}/_hopae/verify','native':{'address':f'127.0.0.1:{hop_native}','tls':tls},'request_headers':['authorization'],'response_headers':['x-forwarded-user','x-hopae-aal','x-hopae-principal-kind','x-hopae-service-id'],'static_request_headers':{'x-hopae-gateway-key':{'env':'OWNED_HOPAE_KEY'},'x-hopae-contract':'1'}},'resource_policy':{'resource_id':'logs','principal':{'source':'external','subject_header':'x-forwarded-user'},'allow':[],'pumgye':{'service_id':'logs','information_class':'public','permissions':{'GET':['read']}}}}],'pumgye_authority':{'decision_address':f'127.0.0.1:{pum_native}','management_address':f'127.0.0.1:{pum_http}','decision_token_env':'PUMGYE_DECISION_TOKEN','admin_token_env':'PUMGYE_ADMIN_TOKEN','tls':tls,'timeout_ms':1000}}
  (root/'hangang.json').write_text(json.dumps(gateway))
  env={**os.environ,'OWNED_HOPAE_KEY':caller,'OWNED_KUBE_CA':(root/'ca.pem').read_text(),'OWNED_KUBE_REVIEWER':token,'PUMGYE_ADMIN_TOKEN':admin,'PUMGYE_DECISION_TOKEN':decision,'HANGANG_GUARD_COLLECTOR_TOKEN':guard_key,'HANGANG_GUARD_ADMIN_TOKEN':guard_admin,'HANGANG_ADMIN_TOKEN':gateway_admin}
  if api_key is not None:env['OWNED_CHAIN_KEY']=api_key
  def start(label,command):
   log=open(root/(label+'.log'),'wb');self.logs.append(log);process=subprocess.Popen(command,env=env,stdout=log,stderr=log);self.processes.append(process)
  start('hopae',[str(args.hopae_binary.resolve()),'run','--config',str(root/'hopae.json')])
  start('sumunjang',[str(args.sumunjang_binary.resolve()),'--listen',f'127.0.0.1:{guard_http}','--decision-listen',f'127.0.0.1:{guard_native}','--decision-tls-cert',str(root/'rpc-server.pem'),'--decision-tls-key',str(root/'rpc-server.key'),'--decision-client-ca',str(root/'rpc-ca.pem'),'--database',str(root/'guard.sqlite3'),'--policy',str(root/'guard-policy.json'),'--threads','2'])
  start('hangang',[str(args.gateway_binary.resolve()),'--config',str(root/'hangang.json'),'--listen',f'127.0.0.1:{self.public}','--admin',f'127.0.0.1:{self.admin}','--threads','2','--lua-workers','1','--tls-cert',str(root/'rpc-server.pem'),'--tls-key',str(root/'rpc-server.key'),'--guard-url',f'http://127.0.0.1:{guard_http}','--guard-decision-tcp',f'127.0.0.1:{guard_native}','--guard-token-env','HANGANG_GUARD_COLLECTOR_TOKEN','--guard-decision-server-name','127.0.0.1','--guard-decision-ca',str(root/'rpc-ca.pem'),'--guard-decision-cert',str(root/'rpc-client.pem'),'--guard-decision-key',str(root/'rpc-client.key')])
  self.caller=caller;self.hop_http=hop_http;self.hop_native=hop_native;
  self.admin_token=gateway_admin;self.guard_http=guard_http;self.guard_admin=guard_admin
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   assert all(p.poll()is None for p in self.processes),'owned gateway component exited; private logs retained'
   try:
    with urllib.request.urlopen(urllib.request.Request(f'http://127.0.0.1:{self.admin}/v1/config',headers={'Authorization':'Bearer '+gateway_admin}),timeout=1) as response:json.load(response);break
   except OSError:time.sleep(.05)
  else:raise RuntimeError('owned gateway startup deadline')
 def authority_console(self):
  def get(path):
   request=urllib.request.Request(f'http://127.0.0.1:{self.admin}'+path,headers={'Authorization':'Bearer '+self.admin_token})
   with urllib.request.urlopen(request,timeout=3)as response:return json.load(response),dict(response.headers)
  status,_=get('/v1/pumgye/status');assert status['policy_source']=='kubernetes'
  policy,headers=get('/v1/pumgye/policy');assert self.subject in policy['policy']['services']['logs']['users']
  request=urllib.request.Request(f'http://127.0.0.1:{self.admin}/v1/pumgye/policy',data=json.dumps(policy).encode(),method='PUT',headers={'Authorization':'Bearer '+self.admin_token,'Content-Type':'application/json','If-Match':f'"{policy["revision"]}"','x-hangang-config-revision':next(v for k,v in headers.items()if k.lower()=='x-hangang-config-revision')})
  try:urllib.request.urlopen(request,timeout=3);raise AssertionError('source-owned policy accepted console overwrite')
  except urllib.error.HTTPError as error:assert error.code==409
 def direct_auth(self,token):
  headers={'x-hopae-gateway-key':self.caller,'x-hopae-contract':'1','x-forwarded-host':'app.example.test','x-forwarded-proto':'https','x-forwarded-port':str(self.public),'x-forwarded-for':'127.0.0.1','x-original-url':f'https://app.example.test:{self.public}/secure','x-original-method':'GET','x-original-uri':'/secure','authorization':'Bearer k8s:'+token,'accept':'application/json'}
  request=urllib.request.Request(f'http://127.0.0.1:{self.hop_http}/_hopae/verify',headers=headers)
  try:
   with urllib.request.urlopen(request,timeout=3) as response:
    assert 1 <= int(response.headers['x-hopae-evidence-ttl-ms']) <= 1000, 'native evidence lifetime missing or outside bound'
    return response.status
  except urllib.error.HTTPError as error:return error.code
 def native_lifetime(self,token):
  context=ssl.create_default_context(cafile=str(self.root/'rpc-ca.pem'));context.load_cert_chain(str(self.root/'rpc-client.pem'),str(self.root/'rpc-client.key'));context.set_alpn_protocols(['hop1'])
  def exact(sock,size):
   result=b''
   while len(result)<size:
    part=sock.recv(size-len(result));assert part;result+=part
   return result
  with context.wrap_socket(socket.create_connection(('127.0.0.1',self.hop_native),timeout=3),server_hostname='127.0.0.1')as sock:
   def exchange(identifier,payload):
    sock.sendall(b'HOP1'+struct.pack('!QI',identifier,len(payload))+payload)
    magic,returned,size=struct.unpack('!4sQI',exact(sock,16));assert magic==b'HOP1' and returned==identifier
    return exact(sock,size)
   assert exchange(0,self.caller.encode())==b'\1'
   headers={'x-hopae-contract':'1','x-forwarded-host':'app.example.test','x-forwarded-proto':'https','x-forwarded-port':str(self.public),'x-forwarded-for':'127.0.0.1','x-original-url':f'https://app.example.test:{self.public}/secure','x-original-method':'GET','x-original-uri':'/secure','authorization':'Bearer k8s:'+token,'accept':'application/json'}
   payload=struct.pack('!H',len(headers))
   for name,value in headers.items():
    n,v=name.encode(),value.encode();payload+=struct.pack('!HI',len(n),len(v))+n+v
   reply=exchange(1,payload);status,count=struct.unpack('!HH',reply[:4]);assert status==200;offset=4;values={}
   for _ in range(count):
    n,v=struct.unpack('!HI',reply[offset:offset+6]);offset+=6;name=reply[offset:offset+n].decode();offset+=n;value=reply[offset:offset+v].decode();offset+=v;assert name not in values;values[name]=value
   assert 1<=int(values['x-hopae-evidence-ttl-ms'])<=1000
 def request(self,token=None,path='/secure',stream=False):
  headers={'Host':'app.example.test','x-forwarded-user':self.subject,'x-hopae-principal-kind':'human','x-hopae-aal':'3','x-hopae-service-id':'logs'}
  if token is not None:headers['Authorization']='Bearer '+self.credential_prefix+token
  client=http.client.HTTPSConnection('127.0.0.1',self.public,timeout=3,context=ssl.create_default_context(cafile=str(self.root/'rpc-ca.pem')));client.request('GET',path,headers=headers);response=client.getresponse()
  if stream:return client,response
  response.read();client.close();return response.status
 def expect(self,token,status):
  deadline=time.monotonic()+12
  while time.monotonic()<deadline:
   assert all(p.poll()is None for p in self.processes),'owned component exited'
   result=self.request(token)
   if result==status:return
   assert result==503,('unexpected gateway status',result,status)
   time.sleep(.05)
  raise RuntimeError('gateway policy availability deadline')
 def exercise_native_lease(self,token):
  deadline=time.monotonic()+12
  while True:
   client,response=self.request(token,path='/secure/stream',stream=True)
   if response.status==200:break
   assert response.status==503;response.read();client.close()
   assert time.monotonic()<deadline,'stream admission deadline';time.sleep(.05)
  assert response.read(5)==b'open\n'
  started=time.monotonic()
  try:assert response.read(1)==b''
  except (http.client.IncompleteRead,ConnectionError):pass
  assert time.monotonic()-started<1.5,'machine stream survived evidence/source lease'
  client.close()
 def guard_api(self,method,path,value):
  request=urllib.request.Request(f'http://127.0.0.1:{self.guard_http}'+path,data=json.dumps(value).encode(),method=method,headers={'Authorization':'Bearer '+self.guard_admin,'Content-Type':'application/json'})
  with urllib.request.urlopen(request,timeout=3) as response:return json.load(response)
 def exercise_guard(self,token):
  hits=len(self.hits)
  self.guard_api('PUT','/v1/policy',{'mode':'observe','auto_block':False});self.expect(token,403)
  self.guard_api('PUT','/v1/policy',{'mode':'enforce','auto_block':False})
  self.guard_api('POST','/v1/blocks',{'network':'127.0.0.1/32','expires_at':int(time.time())+60,'reason':'owned-fixture'})
  self.expect(token,403);assert len(self.hits)==hits
  self.guard_api('DELETE','/v1/blocks',{'network':'127.0.0.1/32'});self.expect(token,200)
 def close(self):
  for process in reversed(self.processes):
   if process.poll()is None:
    process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait()
  if self.origin:self.origin.shutdown();self.origin.server_close()
  for log in self.logs:log.close()


def qualify_real_renewal(args,root,connection,policy,reviewer,credential,subject,delete_pod):
 """Isolate native authentication renewal from polling source-health withdrawal."""
 state=root/'real-renewal';state.mkdir(mode=0o700)
 for name in ['ca.pem','rpc-ca.pem','rpc-client.pem','rpc-client.key','rpc-server.pem','rpc-server.key']:shutil.copy2(root/name,state/name)
 initial=state/'initial.json';initial.write_text(json.dumps({'revision':0,'policy':policy}))
 admin,decision=secrets.token_hex(24),secrets.token_hex(24);management,native=port(),port()
 log=open(state/'pumgye.log','wb');fixture=None;owner=None
 try:
  owner=subprocess.Popen([str(args.binary.resolve()),'--listen',f'127.0.0.1:{management}','--decision-listen',f'127.0.0.1:{native}','--database',str(state/'native-policy.sqlite3'),'--policy',str(initial),'--tls-cert',str(state/'rpc-server.pem'),'--tls-key',str(state/'rpc-server.key'),'--client-ca',str(state/'rpc-ca.pem')],env={**os.environ,'PUMGYE_ADMIN_TOKEN':admin,'PUMGYE_DECISION_TOKEN':decision},stdout=log,stderr=log)
  context=ssl.create_default_context(cafile=str(state/'rpc-ca.pem'));context.load_cert_chain(str(state/'rpc-client.pem'),str(state/'rpc-client.key'))
  deadline=time.monotonic()+10
  while True:
   assert owner.poll()is None,'isolated native policy fixture exited'
   try:
    with urllib.request.urlopen(f'https://127.0.0.1:{management}/healthz',context=context,timeout=1)as response:assert response.status==200
    break
   except OSError:
    assert time.monotonic()<deadline;time.sleep(.05)
  fixture=GatewayFixture.__new__(GatewayFixture);fixture.__init__(args,state,connection,management,native,admin,decision,reviewer,subject,renew=True)
  fixture.expect(credential,200)
  client,response=fixture.request(credential,path='/secure/stream',stream=True);assert response.status==200 and response.read(5)==b'open\n'
  began=time.monotonic()
  while time.monotonic()-began<2.2:assert response.read(1)==b'.','actual valid renewed stream closed early'
  # Policy remains constant; only the real Pod credential loses authentication.
  alive_seconds=time.monotonic()-began
  delete_pod();withdrawn=time.monotonic()
  try:
   while response.read(1):assert time.monotonic()-withdrawn<1.5,'deleted Pod stream remained open'
  except (http.client.IncompleteRead,ConnectionError):pass
  assert time.monotonic()-withdrawn<1.5
  client.close();fixture.expect(credential,401);assert not fixture.forbidden_forwarding
  return {'actual_native_renewal_survived_seconds':alive_seconds,'pod_deletion_authentication_withdrawal':True,'policy_mode':'isolated_native_fixed_candidate','kubernetes_rbac_watch_continuity_qualified':False}
 finally:
  if fixture is not None:fixture.close()
  if owner is not None and owner.poll()is None:owner.terminate();owner.wait(timeout=5)
  log.close()
