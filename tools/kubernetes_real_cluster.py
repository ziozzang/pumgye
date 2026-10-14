#!/usr/bin/env python3
"""Qualify read-only RBAC collection/mapping on the owned private kind cluster."""
import argparse,base64,json,os,queue,secrets,signal,subprocess,threading,time
from pathlib import Path
import yaml
p=argparse.ArgumentParser();p.add_argument('--binary',required=True,type=Path);p.add_argument('--state-dir',required=True,type=Path);a=p.parse_args();os.umask(0o077)
state=a.state_dir.resolve();configuration=yaml.safe_load((state/'kubeconfig').read_text());assert configuration['current-context']=='kind-zerotrust-qualification'
c=configuration['clusters'][0]['cluster'];assert c['server'].startswith('https://127.0.0.1:')
root=state/('rbac-'+str(int(time.time()))+'-'+secrets.token_hex(3));root.mkdir(mode=0o700);(root/'ca.pem').write_bytes(base64.b64decode(c['certificate-authority-data']))
container='zerotrust-qualification-control-plane';ns='zt-rbac-'+secrets.token_hex(4);global_role=ns+'-read';process=None;created=False

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
 (root/'mapping.json').write_text(json.dumps(mapping));db=root/'must-not-open.db'
 command=[str(a.binary.resolve()),'--observe-kubernetes-rbac','--kubernetes-cluster','owned-kind-rbac','--kubernetes-namespace',ns,'--kubernetes-api',c['server'],'--kubernetes-ca',str(root/'ca.pem'),'--kubernetes-token',str(root/'token'),'--kubernetes-mapping',str(root/'mapping.json'),'--database',str(db)]
 process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);q=queue.Queue()
 def read():
  for line in process.stdout:q.put(line)
 threading.Thread(target=read,daemon=True).start()
 def observation(predicate):
  deadline=time.monotonic()+12
  while time.monotonic()<deadline:
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
 observation(lambda v:'source'in v and any(o['uid']==recreated['metadata']['uid']for o in v['source']['inventory']['objects']) and not v['candidate']['mappings'][0]['active'])
 (root/'token').write_text('invalid-fixture-token');observation(lambda v:v.get('available') is False);(root/'token').write_text(token);observation(lambda v:'candidate'in v)
 assert not db.exists();process.send_signal(signal.SIGINT);assert process.wait(timeout=5)==0;assert token not in process.stderr.read()
 version=json.loads(ctl('version','-o','json'))['serverVersion']['gitVersion'];report={'cluster_version':version,'read_only_namespaced_and_cluster_rbac':True,'literal_mapping_candidate':True,'binding_delete_withdrawal':True,'recreated_binding_uid_refusal':True,'credential_failure_fence_recovery':True,'authority_database_untouched':True,'native_subject_is_fixture_reference':True,'production_changed':False};(root/'report.json').write_text(json.dumps(report,indent=2)+'\n');(state/'rbac-latest.json').write_text(json.dumps({'report':str(root/'report.json')})+'\n')
 success='PASS: real Kubernetes '+version+' read-only RBAC collection and explicit candidate mapping, Binding deletion/recreation and credential failure recovery; no authority DB or production changes'
finally:
 if process is not None and process.poll() is None:process.terminate();process.wait(timeout=5)
 (root/'token').unlink(missing_ok=True);failed=False
 if created:
  for argv in [('delete','clusterrolebinding',global_role,'--ignore-not-found'),('delete','clusterrole',global_role,'--ignore-not-found'),('delete','namespace',ns,'--ignore-not-found','--wait=false')]:
   try:ctl(*argv)
   except Exception:failed=True
 if failed:raise RuntimeError('owned RBAC fixture cleanup failed')
print(success)
