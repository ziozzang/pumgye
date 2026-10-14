#!/usr/bin/env python3
"""Owned actual Hopae/Sumunjang/Pumgye authenticated endpoint fixture; no operating data."""
import argparse, base64, copy, hashlib, hmac, http.client, json, os
from pathlib import Path
import secrets, selectors, socket, ssl, subprocess, tempfile, time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--live-validation', action='store_true', help='client supports cached receipt revocation and outage checks')
    parser.add_argument('--pumgye', required=True, type=Path)
    parser.add_argument('--sumunjang', required=True, type=Path)
    parser.add_argument('--grpc-decisions', action='store_true')
    parser.add_argument('--nonempty-entity', action='store_true', help='bind an owned nonempty entity instead of an empty request body')
    args = parser.parse_args()
    os.umask(0o077)
    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='owned-service-receipt-') as directory:
        root = Path(directory)
        def openssl(*argv):
            return subprocess.check_output(['openssl', *map(str, argv)], stderr=subprocess.DEVNULL)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=owned-ca','-keyout',root/'ca.key','-out',root/'ca.pem','-addext','basicConstraints=critical,CA:TRUE')
        for name, usage in [('server','serverAuth'),('client','clientAuth')]:
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=owned','-keyout',root/(name+'.key'),'-out',root/(name+'.csr'))
            extension=root/(name+'.ext');extension.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:hopae.example.test,IP:127.0.0.1\n')
            openssl('x509','-req','-in',root/(name+'.csr'),'-CA',root/'ca.pem','-CAkey',root/'ca.key','-CAcreateserial','-days','1','-extfile',extension,'-out',root/(name+'.pem'))
        openssl('genpkey','-algorithm','ED25519','-out',root/'issuer.pem')
        seed=openssl('pkey','-in',root/'issuer.pem','-outform','DER')
        public=openssl('pkey','-in',root/'issuer.pem','-pubout','-outform','DER')
        assert len(seed)==48 and len(public)==44
        env=dict(os.environ,OWNED_RECEIPT_SEED=base64.b64encode(seed[-32:]).decode(),OWNED_RECEIPT_CALLER=secrets.token_hex(24),OWNED_RECEIPT_CREDENTIAL=secrets.token_hex(24),OWNED_RECEIPT_DELEGATION=secrets.token_hex(24))
        portal,gateway,grpc,admin=[port() for _ in range(4)]
        guard_http,guard_native,guard_grpc,pum_http,pum_grpc=[port() for _ in range(5)]
        env.update(HANGANG_GUARD_ADMIN_TOKEN=secrets.token_hex(24),HANGANG_GUARD_COLLECTOR_TOKEN=secrets.token_hex(24),PUMGYE_ADMIN_TOKEN=secrets.token_hex(24),PUMGYE_DECISION_TOKEN=secrets.token_hex(24))
        profile={'authority_id':'owned','profiles':[{'service_id':'orders','host':'orders.example.test','ports':[443],'realm':'owned','api_keys':[{'token_env':'OWNED_RECEIPT_CREDENTIAL','subject':'worker'}],'networks':['203.0.113.0/24']}]}
        pin=base64.b64encode(public[-32:]).decode()
        config={'state_dir':str(root/'state'),'listen':{'portal':f'127.0.0.1:{portal}','gateway':f'127.0.0.1:{gateway}','grpc_gateway':f'127.0.0.1:{grpc}','admin':f'127.0.0.1:{admin}','native_gateway_tls':{'certificate':str(root/'server.pem'),'key':str(root/'server.key'),'client_ca':str(root/'ca.pem')}},'portal':{'public_url':'https://auth.example.test'},'gateway':{'kind':'hangang','caller_key_env':'OWNED_RECEIPT_CALLER'},'apps':[{'app_id':'orders','hosts':['orders.example.test']}],'admin':{'public_url':'https://admin.example.test','hangang_delegation':{'authority':'hangang','key_env':'OWNED_RECEIPT_DELEGATION'}},'authentication_gateway':profile,'receipt_issuer':{'issuer_ref':'owned','key_epoch':1,'identity_authority_epoch':'epoch1','public_key':pin,'seed_env':'OWNED_RECEIPT_SEED','scopes':[{'service':'orders','audience':'orders-api'}]}}
        server_config=root/'server.json';server_config.write_text(json.dumps(config))
        client_config={'settings':{'transport':'grpc','address':f'localhost:{grpc}','tls':{'server_name':'hopae.example.test','ca':str(root/'ca.pem'),'certificate':str(root/'client.pem'),'key':str(root/'client.key')}},'issuer_ref':'owned','key_epoch':1,'public_key':pin,'service':'orders','audience':'orders-api','method':'GET','target':'/private','body':'owned transformed entity' if args.nonempty_entity else '','headers':[['x-hopae-contract','1'],['x-forwarded-host','orders.example.test'],['x-forwarded-proto','https'],['x-forwarded-port','443'],['x-forwarded-for','203.0.113.9'],['x-original-method','GET'],['x-original-url','https://orders.example.test/private']]}
        client_config['pumgye_endpoint']=f'http://127.0.0.1:{pum_http}/v1/resource/authenticated-decision'
        if args.grpc_decisions:client_config['pumgye_grpc_address']=f'https://localhost:{pum_grpc}'
        client_path=root/'client.json';client_path.write_text(json.dumps(client_config))
        def publish(revision, configuration):
            path='/v1/authentication/profiles/publish';body=json.dumps({'revision':revision,'configuration':configuration},separators=(',',':')).encode()
            actor={'authority':'hangang','actor_id':0,'actor_name':'system','timestamp':int(time.time()),'nonce':secrets.token_hex(16),'method':'POST','path':path,'body_sha256':hashlib.sha256(body).hexdigest(),'handle_sha256':hashlib.sha256(b'').hexdigest(),'client_ip':'127.0.0.1','user_agent':None}
            raw=json.dumps(actor,separators=(',',':')).encode()
            encode=lambda value:base64.urlsafe_b64encode(value).decode().rstrip('=')
            headers={'Host':'admin.example.test','Content-Type':'application/json','x-hopae-delegation':encode(raw),'x-hopae-delegation-mac':encode(hmac.digest(env['OWNED_RECEIPT_DELEGATION'].encode(),raw,'sha256')),'x-forwarded-host':'admin.example.test','x-forwarded-proto':'https','x-forwarded-port':'443','x-forwarded-for':'127.0.0.1'}
            connection=http.client.HTTPConnection('127.0.0.1',admin,timeout=3)
            try:
                connection.request('POST',path,body=body,headers=headers);response=connection.getresponse();result=json.loads(response.read())
                assert response.status==200, 'owned profile publication refused'
                return result['revision']
            finally:connection.close()
        processes=[]
        with (root/'server.log').open('wb') as server_log, (root/'client.log').open('wb') as client_log:
            try:
                server=subprocess.Popen([str(args.server.resolve()),'run','--config',str(server_config)],env=env,stdout=server_log,stderr=server_log);processes.append(server)
                for _ in range(100):
                    assert server.poll() is None, 'owned server exited before readiness'
                    connection=http.client.HTTPConnection('127.0.0.1',portal,timeout=.5)
                    try:
                        connection.request('GET','/healthz');response=connection.getresponse();response.read()
                        if response.status==200:break
                    except OSError:pass
                    finally:connection.close()
                    time.sleep(.05)
                else:raise RuntimeError('owned receipt server readiness deadline')
                guard_bootstrap=root/'guard-bootstrap.json';guard_bootstrap.write_text(json.dumps({'mode':'enforce','allow':[]}))
                guard_process=subprocess.Popen([str(args.sumunjang.resolve()),'--listen',f'127.0.0.1:{guard_http}','--database',str(root/'guard.sqlite3'),'--bootstrap-policy',str(guard_bootstrap),'--decision-listen',f'127.0.0.1:{guard_native}','--grpc-listen',f'127.0.0.1:{guard_grpc}','--decision-tls-cert',str(root/'server.pem'),'--decision-tls-key',str(root/'server.key'),'--decision-client-ca',str(root/'ca.pem')],env=env,stdout=server_log,stderr=server_log);processes.append(guard_process)
                def guard(method,path,value=None):
                    connection=http.client.HTTPConnection('127.0.0.1',guard_http,timeout=2)
                    try:
                        connection.request(method,path,body=None if value is None else json.dumps(value),headers={'Authorization':'Bearer '+env['HANGANG_GUARD_ADMIN_TOKEN'],'Content-Type':'application/json'})
                        response=connection.getresponse();response.read();assert response.status==200
                    finally:connection.close()
                for _ in range(100):
                    assert guard_process.poll() is None
                    try:guard('GET','/v1/status');break
                    except (OSError,AssertionError):time.sleep(.05)
                else:raise RuntimeError('owned network readiness')
                def write(name,value):
                    path=root/name;path.write_text(json.dumps(value));return str(path)
                tls_fields={'server_name':'hopae.example.test','ca':str(root/'ca.pem'),'certificate':str(root/'client.pem'),'key':str(root/'client.key')}
                trust=write('trust.json',{'entries':[{'issuer_ref':'owned','key_epoch':1,'identity_epoch':'epoch1','service':'orders','audience':'orders-api','minimum_revision':1,'public_key':pin}]})
                auth_live=write('auth-live.json',dict(tls_fields,issuer_ref='owned',address=f'https://localhost:{grpc}',token_env='OWNED_RECEIPT_CALLER'))
                network_live=write('network-live.json',dict(tls_fields,address=f'https://localhost:{guard_grpc}',token_env='HANGANG_GUARD_COLLECTOR_TOKEN'))
                import struct
                subject_hash=hashlib.sha256(bytes([1]))
                for field in ['hopae:owned','owned','worker']:
                    raw=field.encode();subject_hash.update(struct.pack('!Q',len(raw)));subject_hash.update(raw)
                subject='s_'+subject_hash.hexdigest()[:48]
                policy=write('policy.json',{'revision':1,'policy':{'version':1,'information_classes':['internal'],'services':{'orders':{'permissions':['read'],'require_guard':True,'roles':{'reader':{'permissions':['read'],'information_classes':['internal'],'minimum_aal':0}},'users':{subject:['reader']},'networks':[{'cidr':'203.0.113.0/24','roles':['reader']}]}},'resources':{'db:orders':{'service':'orders','information_class':'internal','actions':{'select':'read'},'minimum_aal':0}}}})
                grpc_arguments=['--grpc-listen',f'127.0.0.1:{pum_grpc}','--tls-cert',str(root/'server.pem'),'--tls-key',str(root/'server.key'),'--client-ca',str(root/'ca.pem')] if args.grpc_decisions else []
                pum_tls=ssl.create_default_context(cafile=str(root/'ca.pem'));pum_tls.load_cert_chain(str(root/'client.pem'),str(root/'client.key'))
                pum_process=subprocess.Popen([str(args.pumgye.resolve()),'--listen',f'127.0.0.1:{pum_http}','--database',str(root/'pum.sqlite3'),'--policy',policy,'--authentication-trust',trust,'--authentication-live',auth_live,'--network-live',network_live]+grpc_arguments,env=env,stdout=server_log,stderr=server_log);processes.append(pum_process)
                for _ in range(100):
                    assert pum_process.poll() is None,'owned Pumgye startup refused'
                    connection=http.client.HTTPSConnection('127.0.0.1',pum_http,context=pum_tls,timeout=.5) if args.grpc_decisions else http.client.HTTPConnection('127.0.0.1',pum_http,timeout=.5)
                    try:
                        connection.request('GET','/v1/status',headers={'Authorization':'Bearer '+env['PUMGYE_ADMIN_TOKEN']});response=connection.getresponse();response.read()
                        if response.status==200:break
                    except OSError:pass
                    finally:connection.close()
                    time.sleep(.05)
                else:raise RuntimeError('owned Pumgye readiness')
                client=subprocess.Popen([str(args.client.resolve()),str(client_path)],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=client_log,text=True);processes.append(client)
                selector=selectors.DefaultSelector();selector.register(client.stdout,selectors.EVENT_READ)
                def command(value):
                    client.stdin.write(value+'\n');client.stdin.flush()
                    assert selector.select(5), 'owned client reply deadline'
                    line=client.stdout.readline();assert line, 'owned client refused expected result'
                    return json.loads(line)
                allowed=command('allow');assert allowed['allowed'] is True and allowed['revision']==1
                guard('POST','/v1/blocks',{'network':'203.0.113.9/32','expires_at':int(time.time())+600,'reason':'owned combined qualification'})
                assert command('deny-network')['allowed'] is False
                guard('DELETE','/v1/blocks',{'network':'203.0.113.9/32'})
                assert command('allow')['allowed'] is True
                revision=publish(1,None);assert revision==2
                assert command('deny')['allowed'] is False
                revision=publish(revision,copy.deepcopy(profile));assert revision==3
                restored=command('allow');assert restored['allowed'] is True and restored['revision']==revision
                if not args.live_validation:
                    client.stdin.close();assert client.wait(timeout=3)==0
                    selector.close()
                openssl('genpkey','-algorithm','ED25519','-out',root/'wrong-issuer.pem')
                wrong_public=openssl('pkey','-in',root/'wrong-issuer.pem','-pubout','-outform','DER')[-32:]
                for name in ['caller', 'issuer', 'audience', 'service', 'server-name', 'key', 'key-epoch']:
                    denied_config=copy.deepcopy(client_config);denied_env=dict(env)
                    if name=='caller':denied_env['OWNED_RECEIPT_CALLER']=secrets.token_hex(24)
                    elif name=='issuer':denied_config['issuer_ref']='untrusted-issuer'
                    elif name=='audience':denied_config['audience']='untrusted-api'
                    elif name=='service':denied_config['service']='billing'
                    elif name=='key':denied_config['public_key']=base64.b64encode(wrong_public).decode()
                    elif name=='key-epoch':denied_config['key_epoch']=2
                    else:denied_config['settings']['tls']['server_name']='wrong.example.test'
                    denied_path=root/(name+'.json');denied_path.write_text(json.dumps(denied_config))
                    result=subprocess.run([str(args.client.resolve()),str(denied_path)],input='deny\n',env=denied_env,text=True,stdout=subprocess.PIPE,stderr=client_log,timeout=5)
                    assert result.returncode==0 and json.loads(result.stdout)['allowed'] is False, 'unsafe receipt accepted: '+name
                if args.live_validation:
                    fresh=command('allow');assert fresh['allowed'] is True and fresh['revision']==revision
                    server.kill();server.wait(timeout=3)
                    assert command('outage')['allowed'] is False
                    client.stdin.close();assert client.wait(timeout=3)==0
                    selector.close()
                    print('PASS: actual Hopae/Sumunjang/Pumgye processes and authenticated resource endpoint; Enforce Allow, network block/restoration, identity withdrawal/restoration, outage and seven trust refusals')
                else:
                    print('PASS: actual Hopae executable with configured mTLS receipt client; pinned request-bound receipt, signed profile CAS, same-channel revocation/restoration and caller/issuer/service/audience/server-name/key/epoch refusal')
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=8)
                        except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':main()
