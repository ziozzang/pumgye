#!/usr/bin/env python3
"""Owned native fixtures qualify a real Hangang binary. No operational credentials."""
import argparse, http.client, http.server, json, os, pathlib, secrets, socket, struct, subprocess, tempfile, threading, time, urllib.request, urllib.error

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]
def exact(s,n):
    data=b''
    while len(data)<n:
        chunk=s.recv(n-len(data))
        if not chunk:raise EOFError
        data+=chunk
    return data
class Native:
    def __init__(self,key,hopae):
        self.key=key.encode();self.hopae=hopae;self.subject='u_reader';self.mode=1;self.denied=0;self.s=socket.socket();self.s.bind(('127.0.0.1',0));self.port=self.s.getsockname()[1];self.s.listen();threading.Thread(target=self.accept,daemon=True).start()
    def accept(self):
        while True:
            try:s,_=self.s.accept()
            except OSError:return
            threading.Thread(target=self.serve,args=(s,),daemon=True).start()
    def serve(self,s):
        try:
            if self.hopae:
                magic,i,n=struct.unpack('!4sQI',exact(s,16));assert magic==b'HOP1' and i==0 and exact(s,n)==self.key;s.sendall(struct.pack('!4sQI',b'HOP1',0,1)+b'\1')
                while True:
                    magic,i,n=struct.unpack('!4sQI',exact(s,16));exact(s,n)
                    pairs=[(b'x-forwarded-user',self.subject.encode()),(b'x-hopae-aal',b'2')];reply=struct.pack('!HH',200,len(pairs))
                    for name,value in pairs:reply+=struct.pack('!HI',len(name),len(value))+name+value
                    reply+=struct.pack('!I',0);s.sendall(struct.pack('!4sQI',b'HOP1',i,len(reply))+reply)
            else:
                magic,n=struct.unpack('!4sH',exact(s,6));assert magic==b'HGD1' and exact(s,n)==self.key;s.sendall(b'HGA1')
                while True:
                    request=exact(s,24);reply=bytearray(24);reply[0]=1;reply[1]=self.denied;reply[2]=self.mode;reply[4:8]=request[4:8];reply[8:16]=struct.pack('!Q',1);reply[16:20]=struct.pack('!I',1000);s.sendall(reply)
        except (OSError,EOFError):pass
        finally:s.close()
class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1';hits=0
    def log_message(self,*args):pass
    def do_GET(self):
        type(self).hits+=1
        self.send_response(200)
        if self.path=='/secure/stream':
            self.send_header('Transfer-Encoding','chunked');self.end_headers();self.wfile.write(b'5\r\nopen\n\r\n');self.wfile.flush();time.sleep(3)
            try:self.wfile.write(b'0\r\n\r\n')
            except OSError:pass
        else:self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
def main():
    args=argparse.ArgumentParser();args.add_argument('--gateway-binary',required=True);binary=str(pathlib.Path(args.parse_args().gateway_binary).resolve())
    system,key=secrets.token_hex(32),secrets.token_hex(32);hopae=Native(key,True);guard=Native(key,False)
    origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin);threading.Thread(target=origin.serve_forever,daemon=True).start()
    public,admin=port(),port();base=f'http://127.0.0.1:{admin}'
    document={'http':[{'id':'orders','host':'app.example.test','path_prefix':'/secure','path_match':'segment_prefix','access_mode':'protected','backends':[f'http://127.0.0.1:{origin.server_port}'],'auth':{'url':'http://127.0.0.1:8701/_hopae/verify','native':{'address':f'127.0.0.1:{hopae.port}'},'response_headers':['x-forwarded-user','x-hopae-aal'],'static_request_headers':{'x-hopae-gateway-key':{'env':'FIXTURE_KEY'}}},'resource_policy':{'resource_id':'orders','principal':{'source':'external','subject_header':'x-forwarded-user'},'allow':[],'pumgye':{'service_id':'orders','information_class':'internal','permissions':{'GET':['read']}}}}],'pumgye':{'version':1,'information_classes':['internal'],'services':{'orders':{'permissions':['read'],'roles':{'reader':{'permissions':['read'],'information_classes':['internal']}},'users':{'u_reader':['reader']},'networks':[{'cidr':'127.0.0.1/32','roles':['reader']}],'require_guard':True}}}}
    def api(method='GET',document=None,revision=None):
        headers={'Authorization':'Bearer '+system,'Content-Type':'application/json'}
        if revision is not None:headers['If-Match']=f'"{revision}"'
        request=urllib.request.Request(base+'/v1/config',data=None if document is None else json.dumps(document).encode(),headers=headers,method=method)
        with urllib.request.urlopen(request,timeout=3) as r:return json.loads(r.read())
    def request():
        c=http.client.HTTPConnection('127.0.0.1',public,timeout=3);c.request('GET','/secure',headers={'Host':'app.example.test','x-forwarded-user':'u_reader'});r=c.getresponse();r.read();c.close();return r.status
    with tempfile.TemporaryDirectory(prefix='pumgye-qualification-') as directory:
        root=pathlib.Path(directory);config=root/'config.json';config.write_text(json.dumps(document));log=open(root/'gateway.log','wb')
        process=subprocess.Popen([binary,'--config',str(config),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--threads','2','--lua-workers','1','--guard-url','http://127.0.0.1:1','--guard-decision-tcp',f'127.0.0.1:{guard.port}','--guard-token-env','FIXTURE_KEY'],env={**os.environ,'HANGANG_ADMIN_TOKEN':system,'FIXTURE_KEY':key},stdout=log,stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:raise RuntimeError('owned gateway exited')
                try:api();break
                except OSError:time.sleep(.05)
            assert request()==200
            hopae.subject='unassigned';assert request()==403;hopae.subject='u_reader'
            guard.mode=0;assert request()==403;guard.mode=1
            guard.denied=1;assert request()==403;guard.denied=0
            c=http.client.HTTPConnection('127.0.0.1',public,timeout=2);c.request('GET','/secure/stream',headers={'Host':'app.example.test'});r=c.getresponse();assert r.status==200 and r.read(5)==b'open\n'
            current=api();revision=current['revision'];current['pumgye']['services']['orders']['users']={};updated=api('PUT',current,revision);assert updated['revision']>revision
            started=time.monotonic()
            try:assert r.read(1)==b''
            except (http.client.IncompleteRead,ConnectionError):pass
            assert time.monotonic()-started<1.5,'revoked stream remained open';c.close()
            assert request()==403
            try:api('PUT',current,revision);raise AssertionError('stale write accepted')
            except urllib.error.HTTPError as e:assert e.code==409
            assert Origin.hits==2
            print('PASS: real binary HOP1 + HGD1 enforcement, guest/spoof rejection, mandatory observe/deny rejection, CAS publication, stream revocation and revoked subsequent access.')
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            log.close();origin.shutdown();hopae.s.close();guard.s.close()
if __name__=='__main__':main()
