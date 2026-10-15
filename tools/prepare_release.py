#!/usr/bin/env python3
"""Prepare independently signed static Pumgye assets; publication is separate."""
import argparse,base64,gzip,hashlib,json,os,subprocess,tarfile,tempfile,tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TARGETS={'x86_64-unknown-linux-musl':'amd64','aarch64-unknown-linux-musl':'arm64'}
def run(*args):return subprocess.check_output([str(x) for x in args],stderr=subprocess.DEVNULL)
def verify(root):
    pin=base64.b64decode((ROOT/'release-public-key.txt').read_text().strip(),validate=True)
    with tempfile.TemporaryDirectory(prefix='pumgye-signature-') as td:
        td=Path(td);(td/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+pin)
        manifests=list(root.glob('*.manifest.json'))
        if len(manifests)!=1:raise ValueError('one signed artifact is required')
        for manifest in manifests:
            envelope=json.loads(manifest.read_text());payload=base64.b64decode(envelope['payload'],validate=True)
            (td/'payload').write_bytes(payload);(td/'signature').write_bytes(base64.b64decode(envelope['signature'],validate=True))
            run('openssl','pkeyutl','-verify','-pubin','-keyform','DER','-inkey',td/'public.der','-rawin','-in',td/'payload','-sigfile',td/'signature')
            bound=json.loads(payload);artifact=root/manifest.name.removesuffix('.manifest.json')
            if bound['sha256']!=hashlib.sha256(artifact.read_bytes()).hexdigest() or bound['size']!=artifact.stat().st_size:raise ValueError('artifact digest/size mismatch')
        for line in (root/'SHA256SUMS').read_text().splitlines():
            digest,name=line.split('  ')
            if Path(name).name!=name or hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise ValueError('asset checksum mismatch')
# Deliberate allowlist: never recursively include local credentials or evidence.
LEGACY_DOCS=('SERVER.md','SERVER.ko.md','GRPC.md','GRPC.ko.md','KUBERNETES.md','KUBERNETES.ko.md','AUTHENTICATION_RECEIPTS.md','AUTHENTICATION_RECEIPTS.ko.md','OBSERVED_PERMITS.md','OBSERVED_PERMITS.ko.md','WORKLOAD_OBSERVED_PERMITS.md','WORKLOAD_OBSERVED_PERMITS.ko.md')
SAR_DOCS=tuple(stem+suffix for stem in ('KUBERNETES_API_CONTEXT','KUBERNETES_AUTHORIZATION_MAPPING','KUBERNETES_SAR_WIRE','KUBERNETES_SAR_SERVER','RELEASE_0_1_9') for suffix in ('.md','.ko.md'))
# Historical release notes remain provenance; these are the current Human contracts.
HUMAN_DOCS=('HUMAN_POLICY_CORE.md','HUMAN_POLICY_CORE.ko.md','HUMAN_OBSERVED_PERMITS.md','ko/HUMAN_OBSERVED_PERMITS.md')
def package_sources(binary):
    sources={'pumgye':binary,'LICENSE':ROOT/'LICENSE','README.md':ROOT/'README.md','README.ko.md':ROOT/'README.ko.md','release-public-key.txt':ROOT/'release-public-key.txt'}
    for name in LEGACY_DOCS+SAR_DOCS+HUMAN_DOCS:
        p=ROOT/'docs'/name
        if p.is_file():sources['docs/'+name]=p
        elif name in SAR_DOCS:raise ValueError('required SAR release documentation missing')
        elif name in HUMAN_DOCS:raise ValueError('required Human release documentation missing')
    return sources

def write_package(binary,destination,target,version):
    """Write an unsigned reviewable archive; target/version are trusted repo metadata.

    The signed preparation path uses this exact helper, so qualification does not
    need release keys or fake signatures. The caller owns an empty output path.
    """
    sources=package_sources(binary)
    folder=f'pumgye-v{version}-linux-musl-{TARGETS[target]}'
    with destination.open('xb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as tar:
        for name,p in sources.items():
            info=tarfile.TarInfo(folder+'/'+name);info.size=p.stat().st_size;info.mode=0o755 if name=='pumgye' else 0o644;info.mtime=0
            with p.open('rb') as source:tar.addfile(info,source)
    return sources

def prepare(target,output,signer,seed):
    version=tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['package']['version']
    binary=ROOT/'target'/target/'release/pumgye'
    if b'INTERP' in run('readelf','-lW',binary):raise ValueError('static release cannot use an ELF interpreter')
    if run(binary,'--version').decode().strip()!='pumgye '+version:raise ValueError('binary version mismatch')
    if run(signer,'--public-key',seed).decode().strip()!=(ROOT/'release-public-key.txt').read_text().strip():raise ValueError('signing identity mismatch')
    if output.exists() and any(output.iterdir()):raise ValueError('output must be empty')
    if seed.resolve()==output.resolve() or output.resolve() in seed.resolve().parents or seed.resolve() in output.resolve().parents:raise ValueError('output must be separate from seed')
    output.mkdir(parents=True,exist_ok=True)
    artifact=output/('pumgye-'+target);artifact.write_bytes(binary.read_bytes());artifact.chmod(0o755)
    write_package(binary,output/f'pumgye-v{version}-linux-musl-{TARGETS[target]}.tar.gz',target,version)
    payload={'version':version,'target':target,'artifact_url':f'https://github.com/ziozzang/pumgye/releases/download/v{version}/{artifact.name}','sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'size':artifact.stat().st_size}
    with tempfile.TemporaryDirectory(prefix='pumgye-payload-') as td:
        p=Path(td)/'payload.json';p.write_text(json.dumps(payload,separators=(',',':')))
        run(signer,p,seed,output/(artifact.name+'.manifest.json'))
    (output/'release-public-key.txt').write_bytes((ROOT/'release-public-key.txt').read_bytes())
    assets=sorted(output.iterdir());(output/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in assets))
    verify(output)
    envelope=json.loads((output/(artifact.name+'.manifest.json')).read_text())
    if json.loads(base64.b64decode(envelope['payload'],validate=True))!=payload:raise ValueError('signed payload differs')
    print('PASS: prepared and independently verified static signed assets for',target)
if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--target',choices=TARGETS,default='x86_64-unknown-linux-musl');parser.add_argument('--output',type=Path,required=True);parser.add_argument('--signer',type=Path,required=True);parser.add_argument('--seed',type=Path,required=True);args=parser.parse_args()
    prepare(args.target,args.output.resolve(),args.signer.resolve(),args.seed.resolve())
