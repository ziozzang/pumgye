"""Actual Ed25519 verification and release tamper refusal, no operational keys."""
import base64,hashlib,importlib.util,json,subprocess,tempfile,unittest,tarfile
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('release',Path(__file__).with_name('prepare_release.py'));release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.repo=self.root/'repo';self.repo.mkdir();self.assets=self.root/'assets';self.assets.mkdir()
        self.key=self.root/'key.pem';release.run('openssl','genpkey','-algorithm','ED25519','-out',self.key)
        public=release.run('openssl','pkey','-in',self.key,'-pubout','-outform','DER')[-32:];(self.repo/'release-public-key.txt').write_text(base64.b64encode(public).decode())
        p=patch.object(release,'ROOT',self.repo);p.start();self.addCleanup(p.stop)
        self.artifact=self.assets/'pumgye-test';self.artifact.write_bytes(b'qualified fixture')
        payload=json.dumps({'size':self.artifact.stat().st_size,'sha256':hashlib.sha256(self.artifact.read_bytes()).hexdigest()},separators=(',',':')).encode();(self.root/'payload').write_bytes(payload)
        signature=release.run('openssl','pkeyutl','-sign','-inkey',self.key,'-rawin','-in',self.root/'payload')
        self.manifest=self.assets/'pumgye-test.manifest.json';self.manifest.write_text(json.dumps({'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(signature).decode()}));self.checksums()
    def checksums(self):
        (self.assets/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in self.assets.iterdir() if p.name!='SHA256SUMS'))
    def test_real_signature_and_checksums(self):release.verify(self.assets)
    def test_changed_artifact_is_refused_even_with_recomputed_checksums(self):
        self.artifact.write_bytes(b'changed');self.checksums()
        with self.assertRaisesRegex(ValueError,'digest/size'):release.verify(self.assets)
    def test_forged_signature_is_refused(self):
        e=json.loads(self.manifest.read_text());e['signature']=base64.b64encode(bytes(64)).decode();self.manifest.write_text(json.dumps(e));self.checksums()
        with self.assertRaises(subprocess.CalledProcessError):release.verify(self.assets)
    def test_checksum_path_escape_is_refused(self):
        (self.assets/'SHA256SUMS').write_text('0'*64+'  ../key.pem\n')
        with self.assertRaisesRegex(ValueError,'checksum'):release.verify(self.assets)
    def test_dynamic_loader_is_rejected_before_signing(self):
        (self.repo/'Cargo.toml').write_text('[workspace.package]\nversion="0.1.0"\n')
        with patch.object(release,'run',return_value=b'Program Headers: INTERP'):
            with self.assertRaisesRegex(ValueError,'interpreter'):release.prepare('x86_64-unknown-linux-musl',self.root/'new',self.root/'signer',self.key)
        self.assertFalse((self.root/'new').exists())
class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.repo=self.root/'repo';self.repo.mkdir();(self.repo/'docs').mkdir()
        for name in ('LICENSE','README.md','README.ko.md','release-public-key.txt'):(self.repo/name).write_text('reserved fixture '+name)
        for name in release.LEGACY_DOCS+release.SAR_DOCS+release.HUMAN_DOCS:
            path=self.repo/'docs'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('reserved documentation '+name)
        self.binary=self.root/'binary';self.binary.write_bytes(b'qualified binary fixture');self.private=self.repo/'docs'/'operator-private.env';self.private.write_text('must never enter release')
        p=patch.object(release,'ROOT',self.repo);p.start();self.addCleanup(p.stop)
    def test_real_archive_contains_complete_en_ko_sar_contracts_and_only_allowlisted_files(self):
        out=self.root/'review.tar.gz';sources=release.write_package(self.binary,out,'x86_64-unknown-linux-musl','0.1.9')
        prefix='pumgye-v0.1.9-linux-musl-amd64/'
        with tarfile.open(out) as archive:
            members=archive.getmembers();self.assertEqual({m.name for m in members},{prefix+name for name in sources});self.assertEqual(len(members),len(sources))
            for name in release.SAR_DOCS:self.assertIn(prefix+'docs/'+name,{m.name for m in members})
            self.assertNotIn(prefix+'docs/operator-private.env',{m.name for m in members})
            for member in members:
                self.assertTrue(member.isfile());self.assertFalse(member.name.startswith('/') or '..' in Path(member.name).parts);self.assertEqual(member.mtime,0);self.assertEqual(member.mode,0o755 if member.name==prefix+'pumgye' else 0o644)
                self.assertEqual(archive.extractfile(member).read(),sources[member.name.removeprefix(prefix)].read_bytes())
    def test_archive_contains_exact_human_contract_paths_and_bytes(self):
        expected=('HUMAN_POLICY_CORE.md','HUMAN_POLICY_CORE.ko.md','HUMAN_OBSERVED_PERMITS.md','ko/HUMAN_OBSERVED_PERMITS.md')
        out=self.root/'human.tar.gz';release.write_package(self.binary,out,'x86_64-unknown-linux-musl','0.1.9')
        with tarfile.open(out) as archive:
            for name in expected:
                member='pumgye-v0.1.9-linux-musl-amd64/docs/'+name
                self.assertEqual(archive.extractfile(member).read(),(self.repo/'docs'/name).read_bytes())
            self.assertNotIn('pumgye-v0.1.9-linux-musl-amd64/docs/operator-private.env',archive.getnames())
    def test_each_missing_human_contract_refuses_without_partial_archive(self):
        for name in ('HUMAN_POLICY_CORE.md','HUMAN_POLICY_CORE.ko.md','HUMAN_OBSERVED_PERMITS.md','ko/HUMAN_OBSERVED_PERMITS.md'):
            with self.subTest(name=name):
                path=self.repo/'docs'/name;original=path.read_bytes();path.unlink();out=self.root/'missing-human.tar.gz'
                with self.assertRaisesRegex(ValueError,'required Human'):release.write_package(self.binary,out,'x86_64-unknown-linux-musl','0.1.9')
                self.assertFalse(out.exists());path.write_bytes(original)
    def test_unsigned_archive_is_deterministic_and_does_not_invoke_signer(self):
        with patch.object(release,'run',side_effect=AssertionError('unsigned packaging must not invoke subprocess/signer')):
            one=self.root/'one.tar.gz';two=self.root/'two.tar.gz';release.write_package(self.binary,one,'x86_64-unknown-linux-musl','0.1.9');release.write_package(self.binary,two,'x86_64-unknown-linux-musl','0.1.9')
        self.assertEqual(one.read_bytes(),two.read_bytes())
    def test_missing_required_contract_refuses_before_creating_archive(self):
        for name in release.SAR_DOCS:
            p=self.repo/'docs'/name;original=p.read_bytes();p.unlink();out=self.root/'missing.tar.gz'
            with self.assertRaisesRegex(ValueError,'required SAR'):release.write_package(self.binary,out,'x86_64-unknown-linux-musl','0.1.9')
            self.assertFalse(out.exists());p.write_bytes(original)
    def test_existing_archive_is_never_overwritten(self):
        out=self.root/'existing.tar.gz';out.write_bytes(b'old qualified package')
        with self.assertRaises(FileExistsError):release.write_package(self.binary,out,'x86_64-unknown-linux-musl','0.1.9')
        self.assertEqual(out.read_bytes(),b'old qualified package')

if __name__=='__main__':unittest.main()
