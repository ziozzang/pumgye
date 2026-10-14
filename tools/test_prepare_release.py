"""Actual Ed25519 verification and release tamper refusal, no operational keys."""
import base64,hashlib,importlib.util,json,subprocess,tempfile,unittest
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
if __name__=='__main__':unittest.main()
