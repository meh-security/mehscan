"""Offline installer contracts, plus real shell binary installation on Unix."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('installer', ROOT / 'skills/mehscan-security/scripts/install-mehscan.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
TAG = 'v0.2.0'
NAME = 'mehscan-v0.2.0-linux-x86_64.zip'


def release():
    return {'tag_name': TAG, 'draft': False, 'prerelease': False, 'assets': [
        {'name': n, 'size': 100, 'browser_download_url':
         f'https://github.com/{installer.REPO}/releases/download/{TAG}/{n}'}
        for n in (NAME, NAME + '.sha256')]}


def archive_bytes(extra=None, manifest_update=None):
    files = {'mehscan': b'#!/bin/sh\nprintf "mehscan 0.2.0\\n"\n'}
    if extra:
        files.update(extra)
    manifest = {'schema_version': '1.0', 'product': 'mehscan', 'version': '0.2.0',
                'platform': 'linux', 'architecture': 'x86_64',
                'files': sorted(list(files) + ['release-manifest.json'])}
    if manifest_update:
        manifest.update(manifest_update)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, value in files.items():
            archive.writestr(name, value)
        archive.writestr('release-manifest.json', json.dumps(manifest))
    return output.getvalue()


class InstallerTests(unittest.TestCase):
    def test_transport_limits_and_redirects(self):
        class Response:
            def __init__(self, status=200, data=b'example', headers=None):
                self.status, self.data, self.headers = status, io.BytesIO(data), headers or {}
                self.fp = SimpleNamespace(raw=SimpleNamespace(
                    _sock=SimpleNamespace(settimeout=lambda value: None)))

            def getheader(self, name):
                return self.headers.get(name)

            def read1(self, size):
                return self.data.read(size)

        class Connection:
            def __init__(self, response):
                self.response = response
                self.sock = None

            def request(self, *args, **kwargs):
                pass

            def getresponse(self):
                return self.response

            def close(self):
                pass

        with patch.object(installer.http.client, 'HTTPSConnection',
                          return_value=Connection(Response(headers={'Content-Length': '7'}))):
            self.assertEqual(installer.download('https://github.com/a', 7), b'example')
        eof = Response(data=b'', headers={'Content-Length': '0'})
        eof.fp = None
        with patch.object(installer.http.client, 'HTTPSConnection',
                          return_value=Connection(eof)):
            self.assertEqual(installer.download('https://github.com/a', 7), b'')
        for response in (Response(), Response(headers={'Content-Length': '8'}),
                         Response(headers={'Content-Length': '3'}),
                         Response(status=302, headers={'Location': 'https://example.com/evil'})):
            with patch.object(installer.http.client, 'HTTPSConnection', return_value=Connection(response)):
                with self.assertRaises(ValueError):
                    installer.download('https://github.com/a', 4)
        with patch.object(installer.http.client, 'HTTPSConnection',
                          return_value=Connection(Response(status=302, headers={'Location': '/again'}))) as transport:
            with self.assertRaises(ValueError):
                installer.download('https://github.com/a', 7)
            self.assertEqual(transport.call_count, 6)
        with patch.object(installer.time, 'monotonic', side_effect=[0, 0, 61]), \
             patch.object(installer.http.client, 'HTTPSConnection', return_value=Connection(Response())):
            with self.assertRaises(ValueError):
                installer.download('https://github.com/a', 7)

    def test_arguments_and_origins(self):
        self.assertEqual(installer.normalize_version('0.2.0'), TAG)
        for bad in ('../main', 'v0.2.0/evil', '0.2'):
            with self.assertRaises(ValueError):
                installer.normalize_version(bad)
        for bad in ('http://github.com/a', 'https://github.com:444/a',
                    'https://user:password@github.com/a', 'https://example.com/a'):
            with self.assertRaises(ValueError):
                installer.validate_url(bad)

    def test_release_selection(self):
        self.assertEqual(installer.select_release(release(), TAG, 'linux', 'x86_64')[1], NAME)
        for edit in ({'draft': True}, {'prerelease': True}, {'tag_name': 'v0.1.0'}):
            data = release()
            data.update(edit)
            with self.assertRaises(ValueError):
                installer.select_release(data, TAG, 'linux', 'x86_64')
        for mutation in ('duplicate', 'origin', 'size'):
            data = release()
            if mutation == 'duplicate':
                data['assets'].append(copy.deepcopy(data['assets'][0]))
            elif mutation == 'origin':
                data['assets'][0]['browser_download_url'] = 'https://example.com/a'
            else:
                data['assets'][0]['size'] = 262144001
            with self.assertRaises(ValueError):
                installer.select_release(data, TAG, 'linux', 'x86_64')
        with self.assertRaises(ValueError):
            installer.select_release(release(), TAG, 'linux', 'aarch64')

    def test_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / NAME
            archive.write_bytes(b'example')
            digest = hashlib.sha256(b'example').hexdigest()
            self.assertEqual(installer.checksum(archive, digest + '  ' + NAME, NAME), digest)
            for record in ('malformed', digest + '  wrong.zip', '0' * 64 + '  ' + NAME):
                with self.assertRaises(ValueError):
                    installer.checksum(archive, record, NAME)

    def test_archive_validation(self):
        with zipfile.ZipFile(io.BytesIO(archive_bytes())) as archive:
            installer.validate_archive(archive, TAG, 'linux', 'x86_64')
        for name in ('../escape', '/absolute', 'folder/../escape', 'a\\b', 'a:b', 'MEHSCAN'):
            with zipfile.ZipFile(io.BytesIO(archive_bytes({name: b'evil'}))) as archive:
                with self.assertRaises(ValueError):
                    installer.validate_archive(archive, TAG, 'linux', 'x86_64')
        for update in ({'version': '9.9.9'}, {'architecture': 'aarch64'}, {'files': ['mehscan']}):
            with zipfile.ZipFile(io.BytesIO(archive_bytes(manifest_update=update))) as archive:
                with self.assertRaises(ValueError):
                    installer.validate_archive(archive, TAG, 'linux', 'x86_64')
        output = io.BytesIO(archive_bytes())
        with zipfile.ZipFile(output, 'a') as archive:
            entry = zipfile.ZipInfo('link')
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, 'mehscan')
        with zipfile.ZipFile(output) as archive:
            with self.assertRaises(ValueError):
                installer.validate_archive(archive, TAG, 'linux', 'x86_64')

    def test_verifier_failure(self):
        with patch.object(installer.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gh')):
            with self.assertRaises(subprocess.CalledProcessError):
                installer.run_verifier(['gh', 'attestation', 'verify'])
        args = installer.verification_arguments('a.zip', 'b.jsonl', TAG, 'a' * 40)
        for expected in ('--bundle', '--repo', '--signer-workflow', '--source-ref',
                         'refs/tags/' + TAG, '--deny-self-hosted-runners', '--source-digest', 'a' * 40):
            self.assertIn(expected, args)

    def test_missing_gh_describes_source_build_fallback(self):
        options = argparse.Namespace(version=TAG, source_digest=None, force_download=True,
                                     install_directory=None)
        with patch.object(installer, 'target', return_value=('linux', 'x86_64')), \
             patch.object(installer.shutil, 'which', return_value=None), \
             patch.object(installer, 'download') as transport, \
             patch.object(installer, 'binary_version') as execution:
            with self.assertRaisesRegex(ValueError, 'build from trusted source with Cargo'):
                installer.install(options)
            transport.assert_not_called()
            execution.assert_not_called()

    def test_path_precedes_platform_verifier_and_download(self):
        for host in ('Linux', 'Darwin'):
            for version in (None, TAG, '0.2.0'):
                options = argparse.Namespace(version=version, source_digest=None,
                                             force_download=False, install_directory=None)
                with patch.object(installer.platform, 'system', return_value=host), \
                     patch.object(installer.shutil, 'which', return_value='/existing/mehscan') as lookup, \
                     patch.object(installer, 'binary_version', return_value='mehscan 0.2.0'), \
                     patch.object(installer, 'target') as detection, \
                     patch.object(installer, 'run_verifier') as verifier, \
                     patch.object(installer, 'download') as transport:
                    self.assertEqual(installer.install(options), Path('/existing/mehscan').resolve())
                    lookup.assert_called_once_with('mehscan')
                    detection.assert_not_called()
                    verifier.assert_not_called()
                    transport.assert_not_called()

    def test_existing_path_constraints_never_trigger_install(self):
        for version, pin, failure in (('9.9.9', None, None), (TAG, 'a' * 40, None),
                                     (TAG, None, ValueError('invalid executable version'))):
            options = argparse.Namespace(version=version, source_digest=pin,
                                         force_download=False, install_directory=None)
            with patch.object(installer.shutil, 'which', return_value='/existing/mehscan'), \
                 patch.object(installer, 'binary_version', return_value='mehscan 0.2.0', side_effect=failure), \
                 patch.object(installer, 'download') as transport, \
                 patch.object(installer, 'run_verifier') as verifier:
                with self.assertRaises(ValueError):
                    installer.install(options)
                transport.assert_not_called()
                verifier.assert_not_called()

    def test_install_flow_and_failed_verification_never_executes(self):
        payload = archive_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        record = (digest + '  ' + NAME).encode()
        data = release()
        data['assets'][0]['size'] = len(payload)
        data['assets'][1]['size'] = len(record)

        def fake_download(url, maximum, destination=None):
            if '/attestations/' in url:
                result = json.dumps({'attestations': [{'bundle': {'example': True}}]}).encode()
            elif '/releases/tags/' in url:
                result = json.dumps(data).encode()
            else:
                result = record if url.endswith('.sha256') else payload
            self.assertLessEqual(len(result), maximum)
            if destination:
                destination.write_bytes(result)
                return len(result)
            return result

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'install with spaces'
            options = argparse.Namespace(version=TAG, source_digest=None, force_download=True,
                                         install_directory=str(destination))
            with patch.object(installer, 'target', return_value=('linux', 'x86_64')), \
                 patch.object(installer.shutil, 'which', return_value='gh'), \
                 patch.object(installer, 'download', side_effect=fake_download), \
                 patch.object(installer, 'run_verifier') as verifier:
                if os.name == 'posix':
                    binary = installer.install(options)
                    self.assertEqual(installer.binary_version(binary), 'mehscan 0.2.0')
                    self.assertIn('--source-digest', verifier.call_args.args[0])
                verifier.side_effect = [None, subprocess.CalledProcessError(1, 'gh')]
                with patch.object(installer, 'binary_version') as execution:
                    with self.assertRaises(subprocess.CalledProcessError):
                        installer.install(options)
                    execution.assert_not_called()
                self.assertFalse(any(destination.glob('.mehscan.*')))

    @unittest.skipUnless(os.name == 'posix', 'Unix filesystem contract')
    def test_bash_path_reuse_without_python_or_gh(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / 'mehscan'
            binary.write_text('#!/bin/sh\nprintf "mehscan 0.2.0\\n"\n')
            binary.chmod(0o755)
            (directory / 'dirname').symlink_to(installer.shutil.which('dirname'))
            bash = installer.shutil.which('bash')
            script = ROOT / 'skills/mehscan-security/scripts/install-mehscan.sh'
            environment = dict(os.environ, PATH=str(directory))
            for args in ([], ['--version', '0.2.0'], ['--version=v0.2.0']):
                result = subprocess.run([bash, str(script)] + args, env=environment,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(binary))
            for args in (['--version', '9.9.9'], ['--version', '0.2.0', '--source-digest', 'a' * 40]):
                result = subprocess.run([bash, str(script)] + args, env=environment,
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('No installation attempted', result.stderr)
                self.assertNotIn('Python', result.stderr)

    @unittest.skipUnless(os.name == 'posix', 'Unix filesystem contract')
    def test_preserves_unrelated_path_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            link = home / '.local/bin/mehscan'
            link.parent.mkdir(parents=True)
            link.write_text('user-owned')
            with patch.object(installer.Path, 'home', return_value=home):
                installer.publish_link(home / 'binary', home / '.mehscan/cli')
            self.assertEqual(link.read_text(), 'user-owned')


if __name__ == '__main__':
    unittest.main()
