"""Verified public release installation for the Unix shell entry point."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urljoin, urlsplit
import zipfile

REPO = 'meh-security/mehscan'
HOSTS = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com',
         'objects.githubusercontent.com'}
VERSION = r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def normalize_version(value):
    if not value:
        return None
    tag = value if value.startswith('v') else 'v' + value
    require(re.fullmatch('v' + VERSION, tag), 'Invalid release version')
    return tag


def validate_url(url):
    parsed = urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in HOSTS
            and parsed.port in (None, 443) and not parsed.username
            and not parsed.password and not parsed.fragment,
            'Refusing an unexpected download origin')
    return parsed


def download(url, maximum, destination=None):
    """Public HTTPS only; validate every redirect and bound bytes and total time."""
    deadline = time.monotonic() + 60
    for redirect in range(6):
        parsed = validate_url(url)
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Download time limit exceeded')
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=remaining)
        try:
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            connection.request('GET', path, headers={
                'User-Agent': 'mehscan-installer',
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'})
            response = connection.getresponse()
            require(time.monotonic() < deadline, 'Download time limit exceeded')
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                require(redirect < 5 and location, 'Invalid or excessive redirects')
                url = urljoin(url, location)
                continue
            require(response.status == 200, 'Public download HTTP status: ' + str(response.status))
            length = response.getheader('Content-Length')
            expected = int(length) if length is not None else None
            require(expected is None or 0 <= expected <= maximum, 'Download exceeds byte limit')
            data = bytearray()
            total = 0
            output = open(destination, 'wb') if destination else None
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'Download time limit exceeded')
                    # Response owns the socket after a server sends Connection: close.
                    response.fp.raw._sock.settimeout(remaining)
                    chunk = response.read1(min(65536, maximum - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= maximum, 'Download exceeds byte limit')
                    if output:
                        output.write(chunk)
                    else:
                        data.extend(chunk)
                require(expected is None or total == expected, 'Content-Length mismatch')
            finally:
                if output:
                    output.close()
            return total if destination else bytes(data)
        finally:
            connection.close()


def target():
    system = platform.system()
    require(system in ('Linux', 'Darwin'), 'Shell installer supports Linux and macOS only')
    machine = platform.machine().lower()
    # Detect native Apple Silicon even under an Intel/Rosetta Python runtime.
    if system == 'Darwin' and machine == 'x86_64':
        native_arm = subprocess.run(['sysctl', '-n', 'hw.optional.arm64'],
                                    capture_output=True, text=True, timeout=10)
        if native_arm.returncode == 0 and native_arm.stdout.strip() == '1':
            machine = 'arm64'
    architectures = {'x86_64': 'x86_64', 'amd64': 'x86_64',
                     'arm64': 'aarch64', 'aarch64': 'aarch64'}
    require(machine in architectures, 'Unsupported architecture: ' + machine)
    return ('linux' if system == 'Linux' else 'macos', architectures[machine])


def select_release(release, requested, host, architecture):
    tag = normalize_version(release['tag_name'])
    require(tag and not release['draft'] and not release['prerelease'], 'Release is not final')
    require(not requested or tag == requested, 'Requested release tag mismatch')
    name = f'mehscan-{tag}-{host}-{architecture}.zip'
    assets = []
    for filename, limit in ((name, 262144000), (name + '.sha256', 1024)):
        matches = [asset for asset in release['assets'] if asset['name'] == filename]
        require(len(matches) == 1, 'No unique exact release asset: ' + filename)
        asset = matches[0]
        require(asset['browser_download_url'] ==
                f'https://github.com/{REPO}/releases/download/{tag}/{filename}',
                'Unexpected release asset URL')
        require(type(asset['size']) is int and 0 < asset['size'] <= limit,
                'Release asset size outside limits')
        assets.append(asset)
    return tag, name, assets


def checksum(archive, record, name):
    match = re.fullmatch(r'([0-9a-fA-F]{64})  ([^/\\\r\n]+)', record.strip())
    require(match and match[2] == name, 'Malformed checksum record')
    digest = hashlib.sha256()
    with open(archive, 'rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            digest.update(chunk)
    actual = digest.hexdigest()
    require(actual == match[1].lower(), 'SHA-256 mismatch')
    return actual


def verification_arguments(archive, bundle, tag, source_digest):
    args = ['gh', 'attestation', 'verify', str(archive), '--bundle', str(bundle),
            '--repo', REPO, '--signer-workflow', REPO + '/.github/workflows/release.yml',
            '--source-ref', 'refs/tags/' + tag, '--deny-self-hosted-runners']
    if source_digest:
        args += ['--source-digest', source_digest]
    return args


def run_verifier(args):
    subprocess.run(args, check=True, stdout=sys.stderr, timeout=120)


def validate_archive(archive, tag, host, architecture):
    entries = archive.infolist()
    require(len(entries) <= 100 and sum(e.file_size for e in entries) <= 1073741824,
            'Archive exceeds extraction limits')
    names = []
    seen = set()
    for entry in entries:
        name = entry.filename
        parts = name.rstrip('/').split('/')
        require(name and not name.startswith('/') and '\\' not in name
                and ':' not in name and all(p not in ('', '.', '..') for p in parts),
                'Unsafe archive member: ' + name)
        kind = stat.S_IFMT(entry.external_attr >> 16)
        require(kind in (0, stat.S_IFREG, stat.S_IFDIR)
                and (kind != stat.S_IFDIR or entry.is_dir()), 'Archive contains special file')
        canonical = name.rstrip('/').casefold()
        require(canonical not in seen, 'Duplicate archive path')
        seen.add(canonical)
        if not entry.is_dir():
            names.append(name)
    require('mehscan' in names and 'release-manifest.json' in names, 'Missing required archive member')
    require(archive.getinfo('release-manifest.json').file_size <= 1048576, 'Manifest exceeds byte limit')
    manifest = json.loads(archive.read('release-manifest.json').decode('utf-8-sig'))
    require(manifest['schema_version'] == '1.0' and manifest['product'] == 'mehscan'
            and manifest['version'] == tag[1:] and manifest['platform'] == host
            and manifest['architecture'] == architecture
            and sorted(manifest['files']) == sorted(names), 'Release manifest mismatch')


def binary_version(binary):
    result = subprocess.run([str(binary), '--version'], check=True, capture_output=True,
                            text=True, timeout=30)
    require(re.fullmatch('mehscan ' + VERSION, result.stdout.strip()), 'Invalid executable version')
    return result.stdout.strip()


def publish_link(binary, managed_root):
    link = Path.home() / '.local' / 'bin' / 'mehscan'
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(link):
            if not link.is_symlink():
                return
            resolved = link.resolve()
            if not resolved.is_relative_to(managed_root.resolve()):
                return
            link.unlink()
        link.symlink_to(binary)
    except OSError as error:
        print('Optional PATH link unavailable: ' + str(error), file=sys.stderr)


def install(options):
    requested = normalize_version(options.version)
    require(not options.source_digest or (requested and
            re.fullmatch(r'[0-9a-f]{40}', options.source_digest)),
            'Source digest requires exact version and lowercase 40-character commit')
    if not options.force_download:
        existing = shutil.which('mehscan')
        if existing:
            version = binary_version(existing)
            require(not requested or version == 'mehscan ' + requested[1:],
                    'Mehscan is on PATH but its version differs from the request. No installation attempted.')
            require(not options.source_digest,
                    'Mehscan is on PATH; version cannot establish source provenance. No installation '
                    'attempted. Explicit verified reinstallation requires --force-download.')
            return Path(existing).resolve()
    host, architecture = target()
    require(shutil.which('gh'), 'Recommend installing GitHub CLI for provenance verification; '
            'otherwise build from trusted source with Cargo. No unverified download fallback.')
    run_verifier(['gh', 'attestation', 'verify', '--help'])
    endpoint = 'tags/' + requested if requested else 'latest'
    release = json.loads(download(f'https://api.github.com/repos/{REPO}/releases/{endpoint}', 2097152))
    tag, name, assets = select_release(release, requested, host, architecture)
    pins = json.loads((Path(__file__).parent / '../references/release-pins.json').read_text())
    pin = pins.get(tag)
    require(tag not in pins or (isinstance(pin, str) and re.fullmatch(r'[0-9a-f]{40}', pin)),
            'Malformed release source pin')
    source_digest = options.source_digest or pin
    managed = Path.home() / '.mehscan' / 'cli'
    destination_dir = (Path(options.install_directory).expanduser() if options.install_directory
                       else managed / tag / (host + '-' + architecture)).resolve()
    with tempfile.TemporaryDirectory(prefix='mehscan-install-') as temporary:
        root = Path(temporary)
        for asset in assets:
            size = download(asset['browser_download_url'], asset['size'], root / asset['name'])
            require(size == asset['size'], 'Release download size mismatch')
        archive_path = root / name
        digest = checksum(archive_path, (root / (name + '.sha256')).read_text(), name)
        attestations = json.loads(download(
            f'https://api.github.com/repos/{REPO}/attestations/sha256:{digest}', 4194304))
        bundles = [attestation['bundle'] for attestation in attestations['attestations']]
        require(bundles and all(isinstance(b, dict) for b in bundles), 'Missing attestation bundles')
        bundle_path = root / 'attestations.jsonl'
        bundle_path.write_text('\n'.join(json.dumps(b) for b in bundles), encoding='utf-8')
        run_verifier(verification_arguments(archive_path, bundle_path, tag, source_digest))
        with zipfile.ZipFile(archive_path) as archive:
            validate_archive(archive, tag, host, architecture)
            destination_dir.mkdir(parents=True, exist_ok=True)
            descriptor, staged_path = tempfile.mkstemp(prefix='.mehscan.', dir=destination_dir)
            staged = Path(staged_path)
            try:
                # Never extract archive paths. Only copy the validated root binary.
                with os.fdopen(descriptor, 'wb') as output, archive.open('mehscan') as source:
                    shutil.copyfileobj(source, output, 65536)
                staged.chmod(0o755)
                require(binary_version(staged) == 'mehscan ' + tag[1:], 'Staged binary version mismatch')
                binary = destination_dir / 'mehscan'
                os.replace(staged, binary)
                require(binary_version(binary) == 'mehscan ' + tag[1:], 'Installed binary version mismatch')
            finally:
                staged.unlink(missing_ok=True)
        if not options.install_directory:
            publish_link(binary, managed)
        return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', help='Exact release, e.g. 0.4.0; default: latest')
    parser.add_argument('--install-directory')
    parser.add_argument('--force-download', action='store_true')
    parser.add_argument('--source-digest', help='Independently trusted exact source commit')
    options = parser.parse_args()
    try:
        require(sys.version_info >= (3, 9), 'Python 3.9+ required')
        print(install(options))
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            http.client.HTTPException, subprocess.SubprocessError) as error:
        print('Mehscan installation failed: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
