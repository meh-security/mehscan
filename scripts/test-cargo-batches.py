"""Run all default-member Cargo targets without retaining every test executable."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def commands(metadata, batch_size):
    yield ['cargo', 'test', '--locked', '--lib', '--bins', '--examples', '--benches']
    members = set(metadata['workspace_default_members'])
    for package in metadata['packages']:
        if package['id'] not in members:
            continue
        targets = sorted(t['name'] for t in package['targets'] if 'test' in t['kind'])
        for start in range(0, len(targets), batch_size):
            command = ['cargo', 'test', '--locked', '-p', package['name']]
            for name in targets[start:start + batch_size]:
                command += ['--test', name]
            yield command


def remove_executables(executables, target):
    # Only Cargo-reported test products in debug/deps, never libraries or trees.
    deps = (target / 'debug' / 'deps').resolve()
    removed = 0
    for executable in executables:
        path = Path(executable)
        if path.resolve().parent != deps or path.is_symlink():
            continue
        for product in [path, path.with_suffix('.pdb')]:
            if product.resolve().parent == deps and not product.is_symlink() and product.is_file():
                removed += product.stat().st_size
                product.unlink()
    return removed


def run(command, target):
    executables = set()
    print('+ ' + ' '.join(command), flush=True)
    try:
        with subprocess.Popen(command + ['--message-format=json'], stdout=subprocess.PIPE,
                              text=True, encoding='utf-8', errors='replace') as process:
            for line in process.stdout:
                try:
                    message = json.loads(line)
                except ValueError:
                    print(line, end='', flush=True)
                    continue
                if not isinstance(message, dict) or 'reason' not in message:
                    print(line, end='', flush=True)
                elif message['reason'] == 'compiler-artifact' and message.get('executable'):
                    executables.add(message['executable'])
                elif message['reason'] == 'compiler-message':
                    print(message['message'].get('rendered', ''), end='', flush=True)
            code = process.wait()
        if code:
            raise subprocess.CalledProcessError(code, command)
    finally:
        print(f'Released {remove_executables(executables, target):,} bytes of test executables.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch-size', type=int, default=16)
    parser.add_argument('--list', action='store_true', help='Print the complete target plan without running tests.')
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 64:
        parser.error('batch-size must be between 1 and 64')
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--no-deps', '--format-version', '1', '--locked'], text=True, encoding='utf-8'))
    for command in commands(metadata, args.batch_size):
        if args.list:
            print(' '.join(command))
        else:
            run(command, Path(metadata['target_directory']))


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
