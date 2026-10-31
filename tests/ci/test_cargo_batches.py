import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

SPEC = importlib.util.spec_from_file_location('batches', Path(__file__).resolve().parents[2] / 'scripts/test-cargo-batches.py')
batches = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(batches)


class CargoBatchesTest(unittest.TestCase):
    def test_every_default_integration_target_once_and_other_target_kinds_retained(self):
        metadata = {'workspace_default_members': ['a', 'b'], 'packages': [
            {'id': 'a', 'name': 'engine', 'targets': [{'name': str(n), 'kind': ['test']} for n in range(35)]},
            {'id': 'b', 'name': 'cli', 'targets': [{'name': 'cli_test', 'kind': ['test']}, {'name': 'main', 'kind': ['bin']}]},
            {'id': 'dependency', 'name': 'dependency', 'targets': [{'name': 'external', 'kind': ['test']}]},
        ]}
        commands = list(batches.commands(metadata, 16))
        self.assertEqual(commands[0], ['cargo', 'test', '--locked', '--lib', '--bins', '--examples', '--benches'])
        selected = [(c[c.index('-p') + 1], c[i + 1]) for c in commands[1:] for i, flag in enumerate(c) if flag == '--test']
        self.assertCountEqual(selected, [('engine', str(n)) for n in range(35)] + [('cli', 'cli_test')])
        self.assertEqual(len(selected), len(set(selected)))
        self.assertTrue(all(c.count('--test') <= 16 for c in commands[1:]))

    def test_cleanup_preserves_dependencies_and_products_outside_deps(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            deps = target / 'debug/deps'
            deps.mkdir(parents=True)
            executable, pdb, library = deps / 'test-123.exe', deps / 'test-123.pdb', deps / 'engine.rlib'
            outside = Path(directory) / 'outside.exe'
            for path in [executable, pdb, library, outside]:
                path.write_bytes(b'keep-or-remove')
            batches.remove_executables([str(executable), str(outside), str(deps / '../..' / 'outside.exe')], target)
            self.assertFalse(executable.exists())
            self.assertFalse(pdb.exists())
            self.assertTrue(library.exists())
            self.assertTrue(outside.exists())

    def test_failed_batch_is_not_hidden_and_its_executables_are_released(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            deps = target / 'debug/deps'
            deps.mkdir(parents=True)
            executable = deps / 'test-123.exe'
            executable.write_bytes(b'test')
            message = {'reason': 'compiler-artifact', 'executable': str(executable)}
            program = 'import sys; print(' + repr(json.dumps(message)) + '); sys.exit(7)'
            with self.assertRaises(subprocess.CalledProcessError) as result:
                batches.run([sys.executable, '-c', program], target)
            self.assertEqual(result.exception.returncode, 7)
            self.assertFalse(executable.exists())


if __name__ == '__main__':
    unittest.main()
