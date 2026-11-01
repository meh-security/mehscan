import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    'installed_review', Path(__file__).resolve().parents[2] / 'scripts/test-installed-review.py')
installed_review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installed_review)


class ReleaseDocumentsTest(unittest.TestCase):
    def test_nested_encoded_file_link_and_external_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'docs').mkdir()
            (root / 'docs/guide.md').write_text(
                '[license](<../License File.txt#notice>)\n'
                '[encoded](../License%20File.txt)\n'
                '[source](https://example.com/source) [section](#usage)\n', encoding='utf-8')
            (root / 'License File.txt').write_text('license', encoding='utf-8')
            installed_review.validate_document_links(root, ['docs/guide.md', 'License File.txt'])

    def test_existing_but_unshipped_file_does_not_satisfy_a_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('[guide](guide.md)', encoding='utf-8')
            (root / 'guide.md').write_text('source checkout only', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'README.md.*guide.md'):
                installed_review.validate_document_links(root, ['README.md'])

    def test_missing_file_and_parent_escape_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'package'
            root.mkdir()
            (root.parent / 'outside.md').write_text('outside', encoding='utf-8')
            for target in ['missing.md', '../outside.md', '%2e%2e/outside.md']:
                with self.subTest(target=target):
                    (root / 'README.md').write_text(f'[guide]({target})', encoding='utf-8')
                    with self.assertRaises(ValueError):
                        installed_review.validate_document_links(root, ['README.md'])

    def test_fenced_and_inline_code_examples_are_not_document_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text(
                '```md\n[example](not-a-file.md)\n```\n'
                '~~~~markdown\n[example](not-a-file.md)\n~~~~\n'
                '`[example](not-a-file.md)`\n', encoding='utf-8')
            installed_review.validate_document_links(root, ['README.md'])


if __name__ == '__main__':
    unittest.main()
