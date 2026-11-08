"""All shipped locales must cover the English/Russian reference keys."""
import collections
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'translations'


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate translation key: {key}')
        result[key] = value
    return result


class TranslationCompletenessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.locales = {
            path.stem: json.loads(path.read_text(encoding='utf-8'),
                                  object_pairs_hook=unique_object)
            for path in ROOT.glob('*.json')
        }

    def test_reference_languages_have_identical_keys(self):
        self.assertEqual(set(self.locales['en']), set(self.locales['ru']))

    def test_all_locales_cover_reference_keys(self):
        expected = set(self.locales['en']) | set(self.locales['ru'])
        for lang, values in self.locales.items():
            with self.subTest(lang=lang):
                self.assertEqual(set(values), expected)

    def test_values_are_nonempty_strings(self):
        for lang, values in self.locales.items():
            for key, value in values.items():
                with self.subTest(lang=lang, key=key):
                    self.assertIsInstance(value, str)
                    self.assertTrue(value.strip())

    def test_format_placeholders_are_preserved(self):
        for lang, values in self.locales.items():
            for key, value in values.items():
                if key not in self.locales['en']:
                    continue
                with self.subTest(lang=lang, key=key):
                    self.assertEqual(
                        collections.Counter(re.findall(r'\{[^{}]*\}', value)),
                        collections.Counter(re.findall(r'\{[^{}]*\}', self.locales['en'][key])),
                    )


if __name__ == '__main__':
    unittest.main()
