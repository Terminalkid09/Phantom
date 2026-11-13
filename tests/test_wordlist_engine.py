"""Tests for the wordlist generation engine."""
import os
import tempfile
import unittest

from phantom.utils.wordlist_engine import (
    generate, save_wordlist, mutate_leetspeak, mutate_caps,
    mutate_reverse, mutate_suffix, mutate_all, resolve_token
)


class TestPatternResolution(unittest.TestCase):

    def test_lowercase_token(self):
        self.assertEqual(resolve_token('a'), 'abcdefghijklmnopqrstuvwxyz')

    def test_uppercase_token(self):
        self.assertEqual(resolve_token('A'), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')

    def test_number_token(self):
        self.assertEqual(resolve_token('1'), '0123456789')

    def test_symbol_token(self):
        self.assertIn('!', resolve_token('s'))

    def test_any_token_combines_all(self):
        combined = resolve_token('*')
        self.assertIn('a', combined)
        self.assertIn('Z', combined)
        self.assertIn('5', combined)
        self.assertIn('!', combined)

    def test_unknown_token_raises(self):
        with self.assertRaises(ValueError):
            resolve_token('z')


class TestGeneration(unittest.TestCase):

    def test_simple_pattern(self):
        result = generate('aa')
        self.assertEqual(len(result), 26 * 26)

    def test_mixed_pattern(self):
        result = generate('a1')
        self.assertEqual(len(result), 26 * 10)

    def test_min_length_filter(self):
        result = generate('a1', min_len=2)
        self.assertTrue(all(len(w) >= 2 for w in result))

    def test_max_length_filter(self):
        result = generate('aaaa', max_len=2)
        self.assertTrue(all(len(w) <= 2 for w in result))

    def test_single_char(self):
        result = generate('a')
        self.assertEqual(len(result), 26)

    def test_invalid_pattern_raises(self):
        with self.assertRaises(ValueError):
            generate('zz')


class TestSave(unittest.TestCase):

    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.txt")
            save_wordlist(path, ["abc", "def"])
            self.assertTrue(os.path.isfile(path))
            with open(path) as f:
                content = f.read()
            self.assertIn("abc", content)
            self.assertIn("def", content)


class TestMutations(unittest.TestCase):

    def test_leetspeak(self):
        original = ['password']
        mutated = mutate_leetspeak(original)
        # Both 's' chars become '$' per substitution rules
        self.assertIn('p@$$w0rd', mutated)

    def test_caps_variant(self):
        original = ['hello']
        mutated = mutate_caps(original)
        self.assertIn('Hello', mutated)

    def test_suffix(self):
        original = ['admin']
        mutated = mutate_suffix(original, suffixes=[123])
        self.assertIn('admin123', mutated)

    def test_reverse(self):
        original = ['abc']
        mutated = mutate_reverse(original)
        self.assertIn('cba', mutated)

    def test_mutate_all(self):
        original = ['secret']
        mutated = mutate_all(original)
        self.assertIn('secret', mutated)
        self.assertGreater(len(mutated), 1)


if __name__ == "__main__":
    unittest.main()
