"""
wordlist_engine.py - Core engine for generating and mutating wordlists.
"""

import itertools
import os
from typing import List, Optional


DEFAULT_CHARSETS = {
    "lowercase": "abcdefghijklmnopqrstuvwxyz",
    "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "numbers":   "0123456789",
    "symbols":   "!@#$%^&*()-_=+[]{};:'",
}

TOKENS = {
    "a": "lowercase",
    "A": "uppercase",
    "1": "numbers",
    "s": "symbols",
    "*": None,
}


def get_charset_sets(selected: Optional[List[str]] = None) -> List[str]:
    if not selected:
        return list(DEFAULT_CHARSETS.values())
    result = []
    for name in selected:
        cs = DEFAULT_CHARSETS.get(name)
        if cs:
            result.append(cs)
    return result or list(DEFAULT_CHARSETS.values())


def resolve_token(token: str, selected_sets: Optional[List[str]] = None) -> str:
    name = TOKENS.get(token)
    if name is None and token != '*':
        raise ValueError(f"Unknown pattern token '{token}'")
    if token == '*':
        return ''.join(get_charset_sets(selected_sets))
    idx = ['lowercase', 'uppercase', 'numbers', 'symbols'].index(name)
    sets = get_charset_sets(selected_sets)
    if idx < len(sets):
        return sets[idx]
    return DEFAULT_CHARSETS[name]


def generate(pattern: str, selected_sets: Optional[List[str]] = None,
             min_len: Optional[int] = None, max_len: Optional[int] = None,
             verbose: bool = False) -> List[str]:
    resolved = [resolve_token(t, selected_sets) for t in pattern]
    if not all(resolved):
        raise ValueError("Invalid pattern or charset combination.")

    total = 1
    for cs in resolved:
        total *= len(cs)
    if verbose:
        print(f"[wordlist_engine] Generating up to {total} candidates...")

    words = []
    for combo in itertools.product(*resolved):
        word = ''.join(combo)
        if min_len and len(word) < min_len:
            continue
        if max_len and len(word) > max_len:
            continue
        words.append(word)
    if verbose:
        print(f"[wordlist_engine] Generated {len(words)} candidates.")
    return words


def save_wordlist(path: str, words: List[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', errors='replace') as f:
        for word in words:
            f.write(word + '\n')


def mutate_leetspeak(words: List[str]) -> List[str]:
    subs = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
    mutated = []
    for w in words:
        m = w.lower()
        for k, v in subs.items():
            m = m.replace(k, v)
        if m != w.lower():
            mutated.append(m)
    return mutated


def mutate_caps(words: List[str]) -> List[str]:
    out = []
    for w in words:
        out.append(w.capitalize())
        if len(w) > 1:
            out.append(w[0].upper() + w[1:])
    return out


def mutate_suffix(words: List[str], suffixes: Optional[List[int]] = None) -> List[str]:
    if suffixes is None:
        suffixes = list(range(2020, 2025)) + [0, 1, 123, 1234, '!']
    out = []
    for w in words:
        for suf in suffixes:
            out.append(f"{w}{suf}")
    return out


def mutate_reverse(words: List[str]) -> List[str]:
    return [w[::-1] for w in words if len(w) > 1]


def mutate_all(words: List[str]) -> List[str]:
    out = set(words)
    out.update(mutate_leetspeak(words))
    out.update(mutate_caps(words))
    out.update(mutate_suffix(words))
    out.update(mutate_reverse(words))
    return list(out)
