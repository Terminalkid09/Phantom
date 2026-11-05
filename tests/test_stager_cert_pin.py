"""The Windows stager must not execute bytes from an unverified channel.

Measured 2026-11-05: the PIC stager set
``ServerCertificateValidationCallback={$true}`` before ``DownloadData``, so
every certificate was accepted — and the fetched bytes are mapped and executed
in the same process. Pinning the C2's own certificates keeps the self-signed
workflow without turning the staging channel into a code-execution primitive.
"""
import pytest

from phantom.utils import builder


def test_pinned_statement_names_every_c2_certificate():
    pins = builder._stager_cert_thumbprints()
    statement = builder._stager_cert_pin_statement()
    if not pins:
        pytest.skip("no C2 certificate on this checkout (HTTP-only deploy)")
    for thumb in pins:
        assert thumb in statement
    assert "GetCertHashString" in statement
    assert "{$true}" not in statement


def test_the_served_stager_carries_the_pin_not_a_blanket_override():
    script = builder.windows_stager_script("127.0.0.1", 8443, use_ssl=True)
    pins = builder._stager_cert_thumbprints()
    if pins:
        for thumb in pins:
            assert thumb in script
        assert "Callback={$true}" not in script
    else:
        assert "Callback={$true}" in script


def test_a_thumbprint_is_40_hex_chars():
    for thumb in builder._stager_cert_thumbprints():
        assert len(thumb) == 40
        int(thumb, 16)
