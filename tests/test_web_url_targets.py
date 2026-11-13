"""A full URL target must stay one URL in every web-module command.

The preview used to wrap the target in `http://...` even when the target was
already a URL, producing `nuclei -u http://"http://host:8081"` and
`whatweb http://"http://host:8081"` — invalid commands for a supported target
class. These tests pin the normalised URL and the scope host passed to the
executor.
"""
from unittest import mock

from phantom.core.session import session
from phantom.modules.web import WebModule


def _commands() -> list[str]:
    return [command for group in WebModule().build_commands().values()
            for command in group]


def test_url_target_is_not_prefixed_twice():
    previous = session.target
    session.target = "http://192.168.1.50:8081"
    try:
        commands = _commands()
    finally:
        session.target = previous

    assert commands
    for command in commands:
        assert "http://http://" not in command, command
        assert 'http://"http://' not in command, command
        assert "http://'http://" not in command, command
    assert any(command.startswith("whatweb ") for command in commands)
    assert any("192.168.1.50:8081" in command for command in commands)


def test_whatweb_passes_the_url_as_one_argument_and_the_host_for_scope():
    previous = session.target
    session.target = "http://10.0.0.9:8081"
    try:
        with mock.patch("phantom.modules.web.run_command") as run, \
                mock.patch("phantom.modules.web.notifier"):
            run.return_value = ""
            WebModule().do_whatweb("")
    finally:
        session.target = previous

    command = run.call_args.args[0]
    assert "10.0.0.9:8081" in command
    assert "http://http://" not in command
    assert run.call_args.kwargs["target_ip"] == "10.0.0.9"
