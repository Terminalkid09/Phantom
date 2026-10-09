"""P1: `help` must not offer what it cannot do.

The C2 used to answer `help` with one flat table mixing listener commands
with commands that only work after `interact <id>`. An operator read
`screenshot` as available and only discovered otherwise by trying — the help
was technically complete and operationally misleading, which is worse than a
short list.

These pin the three filters the registry now applies (scope, prerequisite,
platform) and the honest default: an undeclared prerequisite counts as
blocked, so a newly added command is never advertised before someone says
what it needs.
"""
import unittest

from phantom.core.c2_help import (
    AGENT, AVAILABLE, BEACON_SCOPE, BLOCKED, BY_NAME, COMMANDS, GLOBAL_SCOPE,
    HANDLER, NEEDS_BEACON, NEEDS_REMOTE, commands_for, grouped, is_available,
)


class TestRegistryIntegrity(unittest.TestCase):
    def test_every_spec_declares_a_reachable_dispatch(self):
        # A spec pointing at a do_* that does not exist is help for a command
        # the operator cannot run: the most misleading failure mode there is.
        # Commands the BEACON implements are reached through default(), so
        # they are declared AGENT rather than pretending to have a handler.
        from phantom.core.c2_shell import C2Shell
        shell = C2Shell()
        missing = []
        for spec in COMMANDS:
            if spec.dispatch == AGENT:
                continue
            if not spec.handler or not hasattr(shell, f"do_{spec.handler}"):
                missing.append((spec.name, spec.handler, spec.dispatch))
        self.assertEqual(missing, [],
                         f"registry advertises unreachable commands: {missing}")

    def test_every_usage_string_is_unique(self):
        # `listeners start|stop|<status>` share a NAME on purpose; the usage
        # line is what the operator reads, so THAT must be unambiguous.
        usages = [spec.usage for spec in COMMANDS]
        self.assertEqual(len(usages), len(set(usages)),
                         "duplicate usage strings in the help registry")

    def test_usage_and_description_are_present(self):
        for spec in COMMANDS:
            self.assertTrue(spec.usage.strip(), spec.name)
            self.assertTrue(spec.description.strip(), spec.name)
            self.assertIn(spec.scope, (GLOBAL_SCOPE, BEACON_SCOPE), spec.name)
            self.assertIn(spec.dispatch, (HANDLER, AGENT), spec.name)
            if spec.dispatch == AGENT:
                self.assertEqual(spec.handler, "",
                                 f"{spec.name}: an agent command has no "
                                 "C2 handler to point at")

    def test_by_name_index_is_complete(self):
        for spec in COMMANDS:
            self.assertIn(spec.name, BY_NAME)
        self.assertIs(BY_NAME[list(BY_NAME)[0]], COMMANDS[0])


class TestScopeFiltering(unittest.TestCase):
    def test_the_global_context_offers_no_beacon_only_commands_as_ready(self):
        for spec in commands_for(GLOBAL_SCOPE):
            if spec.scope == BEACON_SCOPE:
                # Listed, so the operator knows they exist...
                self.assertIsNotNone(spec.state_note())
                # ...but never as something they can do right now.
                if spec.prerequisite == AVAILABLE:
                    continue
                self.assertFalse(is_available(spec), spec.name)

    def test_the_beacon_context_is_only_beacon_commands(self):
        specs = commands_for(BEACON_SCOPE)
        self.assertTrue(specs)
        for spec in specs:
            self.assertEqual(spec.scope, BEACON_SCOPE, spec.name)

    def test_a_selected_beacon_unlocks_the_collection_commands(self):
        for name in ("screenshot", "keylog", "results", "health",
                     "set-sleep"):
            spec = BY_NAME[name]
            self.assertFalse(is_available(spec), name)
            self.assertTrue(is_available(spec, active_beacon="B-1"), name)

    def test_listener_and_generate_stay_global(self):
        for name in ("listeners", "beacons", "interact", "generate",
                     "audit", "payloads"):
            self.assertEqual(BY_NAME[name].scope, GLOBAL_SCOPE, name)


class TestPrerequisiteFiltering(unittest.TestCase):
    def test_remote_view_needs_an_active_remote_session(self):
        spec = BY_NAME["remote-view"]
        self.assertEqual(spec.prerequisite, NEEDS_REMOTE)
        self.assertFalse(is_available(spec, active_beacon="B-1"))
        self.assertTrue(is_available(spec, active_beacon="B-1",
                                     has_remote=True))

    def test_an_unknown_prerequisite_is_treated_as_blocked(self):
        # Fail closed: a new command nobody has classified must not be
        # advertised as runnable.
        from phantom.core.c2_help import CommandSpec
        spec = CommandSpec("newcmd", "does a thing", GLOBAL_SCOPE, "X",
                           prerequisite="something-nobody-declared")
        self.assertFalse(is_available(spec))


class TestPlatformGating(unittest.TestCase):
    def test_windows_only_commands_are_refused_on_other_beacons(self):
        for name in ("mem-run", "inject", "migrate"):
            spec = BY_NAME[name]
            self.assertIn("windows", spec.platforms, name)
            self.assertTrue(
                is_available(spec, active_beacon="B-1", beacon_os="windows"),
                name)
            self.assertFalse(
                is_available(spec, active_beacon="B-1", beacon_os="linux"),
                name)

    def test_platform_is_not_enforced_when_the_os_is_unknown(self):
        # Guessing "unsupported" from a missing OS would hide commands that
        # do work; the honest answer is to stay quiet about the gate.
        spec = BY_NAME["mem-run"]
        self.assertTrue(is_available(spec, active_beacon="B-1"))

    def test_the_registry_isolates_the_beacon_injection_commands(self):
        # These are the ones that must never appear runnable by accident.
        for name in ("inject", "inject-tl", "migrate"):
            spec = BY_NAME[name]
            self.assertEqual(spec.scope, BEACON_SCOPE, name)
            self.assertEqual(spec.prerequisite, NEEDS_BEACON, name)


class TestGrouping(unittest.TestCase):
    def test_categories_keep_first_seen_order(self):
        specs = commands_for(GLOBAL_SCOPE)
        names = [name for name, _ in grouped(specs)]
        self.assertEqual(names[0], "Listener")
        self.assertEqual(len(names), len(set(names)), "duplicate category")

    def test_every_command_lands_in_exactly_one_group(self):
        specs = commands_for(GLOBAL_SCOPE)
        total = sum(len(items) for _, items in grouped(specs))
        self.assertEqual(total, len(specs))


if __name__ == "__main__":
    unittest.main()