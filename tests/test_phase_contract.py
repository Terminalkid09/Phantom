"""The phase contract gate: every phase package is standalone, exposes
capabilities/adapters/interpreters, never imports another phase, and
the phase index maps every registry capability to exactly one phase."""
import ast
import os
import unittest

from phantom.automation.guidance.commands import make_registry
from phantom.automation.phases import (
    PHASE_ORDER,
    _CAPABILITY_PHASE,
    capabilities_of,
    load_phase,
    phase_of,
    phases,
)

PHASES_DIR = os.path.join("phantom", "automation", "phases")
REQUIRED = ("capabilities.py", "adapters.py", "interpreters.py")

# capability ids declared in the registry (kit.py)
ALL_REGISTRY_IDS = {c.id for c in make_registry().all()}

# capability ids declared across all phase capabilities.py files
DECLARED = {}
for phase in PHASE_ORDER:
    from importlib import import_module
    cap_mod = import_module(f"phantom.automation.phases.{phase}.capabilities")
    attr = f"{phase.upper()}_CAPABILITY_IDS"
    DECLARED[phase] = set(getattr(cap_mod, attr))


class TestPhaseContract(unittest.TestCase):
    def test_phase_list_complete(self):
        self.assertEqual(
            PHASE_ORDER,
            ("recon", "osint", "exploit", "foothold", "beacon", "post", "report"))

    def test_every_phase_has_contract_files(self):
        for phase in PHASE_ORDER:
            for name in REQUIRED:
                path = os.path.join(PHASES_DIR, phase, name)
                self.assertTrue(os.path.exists(path), f"missing {path}")

    def test_every_phase_imports_standalone(self):
        for phase in PHASE_ORDER:
            from importlib import import_module
            import_module(f"phantom.automation.phases.{phase}.capabilities")
            import_module(f"phantom.automation.phases.{phase}.adapters")
            import_module(f"phantom.automation.phases.{phase}.interpreters")

    def test_phase_capabilities_resolve_in_live_registry(self):
        reg = make_registry()
        for phase in PHASE_ORDER:
            caps = load_phase(phase).capabilities.phase_capabilities(reg)
            # report declares no registry capabilities by design
            if phase == "report":
                self.assertEqual(caps, [])
                continue
            self.assertTrue(caps, f"{phase} phase resolved no capabilities")
            self.assertTrue(all(hasattr(c, "id") for c in caps))

    def test_index_covers_every_registry_capability(self):
        undeclared = ALL_REGISTRY_IDS - set(_CAPABILITY_PHASE)
        self.assertEqual(
            undeclared, set(),
            f"registry capabilities missing from phase index: {undeclared}")

    def test_index_consistent_with_declarations(self):
        for phase in PHASE_ORDER:
            declared = DECLARED[phase]
            indexed = set(capabilities_of(phase))
            self.assertEqual(
                declared, indexed,
                f"{phase}: capabilities.py ids != phase index")

    def test_no_duplicate_ownership(self):
        owners = {}
        for cid, phase in _CAPABILITY_PHASE.items():
            owners.setdefault(cid, []).append(phase)
        dupes = {cid: ps for cid, ps in owners.items() if len(ps) > 1}
        self.assertEqual(dupes, {})

    def test_phase_of_resolves(self):
        self.assertEqual(phase_of("scan_tcp"), "recon")
        self.assertEqual(phase_of("beacon_deploy"), "beacon")
        self.assertIsNone(phase_of("not_a_capability"))

    def test_adapters_are_callable(self):
        for phase in PHASE_ORDER:
            mod = load_phase(phase)
            if not hasattr(mod, "adapters"):
                continue
            # every adapter attribute must be callable (functions or
            # callable objects re-exported from the live registry)
            for name in dir(mod.adapters):
                # "annotations" is the __future__ feature object bound by
                # `from __future__ import annotations`, not an adapter (the
                # interpreter test excludes it too). It only shows up once
                # the submodule has been imported by someone else, which is
                # why this used to fail by test ordering.
                if name.startswith("_") or name == "annotations":
                    continue
                fn = getattr(mod.adapters, name)
                self.assertTrue(callable(fn), f"{phase}.adapters.{name}")

    def test_interpreters_are_callable(self):
        for phase in PHASE_ORDER:
            mod = load_phase(phase)
            if not hasattr(mod, "interpreters"):
                continue
            for name in dir(mod.interpreters):
                if name.startswith("_") or name == "annotations":
                    continue
                fn = getattr(mod.interpreters, name)
                self.assertTrue(callable(fn), f"{phase}.interpreters.{name}")

    def test_no_cross_phase_imports(self):
        """Phases must NEVER import each other: isolation is the point."""
        for phase in os.listdir(PHASES_DIR):
            pkg = os.path.join(PHASES_DIR, phase)
            if not os.path.isdir(pkg) or phase.startswith("__"):
                continue
            for fname in os.listdir(pkg):
                if not fname.endswith(".py") or fname.startswith("__"):
                    continue
                path = os.path.join(pkg, fname)
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.module:
                        assert not node.module.startswith(
                            "phantom.automation.phases."), \
                            f"{path} imports another phase: {node.module}"
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            assert not alias.name.startswith(
                                "phantom.automation.phases."), \
                                f"{path} imports another phase: {alias.name}"

    def test_phases_list(self):
        self.assertEqual(len(phases()), len(PHASE_ORDER))


if __name__ == "__main__":
    unittest.main()