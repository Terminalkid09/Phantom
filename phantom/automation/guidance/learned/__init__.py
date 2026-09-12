"""learned/ — machine-authored capabilities, loaded automatically.

This package directory IS the production location for capabilities the
evolution loop authored (see phantom/automation/evolution). The registry
scanner (`load_learned`) imports every module here on every boot, so:

  * a capability auto-loaded into a session lives here already —
    when its PR is merged, future boots pick it up with zero plumbing;
  * there are no import lists to update — adding a file IS the
    integration.

Ground rules for every file here (enforced by the evolution gate before
anything is written):
  * self-contained: stdlib + phantom modules only, no learned-to-learned
    imports;
  * exposes exactly one module-level `CAPABILITY` (a commands.Capability,
    normally built with kit._mk);
  * id must carry the `learned.` prefix so provenance is visible in plans,
    reports and the audit log.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import pkgutil
from typing import List

log = logging.getLogger(__name__)

# Loaded capability ids are stamped into plans/reports; keep the prefix
# reserved so nothing else can forge learned provenance.
LEARNED_PREFIX = "learned."


def load_learned():
    """Import every module in this package; return the capabilities found.

    Import order is alphabetical and deterministic. A module that raises
    on import is skipped with a warning — one broken learned file must
    never take the whole auto-mode down (it is machine-authored code).
    """
    from phantom.automation.guidance import commands as _commands
    from phantom.automation.guidance import kit as _kit

    caps: List[_commands.Capability] = []
    for mod in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        name = f"{__name__}.{mod.name}"
        try:
            m = importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 — never break the boot
            log.warning("learned capability %s failed to import: %s", name, exc)
            continue
        cap = getattr(m, "CAPABILITY", None)
        if cap is None or not isinstance(cap, _commands.Capability):
            continue
        if not getattr(cap, "id", "").startswith(LEARNED_PREFIX):
            log.warning("learned module %s: capability id %r lacks the %s "
                        "prefix — skipped", name, getattr(cap, "id", "?"),
                        LEARNED_PREFIX)
            continue
        caps.append(cap)
    return caps
