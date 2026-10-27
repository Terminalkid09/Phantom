"""Local, per-phase training pipeline for Phantom's bounded models.

Nothing in this package is imported by the runtime: the production code
reads only the resulting manifest (``phantom.automation.ai.registry``). That
separation is deliberate — a missing GPU, torch or model file must never
break a Phantom run.
"""

__all__ = ["phases", "manifest", "build_dataset", "curate", "eval",
           "train_lora", "export"]

PIPELINE_VERSION = "1"
