"""sandbox — pre-flight validation of payloads before real deployment.

Two validation layers, both free:
  1. Docker mirror (default): run the sample in a disposable container
     with no network and constrained resources; it must execute cleanly.
  2. Windows Defender (gold): a Windows eval VM runs Defender on the
     sample; any detection = the payload is burned for this target.
"""
