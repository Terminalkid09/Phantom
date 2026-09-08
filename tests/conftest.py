"""Shared pytest configuration for the Phantom test suite.

Excludes standalone integration scripts from collection. These are NOT
pytest tests — they compile the Windows beacon, boot a real C2 server, do
live HTTP and (in the deploy case) run a real beacon process with
keylogger/persistence. They call sys.exit() at module level and are run
manually (or by the release workflow), never collected by pytest.
"""
collect_ignore = [
    "test_features_final.py",   # standalone beacon+C2 integration script
    "test_real_deploy.py",      # standalone real-beacon deploy script
]
