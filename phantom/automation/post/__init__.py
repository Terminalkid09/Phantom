"""
post/__init__.py — post-exploitation module.

Runs AFTER beacon injection, THROUGH the established beacon channel:
the agent queues tasks to the C2 session and interprets the results back
into findings (persistence / system_privilege / injection).
"""
