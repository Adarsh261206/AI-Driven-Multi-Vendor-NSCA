"""Root pytest configuration (STEP 7).

Forces the Celery test broker BEFORE any app module is imported so task
publishing never needs a live broker and tasks never auto-run in tests:
- memory:// transport accepts .delay() without a server
- eager mode stays OFF: worker logic is tested explicitly (direct .apply()
  in sync tests, service functions in async tests), never implicitly

Worker behavior against a REAL broker is covered by live E2E, not unit tests.
"""

import os

os.environ.setdefault("CELERY_BROKER_URL", "memory://")
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "false")
