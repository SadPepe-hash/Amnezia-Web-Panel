"""Test-suite isolation guard.

``app.py`` resolves ``DATA_FILE`` once at import time and falls back to the
checkout's ``data.json``. A test that forgets to point ``DATA_FILE`` at a
temporary directory therefore rewrites the live file. This actually happened
on a production host: running the suite inside the deployed checkout replaced
the panel's ``data.json`` with a test fixture.

Set ``DATA_FILE`` (and therefore every derived store) to a private temp
directory *before* any test module imports ``app``, and fail the session if
the checkout's ``data.json`` is modified anyway.
"""

import hashlib
import os
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CHECKOUT_DATA = os.path.join(_ROOT, 'data.json')

_TMP = tempfile.mkdtemp(prefix='awp-test-data-')
os.environ['DATA_FILE'] = os.path.join(_TMP, 'data.json')


def _checkout_digest():
    try:
        with open(_CHECKOUT_DATA, 'rb') as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return None


_BEFORE = _checkout_digest()


def pytest_sessionfinish(session, exitstatus):
    """Refuse to report success if a test wrote the checkout's data.json."""
    if _checkout_digest() == _BEFORE:
        return
    print('\nERROR: the test suite modified the checkout data.json; '
          'tests must use DATA_FILE in a temp directory.')
    session.exitstatus = 1
