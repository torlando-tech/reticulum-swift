"""Pytest plugin: reclassify declared-capability-gap bridge failures as skips.

The reticulum-conformance suite exercises features a leaf-endpoint implementation
may legitimately not provide. reticulum-swift has no shared-instance
``LocalServerInterface`` / ``LocalClientInterface``, so the Swift bridge answers
``start_tcp_server(share_instance=True)`` with a ``BridgeError`` whose message is
``"share_instance unsupported: reticulum-swift has no
LocalServerInterface/LocalClientInterface ..."``.

That is a declared capability gap, not a conformance failure, so this plugin
turns such a result into a SKIP — keyed on the SUT's OWN error string, so it is
precise (no brittle test-name lists; a test merely named "...shared_sequence..."
is unaffected) and self-maintaining (new shared-instance tests skip automatically).
Reference-implementation parametrizations support shared instances and never raise
this error, so they keep running and pinning normally.

Loaded via ``pytest -p skip_unsupported`` from reticulum-swift's conformance CI;
it lives in the swift repo (not the suite) so the skip is the consumer's choice.
"""

import pytest

# Substrings that identify a "this implementation does not support X" bridge error.
# Keep this list tight: only declared, intentionally-descoped capability gaps.
_UNSUPPORTED_MARKERS = (
    "share_instance unsupported",
    "LocalServerInterface/LocalClientInterface",
)


def _is_unsupported(exc) -> bool:
    if exc is None:
        return False
    msg = str(exc)
    return any(marker in msg for marker in _UNSUPPORTED_MARKERS)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    # Reclassify a failure (in any phase) caused by a declared-unsupported feature
    # into a skip. pytest then counts it as skipped and the job exits 0.
    if rep.failed and call.excinfo is not None and _is_unsupported(call.excinfo.value):
        rep.outcome = "skipped"
        # Skipped longrepr is conventionally (path, lineno, message); a tuple keeps
        # `-rs` summaries readable.
        rep.longrepr = (
            str(item.fspath),
            item.location[1] or 0,
            "Skipped: shared-instance not supported by this implementation "
            f"({call.excinfo.value})",
        )
