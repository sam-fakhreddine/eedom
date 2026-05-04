"""Tests for ScanCode plugin.
# tested-by: tests/unit/test_scancode.py
"""

from __future__ import annotations

from pathlib import Path

from eedom.plugins.scancode import ScanCodePlugin


class TestScanCodePluginDisabled:
    def test_can_run_returns_false_while_disabled(self) -> None:
        """Scancode is temporarily disabled — times out on large repos.
        This test must fail when can_run is re-enabled. See GitHub issue."""
        p = ScanCodePlugin()
        assert p.can_run(["any.py"], Path(".")) is False

    def test_name(self) -> None:
        assert ScanCodePlugin().name == "scancode"
