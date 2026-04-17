# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the ``scripts/connection_test.py`` probe harness."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# The connection tester lives under ``scripts/`` rather than in the
# installed package (it is invoked directly by the testing workflow),
# so load it via ``importlib`` to make it available to pytest without
# polluting the package layout.
_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "connection_test.py"
_spec = importlib.util.spec_from_file_location("connection_test", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
connection_test = importlib.util.module_from_spec(_spec)
sys.modules["connection_test"] = connection_test
_spec.loader.exec_module(connection_test)

Result = connection_test.Result
Target = connection_test.Target
_probe_once = connection_test._probe_once
parse_targets = connection_test.parse_targets
render_summary = connection_test.render_summary


class TestParseTargets:
    """Unit tests for ``parse_targets``."""

    def test_simple_newline_separated(self) -> None:
        """Parses one entry per line."""
        targets = parse_targets("api.github.com:443\npypi.org:443\n")
        assert targets == [
            Target(host="api.github.com", port=443),
            Target(host="pypi.org", port=443),
        ]

    def test_tolerates_blank_lines_and_crlf(self) -> None:
        """Blank lines and CRLF endings are ignored."""
        raw = "api.github.com:443\r\n\r\npypi.org:443\r\n"
        assert parse_targets(raw) == [
            Target(host="api.github.com", port=443),
            Target(host="pypi.org", port=443),
        ]

    def test_ignores_full_line_comments(self) -> None:
        """A leading ``#`` marks the whole line as a comment."""
        raw = "# header comment\napi.github.com:443\n"
        assert parse_targets(raw) == [Target(host="api.github.com", port=443)]

    def test_ignores_inline_comments(self) -> None:
        """Trailing ``# comment`` on an entry line is stripped."""
        raw = "api.github.com:443  # primary endpoint\npypi.org:443#pkg\n"
        assert parse_targets(raw) == [
            Target(host="api.github.com", port=443),
            Target(host="pypi.org", port=443),
        ]

    def test_space_separated_tokens(self) -> None:
        """Space-separated entries on a single line are supported."""
        targets = parse_targets("a.example:443 b.example:80")
        assert targets == [
            Target(host="a.example", port=443),
            Target(host="b.example", port=80),
        ]

    def test_preserves_duplicates(self) -> None:
        """Duplicates are not collapsed; the caller decides policy."""
        targets = parse_targets("example.com:443\nexample.com:443\n")
        assert len(targets) == 2

    def test_rejects_missing_port(self) -> None:
        """A token without ``:port`` raises ``ValueError``."""
        with pytest.raises(ValueError, match="missing ':port'"):
            parse_targets("example.com\n")

    def test_rejects_non_numeric_port(self) -> None:
        """A non-integer port raises ``ValueError``."""
        with pytest.raises(ValueError, match="invalid port"):
            parse_targets("example.com:abc\n")

    def test_rejects_out_of_range_port(self) -> None:
        """Ports outside 1..65535 are rejected."""
        with pytest.raises(ValueError, match="port out of range"):
            parse_targets("example.com:70000\n")

    def test_rejects_port_zero(self) -> None:
        """Port 0 is rejected."""
        with pytest.raises(ValueError, match="port out of range"):
            parse_targets("example.com:0\n")


class TestRenderSummary:
    """Unit tests for ``render_summary``."""

    @staticmethod
    def _make_results(
        *specs: tuple[str, int, bool, int, str | None],
    ) -> list[object]:
        """Build ``Result`` objects from ``(host, port, connected, attempts, error)``."""
        return [
            Result(
                target=Target(host=h, port=p),
                connected=c,
                attempts=a,
                error=e,
            )
            for h, p, c, a, e in specs
        ]

    def test_permitted_all_passing(self) -> None:
        """A fully-passing permitted run reports 0 failures."""
        results = self._make_results(
            ("api.github.com", 443, True, 1, None),
            ("pypi.org", 443, True, 1, None),
        )
        text, failures = render_summary(results, mode="permitted", connect_timeout=5.0, max_attempts=3)
        assert failures == 0
        assert "**Failures:** 0 / 2" in text
        assert "connected" in text
        assert "## Test PERMITTED Connections" in text

    def test_permitted_with_failure(self) -> None:
        """A failing permitted probe increments the failure count."""
        results = self._make_results(
            ("api.github.com", 443, True, 1, None),
            ("unreachable.example", 443, False, 3, "timeout"),
        )
        text, failures = render_summary(results, mode="permitted", connect_timeout=5.0, max_attempts=3)
        assert failures == 1
        assert "**Failures:** 1 / 2" in text
        assert "FAILED (timeout)" in text

    def test_denied_all_blocked(self) -> None:
        """A fully-blocked denied run reports 0 leaks."""
        results = self._make_results(
            ("www.example.org", 443, False, 1, "refused"),
            ("www.wikipedia.org", 443, False, 1, "refused"),
        )
        text, failures = render_summary(results, mode="denied", connect_timeout=5.0, max_attempts=1)
        assert failures == 0
        assert "**Leaks:** 0 / 2" in text
        assert "blocked (refused)" in text
        assert "## Test DENIED Connections" in text

    def test_denied_with_leak(self) -> None:
        """A connected denied probe counts as a leak."""
        results = self._make_results(
            ("leaky.example", 443, True, 1, None),
            ("www.example.org", 443, False, 1, "refused"),
        )
        text, failures = render_summary(results, mode="denied", connect_timeout=5.0, max_attempts=1)
        assert failures == 1
        assert "**Leaks:** 1 / 2" in text
        assert "LEAKED (connected)" in text

    def test_duplicates_are_preserved_in_totals(self) -> None:
        """Duplicate host:port entries appear twice in the totals."""
        results = self._make_results(
            ("example.com", 443, True, 1, None),
            ("example.com", 443, True, 1, None),
        )
        text, failures = render_summary(results, mode="permitted", connect_timeout=5.0, max_attempts=3)
        assert failures == 0
        # Count of 2 proves duplicates are not deduplicated.
        assert "**Failures:** 0 / 2" in text
        assert text.count("`example.com:443`") == 2


class TestProbeError:
    """Integration check: ``_probe_once`` must not leak IP addresses."""

    def test_refused_error_message_has_no_ip(self) -> None:
        """A refused connect reports a canonical errno message.

        asyncio's own ``str(exc)`` formatting embeds the resolved IP
        address for connect failures. Under harden-runner every denied
        target resolves to the same sinkhole address, which made every
        row of the denied-mode summary look identical and suggested a
        bug. Exercise a real refused connect on ``127.0.0.1:1`` and
        assert that the error string contains neither the address nor
        the port so the summary stays informative.
        """
        import asyncio

        connected, error = asyncio.run(_probe_once(Target("127.0.0.1", 1), 2.0))
        assert connected is False
        assert error is not None
        assert "127.0.0.1" not in error
        assert ":1" not in error
        # Canonical POSIX message across macOS and Linux.
        assert error == "Connection refused"
