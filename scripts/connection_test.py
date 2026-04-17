#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Connection allowlist validator.

Parallel TCP connect tests for GitHub Actions hardening workflows.

The script reads a newline-separated list of ``host:port`` targets from
an environment variable and probes each one concurrently using
``asyncio``. Two modes are supported:

* ``permitted`` — targets are expected to connect. Each target is
  retried up to ``--max-attempts`` times with ``--connect-timeout``
  seconds per attempt. A failure to connect is a test failure.
* ``denied`` — targets are expected to be blocked. A single attempt is
  made per target (retries would only slow down the wall-clock). A
  successful connection is a test failure (the allowlist leaked).

Why a Python script rather than inline bash?

* Cancellation is instantaneous: ``asyncio`` wait-groups plus SIGTERM
  / SIGINT handlers tear down every in-flight probe when the runner
  cancels the step. Background bash probes under ``timeout`` routinely
  outlive their parent shell, which is why the previous workflow
  iteration kept hanging on cancel.
* Wall-clock is bounded deterministically. ``--overall-timeout`` caps
  the entire probe phase; results collected so far are still rendered
  to ``$GITHUB_STEP_SUMMARY`` and the exit status reflects the verdict.
* Expected pass/fail counts derive from the number of input lines, so
  the job scales as you add or remove endpoints from the variable.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Mode = Literal["permitted", "denied"]


@dataclass(frozen=True)
class Target:
    """A parsed ``host:port`` target."""

    host: str
    port: int

    @property
    def label(self) -> str:
        """Return the canonical ``host:port`` label."""
        return f"{self.host}:{self.port}"


@dataclass
class Result:
    """Outcome of probing a single target."""

    target: Target
    connected: bool
    attempts: int
    error: str | None


def parse_targets(raw: str) -> list[Target]:
    """Parse a whitespace-separated list of ``host:port`` entries.

    Blank lines, full-line comments (``#``) and inline trailing
    comments (``host:port  # comment``) are tolerated so the variable
    can be edited comfortably in the GitHub Actions UI. Surrounding
    whitespace is ignored.
    """

    targets: list[Target] = []
    for raw_line in raw.replace("\r", "\n").split("\n"):
        # Strip inline comments before tokenising so a trailing
        # ``# note`` on the same line does not confuse the parser.
        line = raw_line.split("#", 1)[0]
        for token in line.split():
            if not token:
                continue
            if ":" not in token:
                raise ValueError(f"missing ':port' in target: {token!r}")
            host, _, port_str = token.rpartition(":")
            if not host or not port_str:
                raise ValueError(f"invalid target: {token!r}")
            try:
                port = int(port_str)
            except ValueError as exc:
                raise ValueError(f"invalid port in target {token!r}: {port_str!r}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range in target {token!r}: {port}")
            targets.append(Target(host=host, port=port))
    return targets


async def _probe_once(target: Target, timeout: float) -> tuple[bool, str | None]:
    """Perform a single TCP connect. Returns (connected, error)."""

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port),
            timeout=timeout,
        )
    except TimeoutError:
        return False, "timeout"
    except OSError as exc:
        # asyncio synthesises ``strerror`` / ``str(exc)`` messages that
        # embed the resolved IP address (e.g. "Connect call failed
        # ('54.185.253.63', 443)"). For denied endpoints that IP is just
        # the harden-runner sinkhole, which makes every row of the
        # summary look identical and suggests a bug. Prefer the canonical
        # ``os.strerror(errno)`` (e.g. "Connection refused") when errno
        # is set, and fall back to the exception class name otherwise.
        if exc.errno:
            return False, os.strerror(exc.errno)
        return False, type(exc).__name__
    else:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass
        del reader
        return True, None


async def probe_target(
    target: Target,
    *,
    mode: Mode,
    connect_timeout: float,
    max_attempts: int,
) -> Result:
    """Probe ``target`` according to ``mode`` and return the outcome."""

    # Denied targets should never connect; a single attempt is enough
    # and avoids slowing the job down waiting for multiple timeouts on
    # a correctly-blocked endpoint.
    attempts_allowed = 1 if mode == "denied" else max_attempts
    last_error: str | None = None
    for attempt in range(1, attempts_allowed + 1):
        connected, error = await _probe_once(target, connect_timeout)
        if connected:
            return Result(target=target, connected=True, attempts=attempt, error=None)
        last_error = error
    return Result(
        target=target,
        connected=False,
        attempts=attempts_allowed,
        error=last_error,
    )


async def run_probes(
    targets: list[Target],
    *,
    mode: Mode,
    connect_timeout: float,
    max_attempts: int,
    overall_timeout: float,
) -> list[Result]:
    """Probe all targets concurrently under a global wall-clock cap."""

    tasks = [
        asyncio.create_task(
            probe_target(
                target,
                mode=mode,
                connect_timeout=connect_timeout,
                max_attempts=max_attempts,
            ),
            name=f"probe:{target.label}",
        )
        for target in targets
    ]
    try:
        done = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=False),
            timeout=overall_timeout,
        )
    except TimeoutError:
        # Collect whatever has completed; mark the rest as timed out.
        done = []
        for task, target in zip(tasks, targets, strict=True):
            if task.done() and not task.cancelled():
                exc = task.exception()
                if exc is None:
                    done.append(task.result())
                    continue
            task.cancel()
            done.append(
                Result(
                    target=target,
                    connected=False,
                    attempts=0,
                    error="overall-timeout",
                )
            )
        # Allow cancelled tasks to finalise so we don't leak warnings.
        await asyncio.gather(*tasks, return_exceptions=True)
    return list(done)


def render_summary(
    results: list[Result],
    *,
    mode: Mode,
    connect_timeout: float,
    max_attempts: int,
) -> tuple[str, int]:
    """Render a markdown summary and return (text, failure_count)."""

    # Preserve duplicate entries: keying by label would silently hide
    # misconfigurations where the same host:port is listed twice.
    ordered = sorted(results, key=lambda r: r.target.label)

    if mode == "permitted":
        heading = "## Test PERMITTED Connections"
        blurb = (
            "Endpoints expected to be reachable through the "
            "`CONNECTION_WHITELIST`. Each probe is retried up to "
            f"**{max_attempts}** times with a **{connect_timeout:g}s** "
            "per-attempt timeout."
        )
        columns = "| Endpoint | Expected | Attempts | Result |"
        sep = "| -------- | -------- | -------- | ------ |"
    else:
        heading = "## Test DENIED Connections"
        blurb = (
            "Endpoints expected to be blocked by harden-runner (not "
            "present in `CONNECTION_WHITELIST`). Each probe is a "
            f"single **{connect_timeout:g}s** attempt; any failure to "
            "connect within that attempt is treated as blocked "
            "(harden-runner redirects denied DNS lookups to its "
            "sinkhole address and refuses the TCP connect, so "
            '"Connection refused" is the expected outcome, but '
            "DROP-style firewalls may time out instead)."
        )
        columns = "| Endpoint | Expected | Result |"
        sep = "| -------- | -------- | ------ |"

    lines = [heading, "", blurb, "", columns, sep]
    failures = 0
    for result in ordered:
        if mode == "permitted":
            if result.connected:
                verdict = "connected"
            else:
                verdict = f"FAILED ({result.error or 'no connection'})"
                failures += 1
            lines.append(f"| `{result.target.label}` | allowed | {result.attempts} | {verdict} |")
        else:
            if result.connected:
                verdict = "LEAKED (connected)"
                failures += 1
            else:
                verdict = f"blocked ({result.error or 'no connection'})"
            lines.append(f"| `{result.target.label}` | blocked | {verdict} |")

    total = len(ordered)
    label = "Failures" if mode == "permitted" else "Leaks"
    lines.extend(["", f"**{label}:** {failures} / {total}", ""])
    return "\n".join(lines), failures


def append_summary(text: str) -> None:
    """Append ``text`` to ``$GITHUB_STEP_SUMMARY`` when available."""

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")
    except OSError as exc:
        print(
            f"::warning::Could not write to GITHUB_STEP_SUMMARY: {exc}",
            file=sys.stderr,
        )


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Install signal handlers so cancellation is near-instant."""

    def _cancel_all() -> None:
        for task in asyncio.all_tasks(loop):
            task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _cancel_all)
        except (NotImplementedError, RuntimeError):
            # Windows / restricted environments: fall back silently.
            pass


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the CLI."""

    parser = argparse.ArgumentParser(
        description=(
            "Probe a list of host:port endpoints and assert they are "
            "reachable (permitted mode) or blocked (denied mode)."
        )
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=("permitted", "denied"),
        help="Test mode: 'permitted' (must connect) or 'denied' (must fail).",
    )
    parser.add_argument(
        "--targets-env",
        required=True,
        help="Name of the environment variable holding the target list.",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=5.0,
        help="Per-attempt TCP connect timeout in seconds (default: 5).",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=3,
        help="Max attempts per permitted target (default: 3).",
    )
    parser.add_argument(
        "--overall-timeout",
        type=float,
        default=60.0,
        help="Hard wall-clock cap for the whole run in seconds (default: 60).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""

    args = build_parser().parse_args(argv)
    raw = os.environ.get(args.targets_env, "")
    if not raw.strip():
        print(
            f"::error::Environment variable {args.targets_env} is empty or unset",
            file=sys.stderr,
        )
        return 2
    try:
        targets = parse_targets(raw)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2
    if not targets:
        print(
            f"::error::No targets parsed from {args.targets_env}",
            file=sys.stderr,
        )
        return 2

    mode: Mode = args.mode
    print(
        f"Probing {len(targets)} target(s) in {mode} mode "
        f"(connect_timeout={args.connect_timeout}s, "
        f"max_attempts={args.max_attempts}, "
        f"overall_timeout={args.overall_timeout}s)"
    )
    for target in targets:
        print(f"  - {target.label}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_signal_handlers(loop)
    start = time.monotonic()
    try:
        results = loop.run_until_complete(
            run_probes(
                targets,
                mode=mode,
                connect_timeout=args.connect_timeout,
                max_attempts=args.max_attempts,
                overall_timeout=args.overall_timeout,
            )
        )
    except asyncio.CancelledError:
        print("::warning::Probe run was cancelled", file=sys.stderr)
        return 130
    finally:
        loop.close()
    elapsed = time.monotonic() - start

    summary, failures = render_summary(
        results,
        mode=mode,
        connect_timeout=args.connect_timeout,
        max_attempts=args.max_attempts,
    )
    summary += f"_Completed in {elapsed:.1f}s._\n"
    append_summary(summary)
    print(summary)

    if failures:
        noun = "blocked" if mode == "permitted" else "reached"
        print(
            f"::error::{failures} endpoint(s) were unexpectedly {noun}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
