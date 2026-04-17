# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""CLI interface for GitHub Network Audit."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from github_network_audit.collector import NetworkAuditCollector
from github_network_audit.reporter import NetworkAuditReporter

app = typer.Typer(
    name="github-network-audit",
    help="Audit outbound network connections from GitHub Actions.",
)
console = Console()


@app.command()
def collect(
    org: str = typer.Option(
        "lfreleng-actions",
        help="GitHub organization to audit.",
    ),
    repo: Optional[str] = typer.Option(
        None,
        help="Specific repository to audit.",
    ),
    output_dir: Path = typer.Option(
        Path("."),
        help="Output directory for cached data.",
    ),
    refresh: bool = typer.Option(
        False,
        help="Force refresh of cached data.",
    ),
    github_token: Optional[str] = typer.Option(
        None,
        envvar="GITHUB_TOKEN",
        help="GitHub API token for GraphQL queries.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable verbose logging output.",
    ),
) -> None:
    """Collect network endpoint data from workflow runs."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    collector = NetworkAuditCollector(
        org=org,
        output_dir=output_dir,
        github_token=github_token,
    )

    console.print(
        f"[bold]Fetching repositories for: {org}[/bold]",
    )
    repos = collector.fetch_repos(refresh=refresh)
    active = [r for r in repos if not r.get("isArchived")]
    console.print(
        f"  Found {len(repos)} repos ({len(active)} active)",
    )

    if repo:
        repo_names = [repo]
    else:
        repo_names = [r["name"] for r in active]

    for repo_name in repo_names:
        console.print()
        console.print(
            f"[bold cyan]Processing: {repo_name}[/bold cyan]",
        )

        runs = collector.fetch_repo_runs(
            repo_name, refresh=refresh,
        )
        console.print(f"  Total runs tracked: {len(runs)}")

        detail_runs = [
            r for r in runs if r.get("destination_count", 0) > 0
        ]
        console.print(
            f"  Runs with network data: {len(detail_runs)}",
        )

        for i, run in enumerate(detail_runs):
            run_id = run["id"]
            collector.fetch_run_detail(
                repo_name, run_id, refresh=refresh,
            )
            if (i + 1) % 10 == 0 or (i + 1) == len(detail_runs):
                console.print(
                    f"    Fetched {i + 1}/{len(detail_runs)} details",
                )

        console.print(
            f"  [green]✓[/green] Done with {repo_name}",
        )

    console.print()
    console.print(
        "[bold green]✓ Collection complete![/bold green]",
    )


@app.command()
def report(
    org: str = typer.Option(
        "lfreleng-actions",
        help="GitHub organization.",
    ),
    output_dir: Path = typer.Option(
        Path("."),
        help="Directory with cached data.",
    ),
    output_format: str = typer.Option(
        "all",
        help="Output format: md, csv, json, or all.",
    ),
    repo: Optional[str] = typer.Option(
        None,
        help="Report for specific repo only.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Enable verbose logging output.",
    ),
) -> None:
    """Generate reports from cached data."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    reporter = NetworkAuditReporter(
        org=org, output_dir=output_dir,
    )

    console.print(
        f"[bold]Generating reports for: {org}[/bold]",
    )
    allowlist = reporter.generate_reports(
        output_format=output_format, repo_filter=repo,
    )
    console.print(
        f"  Unique endpoints: [bold]{len(allowlist)}[/bold]",
    )

    report_dir = output_dir / org
    console.print(f"  Reports written to: {report_dir}")
    console.print()
    console.print(
        "[bold green]✓ Reports generated![/bold green]",
    )
