"""Prompt templates that steer a client towards a sensible tool sequence."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from mcp_devtools.config import Settings


def review_recent_commits(repo: str, count: int = 10, focus: str = "") -> str:
    focus_line = f"\nPay particular attention to: {focus}." if focus else ""
    return f"""You are reviewing recent work in the repository `{repo}`.

1. Call `git_log` with repo="{repo}" and max_count={count} to list the latest commits.
2. For each commit that looks non-trivial, call `git_show` to read its diff.
3. Use `git_blame` on any hunk where the history of a line matters.

Produce a review grouped by commit with: a one-line summary, correctness risks,
missing tests, and naming/design remarks. Finish with the three most important
follow-ups. Quote file paths and short SHAs so findings are easy to locate.{focus_line}"""


def diagnose_failing_container(container: str, log_dir: str = "") -> str:
    logs_step = (
        f'\n4. Call `logs_search` on directory="{log_dir}" for the error signatures you found '
        "to correlate with application logs."
        if log_dir
        else ""
    )
    return f"""The container `{container}` is failing or unhealthy. Diagnose it.

1. Call `docker_inspect` for "{container}": note state, exit code, OOM kill flag,
   restart count, health-check output, command and mounts.
2. Call `docker_logs` for "{container}" with tail=300 and look for the first error,
   not just the last one.
3. If the container talks to HTTP dependencies, use `http_probe` on them.{logs_step}

Report: the most likely root cause with the evidence lines quoted, alternative
explanations you ruled out and why, and the concrete next command or config change
to try. Do not guess beyond the evidence."""


def explain_slow_query(database: str, sql: str) -> str:
    return f"""Explain why this query against `{database}` is slow and how to speed it up.

```sql
{sql}
```

1. Call `pg_explain` with analyze=false first to see the estimated plan.
2. If the estimate looks plausible, call it again with analyze=true (read-only and
   time-limited) to compare estimated and actual rows per node.
3. Use `pg_list_tables` to check the columns and types of the tables involved.

Explain the plan in plain language, point out sequential scans, misestimates,
expensive sorts or nested loops, and propose specific indexes or rewrites. State the
trade-offs of each suggestion (write amplification, index size)."""


def register(server: MCPServer, settings: Settings) -> None:
    if settings.git.enabled:
        server.prompt(
            name="review_recent_commits",
            description="Review the latest commits of a repository.",
        )(review_recent_commits)
    if settings.docker.enabled:
        server.prompt(
            name="diagnose_failing_container",
            description="Work out why a container is crashing or unhealthy.",
        )(diagnose_failing_container)
    if settings.postgres.enabled:
        server.prompt(
            name="explain_slow_query",
            description="Analyse a slow SQL query with EXPLAIN and suggest fixes.",
        )(explain_slow_query)
