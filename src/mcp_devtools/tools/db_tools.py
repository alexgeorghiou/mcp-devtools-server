"""Postgres tools: validated read-only queries, EXPLAIN plans and schema listing."""

from __future__ import annotations

import json
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_devtools.errors import ValidationError
from mcp_devtools.security.sql_guard import validate_read_only
from mcp_devtools.tools.context import ToolContext

READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)

Database = Annotated[str, Field(description="Database alias from postgres.databases")]

SCHEMA_SQL = """
SELECT c.table_schema, c.table_name, t.table_type, c.column_name, c.data_type,
       c.is_nullable = 'YES' AS nullable
FROM information_schema.columns c
JOIN information_schema.tables t
  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
WHERE c.table_schema = %(schema)s
ORDER BY c.table_name, c.ordinal_position
"""


class DatabaseTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self.pg = ctx.backends.postgres
        self.cfg = ctx.settings.postgres

    def _limit(self, requested: int | None) -> int:
        if requested is None:
            return self.cfg.max_rows
        return max(1, min(requested, self.cfg.max_rows))

    def query(self, database: str, sql: str, max_rows: int | None = None) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            dsn = self.ctx.policy.database(database)
            checked = validate_read_only(sql)
            result = self.pg.execute(
                dsn,
                checked.sql,
                statement=checked.statement,
                max_rows=self._limit(max_rows),
                timeout_ms=self.cfg.statement_timeout_ms,
            )
            return {
                "database": database,
                "columns": result.columns,
                "rows": result.rows,
                "row_count": result.row_count,
                "truncated": result.truncated,
                "duration_ms": result.duration_ms,
                "notices": result.notices,
            }

        return self.ctx.run("pg_query", {"database": database, "sql": sql}, run)

    def explain(self, database: str, sql: str, analyze: bool = False) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            dsn = self.ctx.policy.database(database)
            checked = validate_read_only(sql)
            if checked.statement not in {"SELECT", "WITH", "VALUES", "TABLE"}:
                raise ValidationError("only SELECT-style statements can be explained")
            options = "ANALYZE, BUFFERS, " if analyze else ""
            explain_sql = f"EXPLAIN ({options}FORMAT JSON) {checked.sql}"
            result = self.pg.execute(
                dsn,
                explain_sql,
                statement="EXPLAIN",
                max_rows=1,
                timeout_ms=self.cfg.statement_timeout_ms,
            )
            plan = result.rows[0][0] if result.rows else None
            return {
                "database": database,
                "analyze": analyze,
                "plan": plan,
                "summary": summarise_plan(plan),
                "duration_ms": result.duration_ms,
            }

        return self.ctx.run(
            "pg_explain", {"database": database, "sql": sql, "analyze": analyze}, run
        )

    def list_tables(self, database: str, schema: str = "public") -> dict[str, Any]:
        def run() -> dict[str, Any]:
            dsn = self.ctx.policy.database(database)
            result = self.pg.execute(
                dsn,
                SCHEMA_SQL,
                statement="SELECT",
                max_rows=5_000,
                timeout_ms=self.cfg.statement_timeout_ms,
                params={"schema": schema},
            )
            tables: dict[str, dict[str, Any]] = {}
            for _schema, table, kind, column, dtype, nullable in result.rows:
                entry = tables.setdefault(table, {"name": table, "type": kind, "columns": []})
                entry["columns"].append({"name": column, "type": dtype, "nullable": nullable})
            return {"database": database, "schema": schema, "tables": list(tables.values())}

        return self.ctx.run("pg_list_tables", {"database": database, "schema": schema}, run)


def summarise_plan(plan: Any) -> dict[str, Any] | None:
    """Pull the headline numbers and the costliest nodes out of a JSON plan."""
    if isinstance(plan, str):
        plan = json.loads(plan)
    if not isinstance(plan, list) or not plan or "Plan" not in plan[0]:
        return None
    root = plan[0]
    nodes: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], depth: int) -> None:
        nodes.append(
            {
                "depth": depth,
                "node": node.get("Node Type"),
                "relation": node.get("Relation Name"),
                "index": node.get("Index Name"),
                "total_cost": node.get("Total Cost"),
                "plan_rows": node.get("Plan Rows"),
                "actual_rows": node.get("Actual Rows"),
                "actual_ms": node.get("Actual Total Time"),
            }
        )
        for child in node.get("Plans", []) or []:
            walk(child, depth + 1)

    walk(root["Plan"], 0)
    seq_scans = [n["relation"] for n in nodes if n["node"] == "Seq Scan" and n["relation"]]
    key = "actual_ms" if any(n["actual_ms"] is not None for n in nodes) else "total_cost"
    hottest = sorted(nodes, key=lambda n: n[key] or 0, reverse=True)[:5]
    return {
        "total_cost": root["Plan"].get("Total Cost"),
        "planning_ms": root.get("Planning Time"),
        "execution_ms": root.get("Execution Time"),
        "node_count": len(nodes),
        "sequential_scans": seq_scans,
        "hottest_nodes": hottest,
    }


def register(server: MCPServer, ctx: ToolContext) -> None:
    tools = DatabaseTools(ctx)

    @server.tool(annotations=READ_ONLY)
    def pg_query(
        database: Database,
        sql: Annotated[str, Field(description="A single SELECT/WITH/VALUES/SHOW/EXPLAIN")],
        max_rows: Annotated[int | None, Field(ge=1, description="Row cap (server max)")] = None,
    ) -> dict[str, Any]:
        """Run one read-only SQL statement in a READ ONLY transaction with a timeout."""
        return tools.query(database, sql, max_rows)

    @server.tool(annotations=READ_ONLY)
    def pg_explain(
        database: Database,
        sql: Annotated[str, Field(description="The SELECT statement to explain")],
        analyze: Annotated[
            bool, Field(description="Execute it to get actual timings (read-only, time-limited)")
        ] = False,
    ) -> dict[str, Any]:
        """EXPLAIN a query as JSON and summarise costly nodes and sequential scans."""
        return tools.explain(database, sql, analyze)

    @server.tool(annotations=READ_ONLY)
    def pg_list_tables(database: Database, schema: str = "public") -> dict[str, Any]:
        """List tables and views in a schema with their columns and types."""
        return tools.list_tables(database, schema)
