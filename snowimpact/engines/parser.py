from __future__ import annotations

import re
from pathlib import Path

import sqlglot
import yaml
from sqlglot import exp

from snowimpact.core.models import Change, ChangeOperation, ObjectRef, SourceLocation


_IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)'
_FQN = rf'{_IDENT}(?:\s*\.\s*{_IDENT}){{0,2}}'


def _clean_ident(value: str) -> str:
    return ".".join(part.strip().strip('"') for part in re.split(r"\s*\.\s*", value.strip()))


def _object_ref(raw: str, object_type: str, column: str | None = None) -> ObjectRef:
    parts = _clean_ident(raw).split(".")
    database = schema = name = None
    if len(parts) == 3:
        database, schema, name = parts
    elif len(parts) == 2:
        schema, name = parts
    elif parts:
        name = parts[-1]
    return ObjectRef(object_type=object_type.upper(), database=database, schema=schema, name=name or "UNKNOWN", column=column)


def _split_statements(sql: str) -> list[str]:
    """Split Snowflake SQL while preserving quotes and $$ specification/procedure bodies."""
    statements: list[str] = []
    buf: list[str] = []
    i = 0
    single = False
    double = False
    dollar = False
    line_comment = False
    block_comment = False
    while i < len(sql):
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""
        if line_comment:
            buf.append(ch)
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if not single and not double and not dollar and ((ch == "-" and nxt == "-") or (ch == "/" and nxt == "/")):
            buf.extend([ch, nxt]); line_comment = True; i += 2; continue
        if not single and not double and not dollar and ch == "/" and nxt == "*":
            buf.extend([ch, nxt]); block_comment = True; i += 2; continue
        if not single and not double and ch == "$" and nxt == "$":
            buf.extend([ch, nxt]); dollar = not dollar; i += 2; continue
        if not dollar and not double and ch == "'":
            # SQL escapes a single quote by doubling it.
            if single and nxt == "'":
                buf.extend([ch, nxt]); i += 2; continue
            single = not single
            buf.append(ch); i += 1; continue
        if not dollar and not single and ch == '"':
            if double and nxt == '"':
                buf.extend([ch, nxt]); i += 2; continue
            double = not double
            buf.append(ch); i += 1; continue
        if ch == ";" and not single and not double and not dollar:
            text = "".join(buf).strip()
            if text:
                statements.append(text)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def _strip_leading_comments(text: str) -> str:
    value = text.lstrip()
    while True:
        if value.startswith("--") or value.startswith("//"):
            pos = value.find("\n")
            value = "" if pos < 0 else value[pos + 1:].lstrip()
            continue
        if value.startswith("/*"):
            pos = value.find("*/", 2)
            if pos < 0:
                return ""
            value = value[pos + 2:].lstrip()
            continue
        return value


def _specification_yaml(text: str) -> dict:
    match = re.search(r"FROM\s+SPECIFICATION\s+\$\$(.*?)\$\$", text, re.I | re.S)
    if not match:
        return {}
    try:
        loaded = yaml.safe_load(match.group(1)) or {}
        return loaded if isinstance(loaded, dict) else {}
    except yaml.YAMLError:
        return {}


def _mcp_tool_summary(spec: dict) -> list[dict[str, object]]:
    tools: list[dict[str, object]] = []
    for item in spec.get("tools", []) if isinstance(spec.get("tools", []), list) else []:
        if not isinstance(item, dict):
            continue
        config = item.get("config") if isinstance(item.get("config"), dict) else {}
        tools.append({
            "name": item.get("name"),
            "type": str(item.get("type") or "").upper(),
            "identifier": item.get("identifier"),
            "read_only": config.get("read_only", True),
            "config_type": config.get("type"),
            "warehouse": config.get("warehouse"),
        })
    return tools


def _agent_tool_summary(spec: dict) -> list[dict[str, object]]:
    resources = spec.get("tool_resources") if isinstance(spec.get("tool_resources"), dict) else {}
    result: list[dict[str, object]] = []
    for item in spec.get("tools", []) if isinstance(spec.get("tools", []), list) else []:
        if not isinstance(item, dict):
            continue
        tool_spec = item.get("tool_spec") if isinstance(item.get("tool_spec"), dict) else {}
        name = str(tool_spec.get("name") or "")
        resource = resources.get(name) if isinstance(resources.get(name), dict) else {}
        result.append({
            "name": name,
            "type": str(tool_spec.get("type") or "").upper(),
            "semantic_view": resource.get("semantic_view"),
            "search_service": resource.get("search_service"),
            "identifier": resource.get("identifier"),
        })
    return result


class SnowflakeSQLParser:
    """Converts Snowflake SQL to normalized Change objects.

    SQLGlot provides statement validation and canonical parsing. A deliberately narrow
    regex layer extracts Snowflake DDL/RBAC details that are easier to express from the
    raw statement while preserving a fail-safe UNKNOWN change for unsupported syntax.
    """

    def parse_file(self, path: str | Path) -> list[Change]:
        p = Path(path)
        return self.parse(p.read_text(encoding="utf-8"), filename=str(p))

    def parse(self, sql: str, filename: str = "inline.sql") -> list[Change]:
        statements = _split_statements(sql)
        if not statements and sql.strip():
            statements = [sql.strip()]
        changes: list[Change] = []
        for index, raw in enumerate(statements):
            expression: exp.Expression | None = None
            parser_error: str | None = None
            try:
                expression = sqlglot.parse_one(raw, read="snowflake", error_level=sqlglot.ErrorLevel.RAISE)
            except Exception as exc:  # noqa: BLE001
                # Snowflake adds DDL faster than generic parsers always adopt it. The deterministic
                # extraction layer below still recognizes supported Snowflake change shapes.
                parser_error = str(exc)
            source = SourceLocation(file=filename, statement_index=index)
            extracted = self._extract(raw, expression, source)
            if parser_error:
                for change in extracted:
                    change.attributes.setdefault("sqlglot_parser_error", parser_error[:500])
            changes.extend(extracted)
        return changes

    def _extract(self, raw: str, expression: exp.Expression | None, source: SourceLocation) -> list[Change]:
        text = _strip_leading_comments(raw.strip().rstrip(";")).strip()
        upper = text.upper()

        # Role hierarchy grants.
        m = re.search(rf"^GRANT\s+ROLE\s+(?P<granted>{_IDENT})\s+TO\s+(?P<target_type>ROLE|USER)\s+(?P<target>{_IDENT})$", text, re.I)
        if m:
            return [Change(
                operation=ChangeOperation.GRANT,
                object=ObjectRef(object_type="ROLE", name=_clean_ident(m.group("granted"))),
                source=source,
                sql=text,
                attributes={"privilege": "INHERIT_ROLE", "role": _clean_ident(m.group("target")), "target_type": m.group("target_type").upper(), "scope": "ONE"},
            )]

        m = re.search(rf"^REVOKE\s+ROLE\s+(?P<granted>{_IDENT})\s+FROM\s+(?P<target_type>ROLE|USER)\s+(?P<target>{_IDENT})$", text, re.I)
        if m:
            return [Change(
                operation=ChangeOperation.REVOKE,
                object=ObjectRef(object_type="ROLE", name=_clean_ident(m.group("granted"))),
                source=source,
                sql=text,
                attributes={"privilege": "INHERIT_ROLE", "role": _clean_ident(m.group("target")), "target_type": m.group("target_type").upper(), "scope": "ONE"},
            )]

        # GRANT / REVOKE
        m = re.search(rf"^GRANT\s+(?P<priv>[A-Z_ ]+)\s+ON\s+(?P<scope>ALL|FUTURE)\s+(?P<otype>[A-Z_ ]+?)\s+IN\s+(?P<container_type>DATABASE|SCHEMA)\s+(?P<object>{_FQN})\s+TO\s+(?:ROLE\s+)?(?P<role>{_IDENT})$", text, re.I)
        if m:
            ref = _object_ref(m.group("object"), m.group("container_type"))
            return [Change(operation=ChangeOperation.GRANT, object=ref, source=source, sql=text, attributes={"privilege": m.group("priv").strip().upper(), "scope": m.group("scope").upper(), "role": _clean_ident(m.group("role")), "target_object_type": m.group("otype").strip().upper()})]

        m = re.search(rf"^GRANT\s+(?P<priv>[A-Z_ ]+)\s+ON\s+(?:(?P<scope>ALL|FUTURE)\s+)?(?P<otype>[A-Z_ ]+?)\s+(?P<object>{_FQN})\s+TO\s+(?:ROLE\s+)?(?P<role>{_IDENT})$", text, re.I)
        if m:
            ref = _object_ref(m.group("object"), m.group("otype"))
            return [Change(operation=ChangeOperation.GRANT, object=ref, source=source, sql=text, attributes={"privilege": m.group("priv").strip().upper(), "scope": (m.group("scope") or "ONE").upper(), "role": _clean_ident(m.group("role"))})]

        m = re.search(rf"^REVOKE\s+(?P<priv>[A-Z_ ]+)\s+ON\s+(?P<otype>[A-Z_ ]+?)\s+(?P<object>{_FQN})\s+FROM\s+(?:ROLE\s+)?(?P<role>{_IDENT})$", text, re.I)
        if m:
            return [Change(operation=ChangeOperation.REVOKE, object=_object_ref(m.group("object"), m.group("otype")), source=source, sql=text, attributes={"privilege": m.group("priv").strip().upper(), "role": _clean_ident(m.group("role"))})]

        # ALTER TABLE DROP/ADD/RENAME COLUMN
        m = re.search(rf"^ALTER\s+TABLE\s+(?P<table>{_FQN})\s+DROP(?:\s+COLUMN)?\s+(?P<column>{_IDENT})", text, re.I)
        if m:
            return [Change(operation=ChangeOperation.DROP, object=_object_ref(m.group("table"), "COLUMN", _clean_ident(m.group("column"))), source=source, sql=text, attributes={"parent_type": "TABLE"})]

        m = re.search(rf"^ALTER\s+TABLE\s+(?P<table>{_FQN})\s+ADD(?:\s+COLUMN)?\s+(?P<column>{_IDENT})", text, re.I)
        if m:
            return [Change(operation=ChangeOperation.CREATE, object=_object_ref(m.group("table"), "COLUMN", _clean_ident(m.group("column"))), source=source, sql=text, attributes={"parent_type": "TABLE"})]

        # ALTER WAREHOUSE SET WAREHOUSE_SIZE
        m = re.search(rf"^ALTER\s+WAREHOUSE\s+(?P<warehouse>{_FQN}).*?WAREHOUSE_SIZE\s*=\s*'?([A-Z0-9_-]+)'?", text, re.I)
        if m:
            size_match = re.search(r"WAREHOUSE_SIZE\s*=\s*'?([A-Z0-9_-]+)'?", text, re.I)
            return [Change(operation=ChangeOperation.ALTER, object=_object_ref(m.group("warehouse"), "WAREHOUSE"), source=source, sql=text, attributes={"warehouse_size": size_match.group(1).upper() if size_match else None})]

        # Generic CREATE / DROP / ALTER objects.
        generic = re.search(rf"^(CREATE(?:\s+OR\s+REPLACE)?|DROP|ALTER)\s+(?P<otype>DATABASE|SCHEMA|TABLE|VIEW|MATERIALIZED\s+VIEW|DYNAMIC\s+TABLE|STREAM|TASK|WAREHOUSE|ROLE|USER|STAGE|PIPE|PROCEDURE|FUNCTION|MASKING\s+POLICY|ROW\s+ACCESS\s+POLICY|SEMANTIC\s+VIEW|MCP\s+SERVER|AGENT|TAG)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?P<object>{_FQN})", text, re.I)
        if generic:
            verb = generic.group(1).upper()
            op = ChangeOperation.CREATE if verb.startswith("CREATE") else ChangeOperation.DROP if verb == "DROP" else ChangeOperation.ALTER
            attrs: dict[str, object] = {}
            object_type = generic.group("otype").upper().replace("  ", " ")
            if op == ChangeOperation.CREATE and object_type == "MCP SERVER":
                attrs["mcp_tools"] = _mcp_tool_summary(_specification_yaml(text))
            if op == ChangeOperation.CREATE and object_type == "AGENT":
                attrs["agent_tools"] = _agent_tool_summary(_specification_yaml(text))
            if op == ChangeOperation.CREATE and "VIEW" in generic.group("otype").upper():
                refs = []
                if expression is not None:
                    for table in expression.find_all(exp.Table):
                        name = table.sql(dialect="snowflake")
                        if _clean_ident(name).upper() != _clean_ident(generic.group("object")).upper():
                            refs.append(_clean_ident(name))
                else:
                    for match in re.finditer(rf"\b(?:FROM|JOIN)\s+(?P<table>{_FQN})", text, re.I):
                        refs.append(_clean_ident(match.group("table")))
                if refs:
                    attrs["references"] = sorted(set(refs))
                projected: list[str] = []
                if expression is not None:
                    select_expr = expression.find(exp.Select)
                    if select_expr is not None:
                        for projection in select_expr.expressions:
                            if isinstance(projection, exp.Star) or projection.find(exp.Star) is not None:
                                projected.append("*")
                                continue
                            columns = [column.name for column in projection.find_all(exp.Column) if column.name]
                            projected.extend(columns)
                else:
                    select_match = re.search(r"\bSELECT\s+(.*?)\s+FROM\b", text, re.I | re.S)
                    if select_match:
                        clause = select_match.group(1).strip()
                        if "*" in clause:
                            projected.append("*")
                        else:
                            for item in clause.split(","):
                                token = re.split(r"\s+AS\s+|\s+", item.strip(), flags=re.I)[0]
                                if re.fullmatch(rf"{_FQN}", token):
                                    projected.append(_clean_ident(token).split(".")[-1])
                if projected:
                    attrs["projected_columns"] = sorted(set(col.upper() for col in projected))
            return [Change(operation=op, object=_object_ref(generic.group("object"), generic.group("otype")), source=source, sql=text, attributes=attrs)]

        # DML is tracked for performance / safety, without attempting execution.
        dml_map = {
            "INSERT": ChangeOperation.INSERT,
            "UPDATE": ChangeOperation.UPDATE,
            "DELETE": ChangeOperation.DELETE,
            "MERGE": ChangeOperation.MERGE,
            "TRUNCATE": ChangeOperation.TRUNCATE,
            "COPY": ChangeOperation.COPY,
            "CALL": ChangeOperation.CALL,
        }
        for prefix, op in dml_map.items():
            if upper.startswith(prefix):
                tables = [t.sql(dialect="snowflake") for t in expression.find_all(exp.Table)] if expression is not None else []
                if not tables:
                    for match in re.finditer(rf"\b(?:FROM|INTO|UPDATE|MERGE\s+INTO|TABLE)\s+(?P<table>{_FQN})", text, re.I):
                        tables.append(match.group("table"))
                target = tables[0] if tables else "UNKNOWN"
                return [Change(operation=op, object=_object_ref(target, "TABLE"), source=source, sql=text, attributes={"tables": [_clean_ident(t) for t in tables]})]

        return [Change(operation=ChangeOperation.UNKNOWN, object=ObjectRef(object_type="UNKNOWN", name="UNKNOWN"), source=source, sql=text, attributes={"expression": expression.key if expression is not None else "unparsed"})]
