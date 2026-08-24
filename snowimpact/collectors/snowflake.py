from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import snowflake.connector
from cryptography.hazmat.primitives import serialization
from snowflake.connector import DictCursor

from snowimpact.collectors.base import MetadataCollector
from snowimpact.core.models import Capability, EnvironmentSnapshot, GraphEdge, GraphNode
from snowimpact.core.settings import Settings

log = logging.getLogger(__name__)


class SnowflakeCollector(MetadataCollector):
    """Read-only Snowflake metadata collector.

    No PR-supplied SQL is ever executed by this collector. Queries below are fixed,
    metadata-only statements. Object identifiers discovered from Snowflake are treated
    as data, not interpolated into arbitrary SQL.
    """

    CAPABILITY_PROBES: dict[str, str] = {
        "OBJECT_DEPENDENCIES": "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES LIMIT 1",
        "QUERY_HISTORY": "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY LIMIT 1",
        "QUERY_ATTRIBUTION_HISTORY": "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_ATTRIBUTION_HISTORY LIMIT 1",
        "ACCESS_HISTORY": "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY LIMIT 1",
        "TAG_REFERENCES": "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES LIMIT 1",
        "POLICY_REFERENCES": "SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES LIMIT 1",
        "CORTEX_AGENTS": "SHOW AGENTS IN ACCOUNT",
        "MCP_SERVERS": "SHOW MCP SERVERS IN ACCOUNT",
        "AGENT_IDENTITY": "SELECT AGENT_TYPE FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY LIMIT 1",
    }

    def __init__(self, settings: Settings):
        self.settings = settings

    def _private_key(self) -> bytes | None:
        path = self.settings.snowflake_private_key_path
        if not path:
            return None
        raw = Path(path).read_bytes()
        password = None
        if self.settings.snowflake_private_key_passphrase:
            password = self.settings.snowflake_private_key_passphrase.get_secret_value().encode()
        key = serialization.load_pem_private_key(raw, password=password)
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def _connect(self):
        kwargs: dict[str, Any] = {
            "account": self.settings.snowflake_account,
            "user": self.settings.snowflake_user,
            "role": self.settings.snowflake_role,
            "warehouse": self.settings.snowflake_warehouse,
            "application": "SnowImpact",
            "session_parameters": {"QUERY_TAG": "snowimpact:metadata"},
        }
        if self.settings.snowflake_database:
            kwargs["database"] = self.settings.snowflake_database
        key = self._private_key()
        if key:
            kwargs["private_key"] = key
        return snowflake.connector.connect(**kwargs)

    @staticmethod
    def _rows(cursor, sql: str, params: tuple[Any, ...] | None = None) -> list[dict[str, Any]]:
        cursor.execute(sql, params or ())
        return list(cursor.fetchall())

    def doctor(self) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        with self._connect() as conn:
            cur = conn.cursor(DictCursor)
            try:
                cur.execute("SELECT CURRENT_ACCOUNT() AS ACCOUNT, CURRENT_ROLE() AS ROLE, CURRENT_WAREHOUSE() AS WAREHOUSE")
                row = cur.fetchone()
                results.append({"name": "CONNECTION", "available": True, "reason": str(row)})
            except Exception as exc:  # noqa: BLE001
                return [{"name": "CONNECTION", "available": False, "reason": str(exc)}]
            for name, sql in self.CAPABILITY_PROBES.items():
                try:
                    cur.execute(sql)
                    cur.fetchone()
                    results.append({"name": name, "available": True, "reason": None})
                except Exception as exc:  # noqa: BLE001
                    results.append({"name": name, "available": False, "reason": str(exc)[:240]})
        return results

    def collect(self, environment: str = "production") -> EnvironmentSnapshot:
        if not self.settings.snowflake_account or not self.settings.snowflake_user:
            raise RuntimeError("SNOWFLAKE_ACCOUNT and SNOWFLAKE_USER are required")

        nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        privileges: list[dict[str, Any]] = []
        query_metrics: list[dict[str, Any]] = []
        warehouse_metrics: list[dict[str, Any]] = []
        classifications: list[dict[str, Any]] = []

        with self._connect() as conn:
            cur = conn.cursor(DictCursor)

            # Current state via SHOW minimizes Account Usage latency for privileges/resources.
            for stmt, node_type, key_prefix in [
                ("SHOW DATABASES", "DATABASE", "database"),
                ("SHOW WAREHOUSES", "WAREHOUSE", "warehouse"),
                ("SHOW ROLES", "ROLE", "role"),
                ("SHOW USERS", "USER", "user"),
            ]:
                try:
                    cur.execute(stmt)
                    for row in cur.fetchall():
                        name = str(row.get("name") or row.get("NAME") or "")
                        if not name:
                            continue
                        node_id = f"{key_prefix}:{name}"
                        nodes[node_id] = GraphNode(id=node_id, node_type=node_type, fqn=name, attributes={k.lower(): v for k, v in row.items() if v is not None})
                except Exception as exc:  # noqa: BLE001
                    log.warning("metadata statement failed: %s: %s", stmt, exc)

            try:
                cur.execute("SHOW GRANTS TO ROLE IDENTIFIER(?)", (self.settings.snowflake_role,))
                cur.fetchall()
            except Exception:
                # Probe only. Full grants are fetched from ACCOUNT_USAGE below when available.
                pass

            # Current Snowflake AI objects. SHOW commands return only objects visible to the role.
            for stmt, node_type, prefix in [
                ("SHOW AGENTS IN ACCOUNT", "AGENT", "agent"),
                ("SHOW MCP SERVERS IN ACCOUNT", "MCP_SERVER", "mcp"),
            ]:
                try:
                    cur.execute(stmt)
                    for row in cur.fetchall():
                        name = str(row.get("name") or row.get("NAME") or "")
                        database = str(row.get("database_name") or row.get("DATABASE_NAME") or "")
                        schema = str(row.get("schema_name") or row.get("SCHEMA_NAME") or "")
                        if not name:
                            continue
                        fqn = ".".join(filter(None, [database, schema, name]))
                        node_id = f"{prefix}:{fqn}"
                        nodes[node_id] = GraphNode(id=node_id, node_type=node_type, fqn=fqn, attributes={k.lower(): v for k, v in row.items() if v is not None})
                except Exception as exc:  # noqa: BLE001
                    log.info("%s unavailable: %s", stmt, exc)

            # Full account role/user inventory from ACCOUNT_USAGE where permitted.
            # SHOW commands above are useful for current state but can be visibility-scoped.
            try:
                for row in self._rows(cur, "SELECT NAME, OWNER, DELETED_ON FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE DELETED_ON IS NULL"):
                    name = str(row.get("NAME") or "")
                    if name:
                        node_id = f"role:{name}"
                        nodes.setdefault(node_id, GraphNode(id=node_id, node_type="ROLE", fqn=name, attributes={"owner": row.get("OWNER")}))
            except Exception as exc:  # noqa: BLE001
                log.info("ACCOUNT_USAGE.ROLES unavailable: %s", exc)
            try:
                for row in self._rows(cur, "SELECT NAME, DISABLED, DELETED_ON FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DELETED_ON IS NULL"):
                    name = str(row.get("NAME") or "")
                    if name:
                        node_id = f"user:{name}"
                        nodes.setdefault(node_id, GraphNode(id=node_id, node_type="USER", fqn=name, attributes={"disabled": row.get("DISABLED")}))
            except Exception as exc:  # noqa: BLE001
                log.info("ACCOUNT_USAGE.USERS unavailable: %s", exc)

            # Historical metadata queries. Lookback is bounded.
            object_sql = """
                SELECT REFERENCING_DATABASE, REFERENCING_SCHEMA, REFERENCING_OBJECT_NAME,
                       REFERENCING_OBJECT_DOMAIN, REFERENCED_DATABASE, REFERENCED_SCHEMA,
                       REFERENCED_OBJECT_NAME, REFERENCED_OBJECT_DOMAIN
                FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES
                WHERE DELETED IS NULL
            """
            try:
                for row in self._rows(cur, object_sql):
                    src_fqn = ".".join(filter(None, [row.get("REFERENCING_DATABASE"), row.get("REFERENCING_SCHEMA"), row.get("REFERENCING_OBJECT_NAME")]))
                    dst_fqn = ".".join(filter(None, [row.get("REFERENCED_DATABASE"), row.get("REFERENCED_SCHEMA"), row.get("REFERENCED_OBJECT_NAME")]))
                    if not src_fqn or not dst_fqn:
                        continue
                    src_id = f"object:{src_fqn}"
                    dst_id = f"object:{dst_fqn}"
                    nodes.setdefault(src_id, GraphNode(id=src_id, node_type=str(row.get("REFERENCING_OBJECT_DOMAIN") or "OBJECT"), fqn=src_fqn))
                    nodes.setdefault(dst_id, GraphNode(id=dst_id, node_type=str(row.get("REFERENCED_OBJECT_DOMAIN") or "OBJECT"), fqn=dst_fqn))
                    # Edge direction means source object is depended on by target consumer.
                    edges.append(GraphEdge(source=dst_id, target=src_id, edge_type="DEPENDS_ON", source_type="OBJECT_DEPENDENCIES", confidence=0.99))
            except Exception as exc:  # noqa: BLE001
                log.warning("OBJECT_DEPENDENCIES unavailable: %s", exc)

            # Column-level runtime consumers from Access History (Enterprise Edition).
            access_sql = """
                SELECT AH.QUERY_ID, AH.USER_NAME,
                       BASE.VALUE:objectName::STRING AS OBJECT_NAME,
                       COL.VALUE:columnName::STRING AS COLUMN_NAME
                FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY AH,
                     LATERAL FLATTEN(INPUT => AH.BASE_OBJECTS_ACCESSED) BASE,
                     LATERAL FLATTEN(INPUT => BASE.VALUE:columns, OUTER => TRUE) COL
                WHERE AH.QUERY_START_TIME >= DATEADD('day', -%s, CURRENT_TIMESTAMP())
                  AND BASE.VALUE:objectName IS NOT NULL
                LIMIT %s
            """
            try:
                access_days = min(self.settings.history_days, 30)
                for row in self._rows(cur, access_sql, (access_days, self.settings.max_access_history_rows)):
                    object_name = str(row.get("OBJECT_NAME") or "")
                    column_name = str(row.get("COLUMN_NAME") or "")
                    query_id = str(row.get("QUERY_ID") or "")
                    user_name = str(row.get("USER_NAME") or "")
                    if not object_name or not query_id:
                        continue
                    accessed_fqn = f"{object_name}.{column_name}" if column_name else object_name
                    accessed_id = f"column:{accessed_fqn}" if column_name else f"object:{accessed_fqn}"
                    nodes.setdefault(accessed_id, GraphNode(id=accessed_id, node_type="COLUMN" if column_name else "OBJECT", fqn=accessed_fqn))
                    query_node = f"query:{query_id}"
                    nodes.setdefault(query_node, GraphNode(id=query_node, node_type="QUERY", fqn=query_id, attributes={"user": user_name, "historical": True}))
                    edges.append(GraphEdge(source=accessed_id, target=query_node, edge_type="CONSUMED_BY", source_type="ACCESS_HISTORY", confidence=0.95))
            except Exception as exc:  # noqa: BLE001
                log.info("ACCESS_HISTORY unavailable: %s", exc)

            grants_sql = """
                SELECT GRANTEE_NAME, PRIVILEGE, GRANTED_ON, NAME, GRANTED_TO, GRANTED_BY, DELETED_ON
                FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                WHERE DELETED_ON IS NULL
            """
            try:
                privileges = self._rows(cur, grants_sql)
                for grant in privileges:
                    granted_on = str(grant.get("GRANTED_ON") or "").upper()
                    grantee = str(grant.get("GRANTEE_NAME") or "")
                    name = str(grant.get("NAME") or "")
                    if grantee:
                        grantee_id = f"role:{grantee}"
                        nodes.setdefault(grantee_id, GraphNode(id=grantee_id, node_type="ROLE", fqn=grantee))
                    if granted_on == "ROLE" and grantee and name:
                        inherited_id = f"role:{name}"
                        nodes.setdefault(inherited_id, GraphNode(id=inherited_id, node_type="ROLE", fqn=name))
                        edges.append(GraphEdge(source=f"role:{grantee}", target=inherited_id, edge_type="GRANTED_TO", source_type="GRANTS_TO_ROLES", confidence=0.98))
            except Exception as exc:  # noqa: BLE001
                log.warning("GRANTS_TO_ROLES unavailable: %s", exc)

            grants_to_users_sql = """
                SELECT ROLE, GRANTEE_NAME, GRANTED_BY
                FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
                WHERE DELETED_ON IS NULL
            """
            try:
                for row in self._rows(cur, grants_to_users_sql):
                    role = str(row.get("ROLE") or "")
                    user = str(row.get("GRANTEE_NAME") or "")
                    if not role or not user:
                        continue
                    role_id = f"role:{role}"
                    user_id = f"user:{user}"
                    nodes.setdefault(role_id, GraphNode(id=role_id, node_type="ROLE", fqn=role))
                    nodes.setdefault(user_id, GraphNode(id=user_id, node_type="USER", fqn=user))
                    edges.append(GraphEdge(source=user_id, target=role_id, edge_type="GRANTED_TO", source_type="GRANTS_TO_USERS", confidence=0.98))
            except Exception as exc:  # noqa: BLE001
                log.warning("GRANTS_TO_USERS unavailable: %s", exc)

            query_sql = """
                SELECT QUERY_PARAMETERIZED_HASH, WAREHOUSE_NAME,
                       COUNT(*) AS EXECUTIONS,
                       AVG(TOTAL_ELAPSED_TIME) AS AVG_DURATION_MS,
                       AVG(BYTES_SCANNED) AS AVG_BYTES_SCANNED,
                       MAX(END_TIME) AS LAST_SEEN
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE START_TIME >= DATEADD('day', -%s, CURRENT_TIMESTAMP())
                  AND QUERY_TYPE NOT IN ('SHOW', 'DESCRIBE')
                GROUP BY 1,2
                LIMIT 100000
            """
            try:
                query_metrics = self._rows(cur, query_sql, (self.settings.history_days,))
            except Exception as exc:  # noqa: BLE001
                log.warning("QUERY_HISTORY unavailable: %s", exc)

            warehouse_sql = """
                SELECT WAREHOUSE_NAME,
                       SUM(CREDITS_USED_COMPUTE) AS COMPUTE_CREDITS,
                       SUM(CREDITS_USED_CLOUD_SERVICES) AS CLOUD_SERVICE_CREDITS
                FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
                WHERE START_TIME >= DATEADD('day', -%s, CURRENT_TIMESTAMP())
                GROUP BY 1
            """
            try:
                warehouse_metrics = self._rows(cur, warehouse_sql, (self.settings.history_days,))
            except Exception as exc:  # noqa: BLE001
                log.warning("WAREHOUSE_METERING_HISTORY unavailable: %s", exc)

            tag_sql = """
                SELECT OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_DATABASE,
                       TAG_SCHEMA, TAG_NAME, TAG_VALUE
                FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                WHERE DOMAIN IN ('TABLE','COLUMN','VIEW')
            """
            try:
                for row in self._rows(cur, tag_sql):
                    obj = ".".join(filter(None, [row.get("OBJECT_DATABASE"), row.get("OBJECT_SCHEMA"), row.get("OBJECT_NAME"), row.get("COLUMN_NAME")]))
                    classifications.append({
                        "object": obj,
                        "tag": ".".join(filter(None, [row.get("TAG_DATABASE"), row.get("TAG_SCHEMA"), row.get("TAG_NAME")])),
                        "classification": row.get("TAG_VALUE"),
                        "masked": None,
                    })
            except Exception as exc:  # noqa: BLE001
                log.warning("TAG_REFERENCES unavailable: %s", exc)

            policy_sql = """
                SELECT POLICY_KIND, POLICY_NAME, REF_DATABASE_NAME, REF_SCHEMA_NAME,
                       REF_ENTITY_NAME, REF_ENTITY_DOMAIN, REF_COLUMN_NAME, POLICY_STATUS
                FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
                WHERE POLICY_STATUS IS NULL OR POLICY_STATUS = 'ACTIVE'
            """
            try:
                masked_objects: set[str] = set()
                for row in self._rows(cur, policy_sql):
                    obj = ".".join(filter(None, [row.get("REF_DATABASE_NAME"), row.get("REF_SCHEMA_NAME"), row.get("REF_ENTITY_NAME"), row.get("REF_COLUMN_NAME")]))
                    if str(row.get("POLICY_KIND") or "").upper() == "MASKING_POLICY" and obj:
                        masked_objects.add(obj.upper())
                for classification in classifications:
                    if str(classification.get("object") or "").upper() in masked_objects:
                        classification["masked"] = True
            except Exception as exc:  # noqa: BLE001
                log.warning("POLICY_REFERENCES unavailable: %s", exc)

        doctor = self.doctor()
        capabilities = [Capability(name=str(i["name"]), available=bool(i["available"]), reason=str(i.get("reason") or "") or None) for i in doctor if i["name"] != "CONNECTION"]
        return EnvironmentSnapshot(
            account=self.settings.snowflake_account or "unknown",
            environment=environment,
            nodes=list(nodes.values()),
            edges=edges,
            privileges=privileges,
            query_metrics=query_metrics,
            warehouse_metrics=warehouse_metrics,
            classifications=classifications,
            capabilities=capabilities,
        )
