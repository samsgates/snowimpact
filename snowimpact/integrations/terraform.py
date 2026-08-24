from __future__ import annotations

import json
from pathlib import Path

from snowimpact.core.models import Change, ChangeOperation, ObjectRef, SourceLocation


_RESOURCE_OBJECT_TYPES = {
    "snowflake_warehouse": "WAREHOUSE",
    "snowflake_database": "DATABASE",
    "snowflake_schema": "SCHEMA",
    "snowflake_table": "TABLE",
    "snowflake_view": "VIEW",
    "snowflake_account_role": "ROLE",
    "snowflake_role": "ROLE",
    "snowflake_grant_privileges_to_account_role": "GRANT",
}


def parse_terraform_plan(path: str | Path) -> list[Change]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    changes: list[Change] = []
    for index, rc in enumerate(raw.get("resource_changes", [])):
        rtype = rc.get("type", "")
        object_type = _RESOURCE_OBJECT_TYPES.get(rtype)
        if not object_type:
            continue
        actions = rc.get("change", {}).get("actions", [])
        before = rc.get("change", {}).get("before") or {}
        after = rc.get("change", {}).get("after") or {}
        if actions == ["create"]:
            op = ChangeOperation.CREATE
        elif actions == ["delete"]:
            op = ChangeOperation.DROP
        else:
            op = ChangeOperation.ALTER
        name = after.get("name") or before.get("name") or rc.get("name") or "UNKNOWN"
        attrs = {"terraform_address": rc.get("address"), "resource_type": rtype, "before": before, "after": after}
        if object_type == "WAREHOUSE" and after.get("warehouse_size"):
            attrs["warehouse_size"] = str(after["warehouse_size"]).upper()
        if object_type == "GRANT":
            op = ChangeOperation.GRANT
            object_type = str(after.get("on_schema_object", {}).get("object_type") or "OBJECT").upper()
            name = str(after.get("on_schema_object", {}).get("object_name") or after.get("on_account_object", {}).get("object_name") or "UNKNOWN")
            attrs["role"] = after.get("account_role_name")
            attrs["privilege"] = ",".join(after.get("privileges", []))
        changes.append(Change(operation=op, object=ObjectRef(object_type=object_type, name=name), source=SourceLocation(file=str(path), statement_index=index), attributes=attrs))
    return changes
