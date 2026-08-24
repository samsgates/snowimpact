from snowimpact.engines.parser import SnowflakeSQLParser


def test_drop_column():
    changes = SnowflakeSQLParser().parse("ALTER TABLE PROD.CUSTOMER.CUSTOMERS DROP COLUMN REGION")
    assert len(changes) == 1
    assert changes[0].operation.value == "drop"
    assert changes[0].object.object_type == "COLUMN"
    assert changes[0].object.fqn == "PROD.CUSTOMER.CUSTOMERS.REGION"


def test_grant_all_tables_in_schema():
    changes = SnowflakeSQLParser().parse("GRANT SELECT ON ALL TABLES IN SCHEMA PROD.CUSTOMER TO ROLE MARKETING")
    change = changes[0]
    assert change.operation.value == "grant"
    assert change.attributes["scope"] == "ALL"
    assert change.attributes["role"] == "MARKETING"
    assert change.object.fqn == "PROD.CUSTOMER"


def test_warehouse_resize():
    change = SnowflakeSQLParser().parse("ALTER WAREHOUSE ANALYTICS_WH SET WAREHOUSE_SIZE='2XLARGE'")[0]
    assert change.object.object_type == "WAREHOUSE"
    assert change.attributes["warehouse_size"] == "2XLARGE"


def test_create_view_references():
    change = SnowflakeSQLParser().parse("CREATE VIEW PROD.REPORTING.V AS SELECT * FROM PROD.CUSTOMER.CUSTOMERS")[0]
    assert change.operation.value == "create"
    assert "PROD.CUSTOMER.CUSTOMERS" in change.attributes["references"]


def test_role_grant():
    change = SnowflakeSQLParser().parse("GRANT ROLE FINANCE_ADMIN TO ROLE ANALYST")[0]
    assert change.operation.value == "grant"
    assert change.object.object_type == "ROLE"
    assert change.object.name == "FINANCE_ADMIN"
    assert change.attributes["role"] == "ANALYST"
    assert change.attributes["privilege"] == "INHERIT_ROLE"


def test_mcp_server_extracts_sql_tool():
    sql = '''CREATE MCP SERVER PROD.AI.MCP1 FROM SPECIFICATION $$
tools:
  - name: sql_exec
    type: SYSTEM_EXECUTE_SQL
    title: SQL
    description: execute
    config:
      read_only: false
$$'''
    change = SnowflakeSQLParser().parse(sql)[0]
    assert change.object.object_type == "MCP SERVER"
    assert change.attributes["mcp_tools"][0]["type"] == "SYSTEM_EXECUTE_SQL"
    assert change.attributes["mcp_tools"][0]["read_only"] is False


def test_leading_comments_do_not_hide_change():
    sql = "-- migration 42\n/* reviewed */\nALTER TABLE PROD.CUSTOMER.CUSTOMERS DROP COLUMN REGION"
    change = SnowflakeSQLParser().parse(sql)[0]
    assert change.operation.value == "drop"
