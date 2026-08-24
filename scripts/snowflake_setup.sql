-- SnowImpact least-privilege reference setup.
-- Review with your Snowflake security team before applying to production.
-- The runtime role is metadata/read-only. It is not granted write privileges on customer data.

USE ROLE ACCOUNTADMIN;
CREATE ROLE IF NOT EXISTS SNOWIMPACT_MONITOR;

-- Current account resource visibility and Information Schema usage metrics.
GRANT MONITOR USAGE ON ACCOUNT TO ROLE SNOWIMPACT_MONITOR;

-- Scoped access to ACCOUNT_USAGE metadata in the shared SNOWFLAKE database.
-- These database roles are preferred over broad IMPORTED PRIVILEGES because each
-- covers a defined metadata domain.
GRANT DATABASE ROLE SNOWFLAKE.OBJECT_VIEWER TO ROLE SNOWIMPACT_MONITOR;
GRANT DATABASE ROLE SNOWFLAKE.USAGE_VIEWER TO ROLE SNOWIMPACT_MONITOR;
GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE SNOWIMPACT_MONITOR;
GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER TO ROLE SNOWIMPACT_MONITOR;

-- Optional warehouse dedicated to SnowImpact metadata queries.
USE ROLE SYSADMIN;
CREATE WAREHOUSE IF NOT EXISTS SNOWIMPACT_WH
  WAREHOUSE_SIZE = 'XSMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE;
GRANT USAGE ON WAREHOUSE SNOWIMPACT_WH TO ROLE SNOWIMPACT_MONITOR;

-- Create the service user according to your organization identity standard, then:
--   GRANT ROLE SNOWIMPACT_MONITOR TO USER <service_user>;
-- Prefer key-pair authentication, OAuth, or workload identity. Password auth is not
-- required by SnowImpact and should not be used for production service identities.
