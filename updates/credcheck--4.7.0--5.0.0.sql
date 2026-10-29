-- credcheck extension for PostgreSQL
-- Copyright (c) 2024-2026 HexaCluster Corp - All rights reserved.

-- Nothing to do, only library change

REVOKE ALL ON FUNCTION pg_banned_role() FROM PUBLIC;
REVOKE ALL ON pg_banned_role FROM PUBLIC;
GRANT SELECT ON pg_banned_role TO pg_read_all_stats;

