LOAD 'credcheck';

-- Integration points that let a connection pooler (e.g. PgBouncer with
-- auth_query) feed authentication failures into credcheck's ban state, since
-- pooler-terminated failures never reach the backend ClientAuthentication hook.
SET credcheck.max_auth_failure = 3;
CREATE ROLE ban_test LOGIN PASSWORD 'DummY1passWORD!';
SELECT pg_banned_role_reset('ban_test');

-- Not banned initially.
SELECT credcheck_is_banned('ban_test');

-- Report failures through the integration point; credcheck applies its own
-- credcheck.max_auth_failure threshold, exactly as for direct connections.
SELECT credcheck_record_auth_failure('ban_test');   -- 1
SELECT credcheck_record_auth_failure('ban_test');   -- 2
SELECT credcheck_is_banned('ban_test');             -- still false (2 < 3)
SELECT credcheck_record_auth_failure('ban_test');   -- 3 -> banned
SELECT credcheck_is_banned('ban_test');             -- true

-- Does not keep incrementing once banned.
SELECT credcheck_record_auth_failure('ban_test');   -- still 3

-- Visible in the same shared ban view used by the in-backend path.
SELECT failure_count, banned_date IS NOT NULL AS banned
  FROM pg_banned_role WHERE roleid='ban_test'::regrole;

-- Unknown roles are ignored (mirrors the hook).
SELECT credcheck_record_auth_failure('does_not_exist');
SELECT credcheck_is_banned('does_not_exist');

-- The existing reset function unbans the role.
SELECT pg_banned_role_reset('ban_test');
SELECT credcheck_is_banned('ban_test');

-- Disabling the feature makes both functions inert.
SET credcheck.max_auth_failure = 0;
SELECT credcheck_record_auth_failure('ban_test');
SELECT credcheck_is_banned('ban_test');

DROP ROLE ban_test;
