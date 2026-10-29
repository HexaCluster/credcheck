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

-- A whitelisted role is never rejected by the hook, so it is not reported as
-- banned to the pooler either, even with a failure entry recorded.
SET credcheck.whitelist_auth_failure = 'ban_test';
SELECT credcheck_is_banned('ban_test');             -- false (whitelisted)
RESET credcheck.whitelist_auth_failure;
SELECT credcheck_is_banned('ban_test');             -- true again

-- Unknown roles are ignored (mirrors the hook).
SELECT credcheck_record_auth_failure('does_not_exist');
SELECT credcheck_is_banned('does_not_exist');

-- The existing reset function unbans the role.
SELECT pg_banned_role_reset('ban_test');
SELECT credcheck_is_banned('ban_test');

-- Access to record_auth_failure is controlled by EXECUTE privilege: not
-- granted to PUBLIC, usable by a non-superuser reporter once granted.
CREATE ROLE ban_reporter;
SET ROLE ban_reporter;
SELECT credcheck_record_auth_failure('ban_test');   -- permission denied
RESET ROLE;
GRANT EXECUTE ON FUNCTION credcheck_record_auth_failure(name) TO ban_reporter;
SET ROLE ban_reporter;
SELECT credcheck_record_auth_failure('ban_test');   -- 1
RESET ROLE;
SELECT pg_banned_role_reset('ban_test');
REVOKE EXECUTE ON FUNCTION credcheck_record_auth_failure(name) FROM ban_reporter;
DROP ROLE ban_reporter;

-- Disabling the feature makes both functions inert.
SET credcheck.max_auth_failure = 0;
SELECT credcheck_record_auth_failure('ban_test');
SELECT credcheck_is_banned('ban_test');

DROP ROLE ban_test;
