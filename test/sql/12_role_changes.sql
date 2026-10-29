LOAD 'credcheck';

SET credcheck.password_min_length = 8;

--
-- Issue #89: credcheck.disallow_change_password must only block a password
-- change, not every ALTER ROLE.
--
CREATE USER issue89 PASSWORD 'Iss89PassWORD!';
SET credcheck.disallow_change_password TO on;
ALTER USER issue89 PASSWORD 'Iss89NewWORD!';          -- error
ALTER USER issue89 PASSWORD NULL;                     -- error, also a change
ALTER USER issue89 CONNECTION LIMIT 5;                -- allowed
ALTER USER issue89 BYPASSRLS;                         -- allowed
SELECT rolconnlimit, rolbypassrls FROM pg_roles WHERE rolname = 'issue89';
RESET credcheck.disallow_change_password;
DROP USER issue89;

--
-- Issue #93: the password history must not be dropped by a DROP ROLE that
-- fails, and must not be written by a CREATE/ALTER ROLE that fails.
--
SELECT pg_password_history_reset();
CREATE USER issue93 PASSWORD 'Iss93PassWORD!';
ALTER USER issue93 SET credcheck.password_reuse_history = 2;
SET credcheck.password_reuse_history = 2;
ALTER USER issue93 PASSWORD 'Iss93PassWORD!';         -- error, reuse
CREATE USER issue93_victim PASSWORD 'Iss93Victim1!';
\c - issue93
ALTER USER issue93 PASSWORD 'Iss93PassWORD!';         -- error, reuse
DROP USER issue93;                                    -- error, permission
ALTER USER issue93 PASSWORD 'Iss93PassWORD!';         -- still an error
-- failing statements on another role must not touch its history
CREATE USER issue93_victim PASSWORD 'Iss93Poison1!';  -- error, permission
ALTER USER issue93_victim PASSWORD 'Iss93Poison2!';   -- error, permission
\c - postgres
SELECT rolename, count(*) FROM pg_password_history
  WHERE rolename LIKE 'issue93%' GROUP BY rolename ORDER BY rolename;
-- a failing DROP ROLE in a superuser session keeps the history too
DROP USER issue93, does_not_exist;                    -- error, unknown role
SELECT count(*) FROM pg_password_history WHERE rolename = 'issue93';
-- a successful DROP ROLE removes it
DROP USER issue93;
DROP USER issue93_victim;
SELECT count(*) FROM pg_password_history WHERE rolename LIKE 'issue93%';
SELECT pg_password_history_reset();
