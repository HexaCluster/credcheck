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

