DROP USER IF EXISTS credtest;
DROP EXTENSION credcheck CASCADE;
CREATE EXTENSION credcheck;
SELECT pg_password_history_reset();
SELECT * FROM pg_password_history WHERE rolename = 'credtest';
SET credcheck.password_reuse_history = 2;
-- When creating user the password must be stored in the history
CREATE USER credtest WITH PASSWORD 'H8Hdre=S2';
ALTER USER credtest PASSWORD 'J8YuRe=6O';
SELECT rolename, length(password_hash) AS hash_length FROM pg_password_history WHERE rolename = 'credtest' ORDER BY password_date;
-- fail, the credential is still in the history
ALTER USER credtest PASSWORD 'J8YuRe=6O';
-- eject the first credential from the history and add a new one
ALTER USER credtest PASSWORD 'AJ8YuRe=6O0';
SELECT rolename, length(password_hash) AS hash_length FROM pg_password_history WHERE rolename = 'credtest' ORDER BY password_date ;
-- fail, the credential is still in the history
ALTER USER credtest PASSWORD 'J8YuRe=6O';
-- success, eject the second credential from the history and reuse the first one
ALTER USER credtest PASSWORD 'H8Hdre=S2';
-- success, the second credential has been removed from the history
ALTER USER credtest PASSWORD 'J8YuRe=6O';
-- Dropping the user must empty the record in history table
DROP USER credtest;
SELECT * FROM pg_password_history WHERE rolename = 'credtest';
-- Reset the password history
SELECT pg_password_history_reset();

-- The history follows the role even when the reuse policy is not set in the
-- session that renames or drops it (the policy can be set per role).
SET credcheck.password_reuse_history = 2;
-- no "MD5 password cleared" notice on rename (md5 is the default before PG14)
SET password_encryption = 'scram-sha-256';
CREATE USER credtest_rn WITH PASSWORD 'H8Hdre=S2';
RESET credcheck.password_reuse_history;
ALTER USER credtest_rn RENAME TO credtest_rn2;
SELECT rolename FROM pg_password_history WHERE rolename LIKE 'credtest_rn%';
DROP USER credtest_rn2;
SELECT count(*) FROM pg_password_history WHERE rolename LIKE 'credtest_rn%';
RESET password_encryption;
