--
-- The password history follows the transaction: changes made by
-- CREATE/ALTER/RENAME/DROP ROLE are only applied when the transaction
-- commits, rolled back changes leave no trace.
--
LOAD 'credcheck';
SET password_encryption = 'scram-sha-256';
SET credcheck.password_min_length = 8;
SET credcheck.password_reuse_history = 2;
SELECT pg_password_history_reset();

CREATE VIEW hx AS
  SELECT rolename, count(*) AS entries FROM pg_password_history
  WHERE rolename LIKE 'hx\_%' GROUP BY rolename ORDER BY rolename;

-- rolled back CREATE ROLE
BEGIN;
CREATE USER hx_a PASSWORD 'HxPassA_1';
ROLLBACK;
SELECT * FROM hx;

-- the history only shows committed changes
BEGIN;
CREATE USER hx_a PASSWORD 'HxPassA_1';
SELECT * FROM hx;
COMMIT;
SELECT * FROM hx;
ALTER USER hx_a PASSWORD 'HxPassB_1';                -- history: A, B
SELECT * FROM hx;

-- rolled back ALTER ROLE: no new entry and no trimming of the old ones
BEGIN;
ALTER USER hx_a PASSWORD 'HxPassC_1';
ROLLBACK;
SELECT * FROM hx;
ALTER USER hx_a PASSWORD 'HxPassA_1';                -- error, A is kept
-- a failed statement does not trim the history either
ALTER USER hx_a PASSWORD 'HxPassC_1' VALID UNTIL 'not a date';
ALTER USER hx_a PASSWORD 'HxPassA_1';                -- error, A is kept

-- rolled back DROP ROLE and RENAME
BEGIN;
DROP USER hx_a;
ROLLBACK;
BEGIN;
ALTER USER hx_a RENAME TO hx_renamed;
ROLLBACK;
SELECT * FROM hx;

-- savepoints: only the changes of the rolled back subtransaction are lost
BEGIN;
ALTER USER hx_a PASSWORD 'HxPassC_1';                -- history: B, C
SAVEPOINT s1;
ALTER USER hx_a PASSWORD 'HxPassD_1';
ROLLBACK TO SAVEPOINT s1;
SAVEPOINT s2;
ALTER USER hx_a CONNECTION LIMIT 2;
RELEASE SAVEPOINT s2;
COMMIT;
SELECT * FROM hx;
ALTER USER hx_a PASSWORD 'HxPassC_1';                -- error, C was committed
ALTER USER hx_a PASSWORD 'HxPassB_1';                -- error, B is kept
ALTER USER hx_a PASSWORD 'HxPassD_1';                -- D was rolled back: ok

-- exception block of PL/pgSQL
DO $$
BEGIN
  ALTER USER hx_a PASSWORD 'HxPassE_1';
  RAISE EXCEPTION 'cancel';
EXCEPTION WHEN raise_exception THEN
  RAISE NOTICE 'password change cancelled';
END
$$;
ALTER USER hx_a PASSWORD 'HxPassE_1';                -- E was not saved: ok
SELECT * FROM hx;

-- a transaction sees its own pending changes
BEGIN;
ALTER USER hx_a PASSWORD 'HxPassF_1';
ALTER USER hx_a PASSWORD 'HxPassF_1';                -- error, F is pending
ROLLBACK;
BEGIN;
DROP USER hx_a;
CREATE USER hx_a PASSWORD 'HxPassE_1';               -- ok, history was dropped
COMMIT;
SELECT * FROM hx;

-- PREPARE TRANSACTION is not supported with pending history changes
BEGIN;
ALTER USER hx_a PASSWORD 'HxPassG_1';
PREPARE TRANSACTION 'hx_2pc';
SELECT * FROM hx;
ALTER USER hx_a PASSWORD 'HxPassG_1';                -- G was not saved: ok

DROP USER hx_a;
SELECT * FROM hx;
-- the history follows a renamed role: its passwords are salted with the
-- role OID, which does not change with the name
CREATE USER hx_r PASSWORD 'HxPassR_1';
ALTER USER hx_r PASSWORD 'HxPassR_2';
ALTER USER hx_r RENAME TO hx_r2;
SELECT * FROM hx;
ALTER USER hx_r2 PASSWORD 'HxPassR_1';               -- error, in the history
ALTER USER hx_r2 PASSWORD 'HxPassR_2';               -- error, in the history
-- the same when the rename is pending in the transaction
BEGIN;
ALTER USER hx_r2 RENAME TO hx_r3;
ALTER USER hx_r3 PASSWORD 'HxPassR_1';               -- error, in the history
ROLLBACK;
-- the same password on two roles gives two different hashes (from PG 14,
-- before the hash is not salted)
CREATE USER hx_s PASSWORD 'HxPassR_2';
SELECT count(DISTINCT password_hash) =
       CASE WHEN current_setting('server_version_num')::int >= 140000
            THEN 3 ELSE 2 END AS expected_distinct_hashes
  FROM pg_password_history WHERE rolename IN ('hx_r2', 'hx_s');
-- a new role with the name of a dropped role starts a new history
DROP USER hx_r2;
CREATE USER hx_r2 PASSWORD 'HxPassR_1';
SELECT * FROM hx;
DROP USER hx_r2;
DROP USER hx_s;

DROP VIEW hx;
SELECT pg_password_history_reset();
