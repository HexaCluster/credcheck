LOAD 'credcheck';

SET log_statement = 'all';
SET lc_messages = 'C';
SET credcheck.password_min_length = 8;
SET credcheck.password_min_special = 0;
SET credcheck.password_min_digit = 0;
SET credcheck.password_min_upper = 0;
SET credcheck.password_min_lower = 0;
SET credcheck.password_contain_username = false;

-- Enabled by default
SHOW credcheck.no_password_logging;
SET client_min_messages TO LOG;

CREATE ROLE alice LOGIN PASSWORD 'Sup3rStr0ng!';
ALTER ROLE alice ENCRYPTED PASSWORD 'An0therGoodOne#';

-- Normal string literal with a doubled (embedded) quote.
CREATE ROLE bob LOGIN PASSWORD 'pa''ss W0rdX1';
-- Escape-string constant with a backslash escape.
CREATE ROLE dave LOGIN PASSWORD E'pa\ss W0rdX2';
-- Rejected password (too short) -> ERROR + "STATEMENT:" line.
ALTER ROLE alice PASSWORD 'Zq3xK';
-- Ordinary data mentioning "password", and a comment containing the word
SELECT 'my password is hunter2' AS note;
/* set the password here */ CREATE ROLE carol LOGIN PASSWORD 'Comm3ntPwd!';

-- Issue #88: dollar-quoted password value.
CREATE ROLE erin LOGIN PASSWORD $mask_me$D0llarPwd!x$mask_me$;
-- Issue #88: password inside a DO block, dollar-quoted or single-quoted.
DO $$ BEGIN CREATE ROLE frank LOGIN PASSWORD 'D0blockPwd!'; END $$;
DO 'BEGIN CREATE ROLE gina LOGIN PASSWORD ''D0quotedPwd!''; END';
-- Issue #88: arguments of pg_check_password(), positional and named.
SELECT pg_check_password('erin', 'Ch3ckedPwd!');
SELECT pg_check_password(username => 'erin', password => 'Ch3ckedPwd!');
-- Data mentioning "password" in a dollar-quoted string is left alone.
SELECT $$the password is not here$$ AS note;
-- A positional parameter is not a dollar quote.
PREPARE p(text) AS SELECT $1 AS v, $$password '$$ AS w;
EXECUTE p('keep me');
DEALLOCATE p;

-- Normal behavior when no_password_logging is disabled
SET credcheck.no_password_logging = off;
ALTER ROLE alice PASSWORD 'Zq3xK';

DROP ROLE alice;
DROP ROLE bob;
DROP ROLE dave;
DROP ROLE carol;
DROP ROLE erin;
DROP ROLE frank;
DROP ROLE gina;

