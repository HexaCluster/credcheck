# Concurrent password changes of the same role: the second change waits for
# the first transaction, then its reuse check sees the first change if it was
# committed and does not see it if it was rolled back. Without this wait
# PostgreSQL fails the second change with "tuple concurrently updated".

setup
{
  SET credcheck.password_reuse_history = 3;
  SET password_encryption = 'scram-sha-256';
  SELECT pg_password_history_reset() IS NOT NULL AS reset;
  CREATE ROLE iso_r PASSWORD 'IsoPassA_1';
}

teardown
{
  DROP ROLE iso_r;
  SELECT pg_password_history_reset() IS NOT NULL AS reset;
}

session s1
setup		{ SET credcheck.password_reuse_history = 3; }
step s1b	{ BEGIN; }
step s1a	{ ALTER ROLE iso_r PASSWORD 'IsoPassB_1'; }
step s1c	{ COMMIT; }
step s1r	{ ROLLBACK; }

session s2
setup		{ SET credcheck.password_reuse_history = 3; }
step s2a	{ ALTER ROLE iso_r PASSWORD 'IsoPassB_1'; }
step s2c	{ ALTER ROLE iso_r PASSWORD 'IsoPassC_1'; }
step s2n	{ SELECT count(*) AS entries FROM pg_password_history WHERE rolename = 'iso_r'; }

# s2 waits for s1, then is rejected: B is now in the history
permutation s1b s1a s2a s1c s2n
# s1 is rolled back: s2 can use B
permutation s1b s1a s2a s1r s2n
# a different password: s2 waits for s1 and succeeds, history: A, B, C
permutation s1b s1a s2c s1c s2n
