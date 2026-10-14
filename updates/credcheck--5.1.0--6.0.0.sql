-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION credcheck UPDATE TO '6.0.0'" to load this file. \quit

----
-- lastlog: utmp/wtmp-like login history. The data is kept in shared memory
-- and a memory-mapped file managed by the C code; this only exposes it.
----
CREATE FUNCTION credcheck_lastlog (
	OUT type        text,
	OUT username    text,
	OUT pid         integer,
	OUT client_addr text,
	OUT client_port integer,
	OUT login_time  timestamp with time zone,
	OUT logout_time timestamp with time zone,
	OUT duration    interval,
	OUT state       text,
	OUT query       text
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'credcheck_lastlog'
LANGUAGE C VOLATILE;

CREATE VIEW pg_lastlog AS
  SELECT * FROM credcheck_lastlog();

REVOKE ALL ON FUNCTION credcheck_lastlog() FROM PUBLIC;
REVOKE ALL ON pg_lastlog FROM PUBLIC;
GRANT SELECT ON pg_lastlog TO pg_read_all_stats;

REVOKE ALL ON FUNCTION pg_password_history() FROM PUBLIC;
REVOKE ALL ON pg_password_history FROM PUBLIC;
GRANT SELECT ON pg_password_history TO pg_read_all_stats;

----
-- Check a candidate password (and the associated username) against the
-- configured credcheck username/password policy without creating or
-- altering a role. Raises the same error as CREATE/ALTER ROLE would when
-- the policy is violated, and returns true when the password is accepted.
-- Note: the password reuse policy is not evaluated here
----
CREATE FUNCTION pg_check_password( IN username name, IN password text )
RETURNS boolean
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE;

----
-- lastlog: utmp/wtmp-like login history (see credcheck.lastlog GUC).
----
CREATE FUNCTION credcheck_lastlog (
	OUT type        text,
	OUT username    text,
	OUT pid         integer,
	OUT client_addr text,
	OUT client_port integer,
	OUT login_time  timestamp with time zone,
	OUT logout_time timestamp with time zone,
	OUT duration    interval,
	OUT state       text,
	OUT query       text
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'credcheck_lastlog'
LANGUAGE C VOLATILE;

CREATE VIEW pg_lastlog AS
  SELECT * FROM credcheck_lastlog();

REVOKE ALL ON FUNCTION credcheck_lastlog() FROM PUBLIC;
REVOKE ALL ON pg_lastlog FROM PUBLIC;
GRANT SELECT ON pg_lastlog TO pg_read_all_stats;
