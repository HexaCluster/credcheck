# Test that a pg_upgrade run does not break on credcheck's password
# policies when it restores role passwords and validity dates.
#
# pg_upgrade restores the roles with the script of
# "pg_dumpall --globals-only --binary-upgrade".  For each role the
# script contains:
#
#   SELECT pg_catalog.binary_upgrade_set_next_pg_authid_oid('16384');
#   CREATE ROLE r;
#   ALTER ROLE r WITH LOGIN PASSWORD 'SCRAM-SHA-256$4096:...'
#         [VALID UNTIL '...'];
#
# pg_upgrade starts the new cluster with -b (src/bin/pg_upgrade/server.c),
# so the server runs in binary upgrade mode.  credcheck is in
# shared_preload_libraries there too, and its hooks see the statements
# above as user password changes:
#
#   - the verifier is not plain text.  credcheck rejects it and the
#     upgrade stops with "ERROR:  password type is not a plain text";
#   - credcheck.password_valid_until/_min/_max replace the dumped
#     rolvaliduntil with now() + N days, or reject it.
#
# In binary upgrade mode credcheck therefore acts as if
# encrypted_password_allowed were on and the VALID UNTIL GUCs were 0.
# All other checks stay on, and each restored verifier is recorded in
# the password history.
#
# A full pg_upgrade is not necessary here: the restore only needs a
# server started with -b.  The test builds a small "old cluster" state,
# restarts the server with -b, and replays the statements that
# pg_dumpall --binary-upgrade writes.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('binary_upgrade');
$node->init;
$node->append_conf(
	'postgresql.conf', q{
shared_preload_libraries = 'credcheck'
credcheck.encrypted_password_allowed = off
credcheck.password_reuse_history = 3
});
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION credcheck');

$node->safe_psql('postgres',
	q{CREATE ROLE normal_scram LOGIN PASSWORD 'Initial-Password-1!'});
$node->safe_psql('postgres',
	q{CREATE ROLE binary_scram LOGIN PASSWORD 'Initial-Password-2!'});
$node->safe_psql('postgres',
	q{CREATE ROLE binary_history LOGIN PASSWORD 'Initial-Password-3!'});

my $normal_scram = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'normal_scram'});
my $scram = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_scram'});
my $history_password = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_history'});
my $history_before = $node->safe_psql('postgres',
	q{SELECT rolename, count(*) FROM pg_password_history
	  WHERE rolename LIKE 'binary_%' GROUP BY rolename ORDER BY rolename});

# The fixture mimics the source cluster of a pg_upgrade: the roles went
# through the normal policy path, so they have encrypted SCRAM verifiers
# and password history entries.
# Outside binary upgrade mode the same statement must still be rejected.
# The binary-upgrade rules must not weaken normal operation.
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER ROLE normal_scram PASSWORD '$normal_scram'");
is($ret, 3, 'encrypted password is rejected in normal mode');
like($stderr, qr/password type is not a plain text/,
	'normal mode reports the expected error');

$node->stop;

# Cluster::start() has no extra-options parameter.  Restart the server
# with -b exactly as pg_upgrade starts the new cluster for the restore
# phase (pg_upgrade/server.c: pg_ctl start -o "-p <port> -b ..."), then
# register the postmaster pid for the usual teardown.
$ret = PostgreSQL::Test::Utils::system_log(
	'pg_ctl', '--wait',
	'--pgdata' => $node->data_dir,
	'--log' => $node->logfile,
	'--options' => '-b',
	'start');
is($ret, 0, 'server starts in binary upgrade mode');
BAIL_OUT('could not start server in binary upgrade mode') if $ret != 0;
$node->_update_pid(1);

# The statement pg_dumpall --binary-upgrade emits for a role with a SCRAM
# password.  On unfixed credcheck this is the exact point where pg_upgrade
# dies with "password type is not a plain text".
($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER ROLE binary_scram PASSWORD '$scram'");
is($ret, 0, 'binary upgrade accepts an encrypted SCRAM verifier');
diag($stderr) if $ret != 0;

if ($ret == 0)
{
	is($node->safe_psql('postgres',
			q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_scram'}),
		$scram, 'SCRAM verifier is restored byte-for-byte');

	# Restoring a role that has password reuse history.  The reuse check
	# runs as usual, but the history holds HMACs of the plaintext passwords
	# set before, so the verifier never matches them.
	($ret, $stdout, $stderr) = $node->psql('postgres',
		"ALTER ROLE binary_history PASSWORD '$history_password'");
	is($ret, 0, 'binary upgrade restores a role with reuse history enabled');
	diag($stderr) if $ret != 0;

	# pg_upgrade does not copy the history store.  The verifier goes through
	# the regular path, as with credcheck.encrypted_password_allowed = on,
	# so the history gets one new entry per restored role.  (Here the
	# fixture entries are still present; a real new cluster starts empty.)
	is($history_before, "binary_history|1\nbinary_scram|1",
		'fixture has one history entry per role');
	is($node->safe_psql('postgres',
			q{SELECT rolename, count(*) FROM pg_password_history
			  WHERE rolename LIKE 'binary_%' GROUP BY rolename ORDER BY rolename}),
		"binary_history|2\nbinary_scram|2",
		'binary upgrade records restored verifiers in password history');
}

# rolvaliduntil is catalog data.  The restore must keep it as dumped,
# whatever VALID UNTIL policy applies to user password changes.  Each
# case replays the CREATE ROLE + ALTER ROLE pair that pg_dumpall
# --binary-upgrade writes, under a policy that would rewrite the dumped
# value (an expiry date added to a role that had none) or reject it (an
# expired date, a date beyond the maximum, a missing VALID UNTIL clause).
my @valid_until_cases = (
	# [ policy GUC, VALID UNTIL clause of the dump, expected rolvaliduntil ]
	[ 'password_valid_until = 30', q{VALID UNTIL '2020-01-01 00:00:00+00'}, q{'2020-01-01 00:00:00+00'} ],
	[ 'password_valid_until = 30', '', 'NULL' ],
	[ 'password_valid_min = 30',   '', 'NULL' ],
	[ 'password_valid_max = 30',   q{VALID UNTIL 'infinity'}, q{'infinity'} ],
	[ 'password_valid_max = 30',   '', 'NULL' ],
);
my $vu = 0;
foreach my $case (@valid_until_cases)
{
	my ($guc, $clause, $expected) = @$case;
	my $role = 'binary_validity_' . ++$vu;
	my $authid = 100000 + $vu;    # far from the fixture's role OIDs
	# SCRAM verifiers do not embed the role name, so $scram can be reused.
	# pg_dumpall writes this SELECT before each CREATE ROLE.  Without it,
	# core rejects CREATE ROLE in binary upgrade mode (commands/user.c).
	($ret, $stdout, $stderr) = $node->psql('postgres',
		"SELECT pg_catalog.binary_upgrade_set_next_pg_authid_oid('$authid');
		 SET credcheck.$guc;
		 CREATE ROLE $role;
		 ALTER ROLE $role WITH LOGIN PASSWORD '$scram' $clause");
	is($ret, 0, "binary upgrade restores $role under $guc");
	diag($stderr) if $ret != 0;
	is($node->safe_psql('postgres',
			"SELECT rolvaliduntil IS NOT DISTINCT FROM ${expected}::timestamptz
			 FROM pg_authid WHERE rolname = '$role'"),
		't', "$role keeps rolvaliduntil = $expected");
}

done_testing();
