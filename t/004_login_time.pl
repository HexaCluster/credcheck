
# Regression test for the login time restrictions:
#   credcheck.login_denied_hours, credcheck.login_denied_days and
#   credcheck.whitelist_login_time.
#
# pg_regress cannot control the clock, so the test controls the server
# timezone instead: the configured timezone is set to a fixed POSIX offset
# that puts the server local time close to 12:00 when the test starts. All
# the ranges used below keep a margin of at least one hour around that time,
# so the outcome does not depend on when the test runs. This also checks that
# the server timezone (and not the client one) is used.
#
# Covers:
#   - syntax validation of the GUCs (rejected by ALTER SYSTEM);
#   - the GUCs cannot be changed at session level (PGC_SIGHUP);
#   - denied days, including ranges wrapping around the end of the week;
#   - denied hours, including ranges wrapping around midnight;
#   - the whitelist;
#   - replication connections (physical and logical) are never refused;
#   - a failed authentication during a denied period still reports the
#     normal authentication error and a refused login neither increments nor
#     resets the max_auth_failure counter;
#   - the client timezone cannot change the decision.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Fixed offset putting the server local time at about 12:00 now.
my @utc = gmtime(time);
my $utc_min = $utc[2] * 60 + $utc[1];
my $delta = 720 - $utc_min;    # local = utc + delta, delta in (-720, 720]
# POSIX offsets are positive west of Greenwich: local = utc - offset.
my $off  = -$delta;
my $sign = $off < 0 ? '-' : '+';
my $tz   = sprintf("LTT%s%02d:%02d", $sign, abs($off) / 60, abs($off) % 60);

# Local week day (0 = sunday) at the fixed offset.
my @local = gmtime(time + $delta * 60);
my @days  = qw(sun mon tue wed thu fri sat);
my $today     = $days[ $local[6] ];
my $tomorrow  = $days[ ($local[6] + 1) % 7 ];
my $yesterday = $days[ ($local[6] + 6) % 7 ];
note "server timezone $tz, local time "
  . sprintf("%02d:%02d", $local[2], $local[1])
  . ", today is $today";

my $node = PostgreSQL::Test::Cluster->new('login_time');
$node->init(allows_streaming => 1);
$node->append_conf(
	'postgresql.conf', qq{
shared_preload_libraries = 'credcheck'
timezone = '$tz'
wal_level = logical
credcheck.max_auth_failure = 3
credcheck.password_min_length = 1
credcheck.password_contain_username = false
});
# carol authenticates with a password, everybody else through trust.
my $hba = $node->data_dir . '/pg_hba.conf';
my $hba_content = slurp_file($hba);
open(my $fh, '>', $hba) or die "could not write $hba: $!";
print $fh "local all carol scram-sha-256\n";
print $fh $hba_content;
close($fh);
$node->start;

$node->safe_psql('postgres', q{
	CREATE EXTENSION credcheck;
	CREATE ROLE alice LOGIN REPLICATION;
	CREATE ROLE bob LOGIN;
	SET password_encryption = 'scram-sha-256';
	CREATE ROLE carol LOGIN PASSWORD 'carol_pwd';
});

# The test connects as the bootstrap superuser, named after the OS user
# running the test (not necessarily "postgres"): it must be whitelisted.
my $su = $node->safe_psql('postgres', 'SELECT current_user');
$node->safe_psql('postgres',
	"ALTER SYSTEM SET credcheck.whitelist_login_time = '\"$su\",bob'");
$node->reload;
$node->poll_query_until('postgres',
	"SELECT current_setting('credcheck.whitelist_login_time') <> ''")
  or die "timed out waiting for credcheck.whitelist_login_time";

my $refused = qr/rejecting connection, user '\w+' is not allowed to connect at this time/;

# Apply a configuration (hash of GUC => value) and reload.
sub set_policy
{
	my (%gucs) = @_;
	foreach my $g (qw(login_denied_hours login_denied_days))
	{
		my $v = exists $gucs{$g} ? $gucs{$g} : '';
		$node->safe_psql('postgres',
			"ALTER SYSTEM SET credcheck.$g = '$v'");
	}
	$node->reload;
	# wait until the reload has been processed
	foreach my $g (qw(login_denied_hours login_denied_days))
	{
		my $v = exists $gucs{$g} ? $gucs{$g} : '';
		$node->poll_query_until('postgres',
			"SELECT current_setting('credcheck.$g') = '$v'")
		  or die "timed out waiting for credcheck.$g = '$v'";
	}
}

sub can_connect
{
	my ($user, $connstr_extra) = @_;
	$connstr_extra //= '';
	my ($ret, $stdout, $stderr) = $node->psql(
		'postgres', 'SELECT 1',
		connstr => $node->connstr('postgres') . " user=$user $connstr_extra");
	return ($ret == 0 && $stdout eq '1', $stderr);
}

sub connect_ok_as
{
	my ($user, $name, $extra) = @_;
	my ($ok, $err) = can_connect($user, $extra);
	ok($ok, $name) or diag($err);
}

sub connect_refused_as
{
	my ($user, $name, $extra) = @_;
	my ($ok, $err) = can_connect($user, $extra);
	ok(!$ok && $err =~ $refused, $name) or diag("ok=$ok stderr=$err");
}

# ---------------------------------------------------------------------------
# 1. Syntax validation and context.
# ---------------------------------------------------------------------------
foreach my $bad ('25:00-01:00', '10:60-11:00', '10:00', '10:00-10:00',
	'1:00-2:00', '10:00-11:00-12:00', 'a:bc-12:00', '24:00-01:00')
{
	my ($ret, $out, $err) = $node->psql('postgres',
		"ALTER SYSTEM SET credcheck.login_denied_hours = '$bad'");
	isnt($ret, 0, "login_denied_hours rejects '$bad'");
}
foreach my $bad ('mo', 'monday-xyz', 'mon-', 'funday')
{
	my ($ret, $out, $err) = $node->psql('postgres',
		"ALTER SYSTEM SET credcheck.login_denied_days = '$bad'");
	isnt($ret, 0, "login_denied_days rejects '$bad'");
}
foreach my $good ('22:00-06:00, 12:30-13:30', '00:00-24:00', '')
{
	my ($ret, $out, $err) = $node->psql('postgres',
		"ALTER SYSTEM SET credcheck.login_denied_hours = '$good'");
	is($ret, 0, "login_denied_hours accepts '$good'") or diag($err);
}
foreach my $good ('sat,sun', 'mon-fri', 'Friday-Monday', 'SUN', '')
{
	my ($ret, $out, $err) = $node->psql('postgres',
		"ALTER SYSTEM SET credcheck.login_denied_days = '$good'");
	is($ret, 0, "login_denied_days accepts '$good'") or diag($err);
}
{
	my ($ret, $out, $err) = $node->psql('postgres',
		"SET credcheck.login_denied_days = 'sun'");
	isnt($ret, 0, 'login_denied_days cannot be set in a session');
	like($err, qr/cannot be changed now/, '... with the expected error');
}

# ---------------------------------------------------------------------------
# 2. No restriction by default.
# ---------------------------------------------------------------------------
set_policy();
connect_ok_as('alice', 'no restriction: alice can connect');

# ---------------------------------------------------------------------------
# 3. Denied days.
# ---------------------------------------------------------------------------
set_policy(login_denied_days => $today);
connect_refused_as('alice', "today ($today) denied: alice is refused");
connect_ok_as('bob',      'today denied: whitelisted bob can connect');
connect_ok_as($su, 'today denied: whitelisted superuser can connect');
connect_refused_as('alice', 'client timezone does not change the decision',
	"options='-c timezone=UTC+12'");

set_policy(login_denied_days => "$tomorrow-$yesterday");
connect_ok_as('alice', "$tomorrow-$yesterday denied (all but today): alice can connect");

set_policy(login_denied_days => "$today-$yesterday");
connect_refused_as('alice', "$today-$yesterday (whole week, wrapping) denied: alice is refused");

# ---------------------------------------------------------------------------
# 4. Denied hours (local time is about 12:00).
# ---------------------------------------------------------------------------
set_policy(login_denied_hours => '00:00-24:00');
connect_refused_as('alice', '00:00-24:00 denied: alice is refused');
connect_ok_as('bob', '00:00-24:00 denied: whitelisted bob can connect');

set_policy(login_denied_hours => '10:00-15:00');
connect_refused_as('alice', '10:00-15:00 denied: alice is refused');

set_policy(login_denied_hours => '20:00-15:00');
connect_refused_as('alice', '20:00-15:00 (wrapping midnight) denied: alice is refused');

set_policy(login_denied_hours => '15:00-10:00');
connect_ok_as('alice', '15:00-10:00 (wrapping midnight) denied: alice can connect');

set_policy(login_denied_hours => '00:00-10:00, 15:00-24:00');
connect_ok_as('alice', 'two ranges around noon denied: alice can connect');

set_policy(login_denied_hours => '00:00-10:00, 11:00-13:00');
connect_refused_as('alice', 'second range matches: alice is refused');

# hours and days are independent (OR)
set_policy(login_denied_hours => '15:00-10:00', login_denied_days => $today);
connect_refused_as('alice', 'hours allow but day denies: alice is refused');

ok($node->log_contains(qr/Logins are denied from 11:00 to 13:00 by credcheck\.login_denied_hours/),
	'the server log explains which hour range matched');
ok($node->log_contains(qr/Logins are denied on $today by credcheck\.login_denied_days/),
	'the server log explains which day matched');

# ---------------------------------------------------------------------------
# 5. Replication is never refused.
# ---------------------------------------------------------------------------
set_policy(login_denied_hours => '00:00-24:00', login_denied_days => $today);
{
	my ($ret, $out, $err) = $node->psql(
		'postgres', 'IDENTIFY_SYSTEM',
		connstr => $node->connstr('postgres') . ' user=alice replication=database');
	is($ret, 0, 'logical replication connection is not refused') or diag($err);

	($ret, $out, $err) = $node->psql(
		'postgres', 'IDENTIFY_SYSTEM',
		connstr => $node->connstr('postgres') . ' user=alice replication=true');
	is($ret, 0, 'physical replication connection is not refused') or diag($err);
}
connect_refused_as('alice', 'but a normal connection of the same role is refused');

# a standby can stream during a denied period
{
	$node->backup('bkp');
	my $standby = PostgreSQL::Test::Cluster->new('standby');
	$standby->init_from_backup($node, 'bkp', has_streaming => 1);
	$standby->append_conf('postgresql.conf',
		"primary_conninfo = 'port=" . $node->port . " host=" . $node->host
		  . " user=alice application_name=standby'");
	$standby->start;
	$node->safe_psql('postgres', 'CREATE TABLE repl_check AS SELECT 42 AS v');
	$node->wait_for_replay_catchup($standby);
	is($standby->safe_psql('postgres', 'SELECT v FROM repl_check'), '42',
		'a standby streams as a non whitelisted role during a denied period');
	$standby->stop;
}

# ---------------------------------------------------------------------------
# 6. Interaction with authentication failures and max_auth_failure.
# ---------------------------------------------------------------------------
sub carol_failures
{
	return $node->safe_psql('postgres',
		"SELECT coalesce(max(failure_count), 0) FROM pg_banned_role WHERE roleid = 'carol'::regrole");
}

set_policy();
{
	local $ENV{PGPASSWORD} = 'wrong';
	my ($ok, $err) = can_connect('carol');
	ok(!$ok && $err =~ /password authentication failed/,
		'no restriction: bad password fails as usual');
}
is(carol_failures(), '1', 'one authentication failure recorded');

set_policy(login_denied_days => $today);
{
	local $ENV{PGPASSWORD} = 'wrong';
	my ($ok, $err) = can_connect('carol');
	ok(!$ok && $err =~ /password authentication failed/ && $err !~ $refused,
		'denied period: a bad password reports the authentication error, not the policy');
}
is(carol_failures(), '2', 'the failed authentication is counted');
{
	local $ENV{PGPASSWORD} = 'carol_pwd';
	connect_refused_as('carol', 'denied period: good password is refused by the policy');
	connect_refused_as('carol', 'denied period: and again');
}
is(carol_failures(), '2',
	'refused logins neither increment nor reset the failure counter');

set_policy();
{
	local $ENV{PGPASSWORD} = 'carol_pwd';
	connect_ok_as('carol', 'restriction removed: carol can connect');
}
is(carol_failures(), '0', 'a successful login resets the failure counter');

$node->stop;
done_testing();
