EXTENSION = credcheck
EXTVERSION = $(shell grep default_version $(EXTENSION).control | \
	       sed -e "s/default_version[[:space:]]*=[[:space:]]*'\([^']*\)'/\1/")

# Uncomment the following two lines to enable cracklib support, adapt the path
# to the cracklib dictionary following your distribution
#PG_CPPFLAGS = -DUSE_CRACKLIB '-DCRACKLIB_DICTPATH="/usr/lib/cracklib_dict"'
#SHLIB_LINK = -lcrack

PG_CPPFLAGS += -Wno-ignored-attributes -flto

MODULE_big = credcheck
OBJS = credcheck.o $(WIN32RES)
PGFILEDESC = "credcheck - postgresql credential checker"

DATA = $(wildcard updates/*--*.sql) sql/$(EXTENSION)--$(EXTVERSION).sql

REGRESS_OPTS  = --inputdir=test --load-extension=credcheck
TESTS = 01_username 02_password 03_rename 04_alter_pwd \
	05_reuse_history 06_reuse_interval 07_valid_until \
	08_first_login 09_plpgsql 10_no_password_logging \
	11_max_auth_pgbouncer 12_role_changes 13_multibyte 14_history_xact

REGRESS = $(patsubst test/sql/%.sql,%,$(TESTS))

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)

# pg_isolation_regress is installed for out-of-tree use since PostgreSQL 14
# only; distro packages for older majors (e.g. PGDG 12/13) do not ship it,
# so run the isolation test only where the tool exists.
PG_ISOLATION_REGRESS := $(dir $(PGXS))../../src/test/isolation/pg_isolation_regress
ifeq ($(shell test -x "$(PG_ISOLATION_REGRESS)" && echo yes),yes)
ISOLATION = history_concurrent
ISOLATION_OPTS = --inputdir=test --load-extension=credcheck
endif

TAP_TESTS = 1

include $(PGXS)
