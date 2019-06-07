bin_PROGRAMS = check_constant_time
AM_CFLAGS = $(CFLAGS) -march=x86-64 -mtune=generic -pipe -fstack-protector-strong \
			-fno-plt -O2 -g3 -Wall -Werror -Wno-format-extra-args -DSTANDARD -DMYSQL_SERVER @MYSQL_CFLAGS@ \
			-Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -fvar-tracking-assignments
AM_CXXFLAGS = -DSTANDARD -DMYSQL_SERVER @MYSQL_CFLAGS@
AM_LDFLAGS = -module -avoid-version -no-undefined -rpath @MYSQL_PLUGINDIR@ 

check_constant_time_LDADD = ../src/lib_mysqludf_crypt.la

# lib_LTADD = ../src/lib_mysqludf_crypt.la $(INTLLIBS)

# check_constant_time_SOURCES = \
# 	check_constant_time.c

# check_constant_time_LIBBADD = \
# 	../src/lib_mysqludf_crypt.la

AM_CFLAGS += @botan_CFLAGS@ @botan_LIBS@ -I../src/

#SHELL = /bin/bash

# clean up these files too during make clean
CLEANFILES=*.log *.reject

# Include these extensions in dist
EXTRA_DIST = *.test *.result *.sql 

MYSQLTEST_ARGS=--defaults-file=mysqld_base_dir/testing_defaults.conf
REAL_SO_PATH=`realpath ../src/.libs/lib_mysqludf_crypt.so`
############################

mysqltest:
	@if test -z "$(MYSQLTEST)" ; then echo "mysqltest not found"; exit 1; fi

%.result:
	mysqltest $(MYSQLTEST_ARGS) --record --result-file=$@ < $(basename $@).test

%.run: create_db.test
	./$@

%.test:
	mysqltest $(MYSQLTEST_ARGS) --result-file=$(basename $@).result < $(@)

create_db.test:
	mysqltest $(MYSQLTEST_ARGS) --result-file=create_db.result < create_db.test

install_db:
	mysql $(MYSQLTEST_ARGS) < ../sql/installdb.sql

install_plugin:
	$(MKDIR_P) -p mysqld_base_dir/plugins
	$(INSTALL) -m 755 $(REAL_SO_PATH) mysqld_base_dir/plugins/lib_mysqludf_crypt.so

start_mariadb:
	./start_mariadb_user_mode.sh

stop_mariadb:
	./stop_mariadb_user_mode.sh

install_shared_object:
	$(INSTALL) -m 755 $(REAL_SO_PATH) lib_mysqludf_crypt.so

all: start_mariadb *.run stop_mariadb

.PHONY: %.test %.result %.run create_db.test
