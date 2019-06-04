SHELL := /bin/bash
# Force test to be a target instead of shell-builtin
.PHONY : *.test *.result *.run

# clean up these files too during make clean
CLEANFILES=*.log *.reject

# Include these extensions in dist
EXTRA_DIST = *.test *.result *.sql 

MYSQLTEST_ARGS=--defaults-file=mysqld_base_dir/testing_defaults.conf
REAL_SO_PATH=`realpath ../src/.libs/lib_mysqludf_crypt.so`
############################

mysqltest:
	@if test -z "$(MYSQLTEST)" ; then echo "mysqltest not found"; exit 1; fi

*.result:
	mysqltest $(MYSQLTEST_ARGS) --record --result-file=$@ < $(basename $@).test

*.run: create_db.test
	./$@ $(MYSQLTEST_ARGS)

*.test:
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

all: start_mariadb *.test stop_mariadb