# Force test to be a target instead of shell-builtin
.PHONY : install_plugin

# clean up these files too during make clean
CLEANFILES=*.log *.reject

# Include these extensions in dist
EXTRA_DIST = *.test *.result *.sql 

#Get filenames from OS
ALL_TESTS=*.test

MYSQLTEST_ARGS= --defaults-file=./mysqld_base_dir/testing_defaults.conf --include=create_testdb.sql  --result-file=$*.result
REAL_SO_PATH=`realpath ../src/.libs/lib_mysqludf_crypt.so`
############################

mysqltest:
	@if test -z "$(MYSQLTEST)" ; then echo "mysqltest not found"; exit 1; fi

*.result:
	$(MYSQLTEST) $(MYSQLTEST_ARGS) --record --result-file=$*.result < $*.test

*.run: *.test
	$(MYSQLTEST) $(MYSQLTEST_ARGS) < $*.test

# results: mysqltest -R < $(ALL_TESTS:*.test=*.result)

*.test: install_plugin
	$(MYSQLTEST) < $(ALL_TESTS:$*.test=$*.run)

install_plugin:
	$(MKDIR_P) -p mysqld_base_dir/plugins
	$(INSTALL) -m 755 $(REAL_SO_PATH) mysqld_base_dir/plugins/lib_mysqludf_crypt.so

start_mariadb:
	./start_mariadb_user_mode.sh

stop_mariadb:
	./stop_mariadb_user_mode.sh