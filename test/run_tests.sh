#! /bin/bash

signal ./stop_mariadb_user_mode.sh exit

./start_mariadb_user_mode.sh

for test in *.test
if mysqltest --defaults-file=mysqld_base_dir/testing_defaults.conf -u root < ${test} --result-file ${test%.test}.result
then
    echo -n "+"
else
    echo -n "-"
fi
