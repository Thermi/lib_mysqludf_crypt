#! /bin/bash

signal ./stop_mariadb_user_mode.sh exit

./start_mariadb_user_mode.sh

for test in *.test
do
if mysqltest --defaults-file=mysqld_base_dir/testing_defaults.conf -u root < ${test} --result-file ${test%.test}.result &>/dev/null
then
    echo -n "+"
else
    echo -n "-"
fi
done
