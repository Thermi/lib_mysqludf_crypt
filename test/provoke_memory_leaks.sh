#! /bin/bash

# load DB

# run 1.000.000 hash calculations eachin 16 threads

MYSQL_TEST_ARGS="--defaults-file=mysqld_base_dir/testing_defaults.conf -u root "
source create_db.sql

for i in {0..16}
do
    coproc mysqltest $MYSQL_TEST_ARGS < provoke_memory_leaks.sql
done

wait $(jobs -p)