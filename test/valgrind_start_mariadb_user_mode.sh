#! /bin/bash -x

# This script configures, starts and provisions mariadb running as the current user in order to enable
# the system installation independent testing of these test scripts in this directory in conjunction with the library.

set -e
this_dir=$(realpath $(dirname "$0"))

MARIADB_START_ARGS="--defaults-file=${this_dir}/mysqld_base_dir/testing_defaults.conf --plugin-dir=${this_dir}/mysqld_base_dir/plugins/"

if [ -f ${this_dir}/curr_systemd_unit ]
then
    SYSTEMD_UNIT=$(cat "${this_dir}/curr_systemd_unit")
    if systemctl --user status -n0 "${SYSTEMD_UNIT}" &>/dev/null
    then
        systemctl --user stop "${SYSTEMD_UNIT}"
    fi
    rm "${this_dir}/curr_systemd_unit"
fi
function stop_unit {
    systemctl --user stop $SYSTEMD_UNIT
}

function generate_my_cnf {
    cat > "${1}" <<-_EOF
[client]
socket = "${this_dir}/mysqld_base_dir/mysqld.sock"

[mysqld]
socket = "${this_dir}/mysqld_base_dir/mysqld.sock"
datadir = "${this_dir}/mysqld_base_dir/mysqld_data_dir"
skip-external-locking
key_buffer_size = 16M
max_allowed_packet = 1M
table_open_cache = 64
sort_buffer_size = 512K
net_buffer_length = 8K
read_buffer_size = 256K
read_rnd_buffer_size = 512K
myisam_sort_buffer_size = 8M
max_connections = 1024
thread_concurrency = 8
skip-networking
binlog-format=mixed
log-bin=mysql-bin

_EOF
}
function error() {
    echo ${1} >&2
}

error $this_dir

if ! which mysqld &>/dev/null
then
    error mysqld executable could not be found in PATH variable
    exit 1
fi

mkdir -p "${this_dir}/mysqld_base_dir/mysqld_data_dir"

generate_my_cnf "${this_dir}/mysqld_base_dir/testing_defaults.conf"

mysql_install_db --defaults-file="${this_dir}/mysqld_base_dir/testing_defaults.conf" \
--datadir="${this_dir}/mysqld_base_dir/mysqld_data_dir"
LANG=C valgrind mysqld ${MARIADB_START_ARGS}
