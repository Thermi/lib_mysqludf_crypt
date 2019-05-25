#! /bin/bash

this_dir=$(realpath $(dirname "$0"))

if [ -f ${this_dir}/curr_systemd_unit ]
then
    SYSTEMD_UNIT=$(cat "${this_dir}/curr_systemd_unit")
    if systemctl --user status -n0 "${SYSTEMD_UNIT}" &>/dev/null
    then
        systemctl --user stop "${SYSTEMD_UNIT}"
    fi
    rm "${this_dir}/curr_systemd_unit"
fi