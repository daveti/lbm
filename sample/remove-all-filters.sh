#!/bin/bash

remove_programs() {
  local filterlist=$1

  ingress_filters="$(cat $filterlist)"

  IFS=$'\n'
  for line in $ingress_filters; do
    subsys=$(echo "$line" | awk '{print $2}')
    programs=$(echo "$line" | awk '{$1=""; $2=""; print $0}')

    IFS=$' '
    for program in $programs; do
      echo "Removing $program from $subsys"
      echo "rm:$program" > $filterlist

      if [ -f "/sys/fs/bpf/$program" ]; then
        rm "/sys/fs/bpf/$program"
      else
        echo "WARNING: $program doesnt have an lbm pin"
      fi
    done
  done
}

remove_programs /sys/kernel/security/lbm/bpf_ingress
remove_programs /sys/kernel/security/lbm/bpf_egress
