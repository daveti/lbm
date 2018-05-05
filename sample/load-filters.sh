#!/bin/bash
#cat /sys/kernel/security/lbm/bpf_ingress
./remove-all-filters.sh
sleep 1

for i in `seq 1 10`; do
  echo "Loading $i..."
  ./lbm_user "daveti$i"
  sleep 1
done

echo ""
echo "-----Loaded Filters-----"
echo "Ingress:"
cat /sys/kernel/security/lbm/bpf_ingress | egrep ': .'
echo "Egress:"
cat /sys/kernel/security/lbm/bpf_egress | egrep ': .'
