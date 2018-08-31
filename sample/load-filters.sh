#!/bin/bash
#cat /sys/kernel/security/lbm/bpf_ingress
./remove-all-filters.sh
sleep 1

for i in `seq 1 $1`; do
  echo "Loading $i..."
  ./load_filter "scala$i" ./programs/scala.lbm
  sleep 0.2
done

echo ""
echo "-----Loaded Filters-----"
echo "Ingress:"
cat /sys/kernel/security/lbm/bpf_ingress | egrep ': .'
echo "Egress:"
cat /sys/kernel/security/lbm/bpf_egress | egrep ': .'
