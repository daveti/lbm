echo 1 > /sys/kernel/security/lbm/perf_option
echo 'bluetooth-l2cap:rx:1,bluetooth-l2cap:tx:1,bluetooth:rx:1,bluetooth:tx:1' > perf
# Optional
# echo 1 > /proc/sys/net/core/bpf_jit_enable

# Filter
# subsys = 0 (USB)
# subsys = 1 (bt-hci)
# subsys = 2 (bt-l2cap)
# cat /var/log/kern.log | grep lbm-perf | grep 'for subsys \[2\]' | grep 'and dir \[0\]' | tail -10000 | awk '{ print $10; }' |  egrep -o '[0-9]+'
