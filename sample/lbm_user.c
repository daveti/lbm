/*
 * User space sample for loading eBPF into LBM
 * Apr 13, 2018
 * root@davejingtian.org
 */
#include <stdio.h>
#include <unistd.h>
#include "libbpf.h"

#define LOG_BUF_SIZE		4096

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

char bpf_log_buf[LOG_BUF_SIZE];
char pathname[] = "./lbm_pin";
char license[] = "GPL";
char bpf_name[] = "daveti";	/* Should be updated accrodingly */


/* Change the eBPF prog here */
struct bpf_insn prog[] = {
	
};



int main(void)
{
	int prog_fd;

	union bpf_attr attr = {
		.lbm.prog_type = BPF_PROG_TYPE_LBM,
		.lbm.insn_cnt = sizeof(prog)/sizeof(struct bpf_insn),
		.lbm.insns = ptr_to_u64(prog),
	.lbm.license = ptr_to_u64(license),
	.lbm.log_level = 1,	/* debug mode */
	.lbm.log_size = LOG_BUF_SIZE,
	.lbm.log_buf = ptr_to_u64(bpf_log_buf),
	.lbm.subsys_idx = 0,	/* USB */
	.lbm.call_dir = 0,	/* Ingress */
	.lbm.pathname = ptr_to_u64(pathname),
	.lbm.bpf_name = ptr_to_u64(bpf_name),
};



	prog_fd = sys_bpf(BPF_PROG_LOAD_LBM, &attr, sizeof(attr));
	printf("eBPF is loaded into fd [%d], with logs:\n", prog_fd);
	printf("%s\n", bpf_log_buf);

	return 0;
}
