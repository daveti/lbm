/*
 * User space sample for loading eBPF into LBM
 * Apr 13, 2018
 * root@davejingtian.org
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/version.h>
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
char pathname[] = "/sys/fs/bpf/lbm_pin";	/* Should be updated accordingly */
char license[] = "GPL";
char bpf_name[] = "daveti";	/* Should be updated accrodingly */


/* Change the eBPF prog here */
struct bpf_insn prog[] = {
	BPF_CALL_FUNC(BPF_FUNC_lbm_usb_get_devnum),	/* get devnum */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 77, 2),		/* if devnum == 77: goto pc+2 */
	BPF_MOV64_IMM(BPF_REG_0, 0),			/* r0 = 0 -> allow the pkt */
	BPF_EXIT_INSN(),
	BPF_MOV64_IMM(BPF_REG_0, 1),			/* r0 = 1  -> drop the pkt */
	BPF_EXIT_INSN(),	
};



int main(void)
{
	int prog_fd;
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.lbm.prog_type = BPF_PROG_TYPE_LBM,
	attr.lbm.insn_cnt = sizeof(prog)/sizeof(struct bpf_insn),
	attr.lbm.insns = ptr_to_u64(prog),
	attr.lbm.license = ptr_to_u64(license),
	attr.lbm.log_level = 1,	/* debug mode */
	attr.lbm.log_size = LOG_BUF_SIZE,
	attr.lbm.log_buf = ptr_to_u64(bpf_log_buf),
	attr.lbm.kern_version = LINUX_VERSION_CODE;	/* needs to match the current kernel */
	attr.lbm.subsys_idx = 0,	/* USB */
	attr.lbm.call_dir = 0,	/* Ingress */
	attr.lbm.pathname = ptr_to_u64(pathname),
	attr.lbm.bpf_name = ptr_to_u64(bpf_name),

	prog_fd = sys_bpf(BPF_PROG_LOAD_LBM, &attr, sizeof(attr));
	printf("eBPF is loaded into fd [%d], with logs:\n", prog_fd);
	printf("%s\n", bpf_log_buf);

	return 0;
}
