/*
 * BPF verifier ops and helper calles for lbm bluetooth
 * The BPF ctx is struct skb!
 * Apr 5, 2018
 * root@davejingtian.org
 */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <uapi/linux/lbm_bpf.h>

/* BPF helpers */


/* BPF verifier ops */
const struct bpf_func_proto *lbm_bluetooth_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	/* Common ones */
	/* lbm bluetooth specific */
	default:
		return NULL;
	}
}

bool lbm_bluetooth_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
	/* Make sure we are in range */
	if (off < 0 || off >= sizeof(struct __lbm_bluetooth))
		return false;
	if (off % size != 0)
		return false;

	/* Block any write for now */
	if (type == BPF_WRITE)
		return false;

	return true;
}

u32 lbm_bluetooth_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	default:
		break;
	}

	return insn - insn_buf;
}

int lbm_bluetooth_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog)
{
	return 0;
}

int lbm_bluetooth_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
	return 0;
}

