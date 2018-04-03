/*
 * BPF verifier ops and helper calles for lbm-usb
 * Apr 3, 2018
 * root@davejingtian.org
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/usb.h>

/* BPF helpers */


/* BPF verifier ops */
const struct bpf_func_proto *lbm_usb_func_proto(enum bpf_func_id func_id)
{
}

bool lbm_usb_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
}

u32 lbm_usb_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size)
{
}

int lbm_usb_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog)
{
}

int lbm_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
}

