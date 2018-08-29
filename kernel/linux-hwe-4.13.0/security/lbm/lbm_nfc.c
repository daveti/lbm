/*
 * BPF verifier ops and helper calles for lbm nfc
 * The BPF ctx is struct skb!
 * Apr 5, 2018
 * root@davejingtian.org
 */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <uapi/linux/lbm_bpf.h>
#include <net/nfc/nci.h>

/* BPF helpers */
BPF_CALL_1(lbm_nfc_nci_get_mt, struct sk_buff *, skb)
{
        return nci_mt(skb->data);
}

static const struct bpf_func_proto lbm_nfc_nci_get_mt_proto = {
        .func           = lbm_nfc_nci_get_mt,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
};


/* BPF verifier ops */
const struct bpf_func_proto *lbm_nfc_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	/* Common ones */
	/* lbm nfc specific */
	case BPF_FUNC_lbm_nfc_nci_get_mt:
		return &lbm_nfc_nci_get_mt_proto;
	default:
		return NULL;
	}
}

bool lbm_nfc_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
	/* Make sure we are in range */
	if (off < 0 || off >= sizeof(struct __lbm_nfc))
		return false;
	if (off % size != 0)
		return false;

	/* Block any write for now */
	if (type == BPF_WRITE)
		return false;

	return true;
}

u32 lbm_nfc_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
        case offsetof(struct __lbm_nfc, len):
                *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
                                bpf_target_off(struct sk_buff, len, 4, target_size));
                break;
	default:
		break;
	}

	return insn - insn_buf;
}

int lbm_nfc_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog)
{
	return 0;
}

int lbm_nfc_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
	return 0;
}

