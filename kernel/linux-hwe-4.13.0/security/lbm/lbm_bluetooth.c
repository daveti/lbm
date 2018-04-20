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
#include <net/bluetooth/hci.h>

/* BPF helpers */
BPF_CALL_1(lbm_bluetooth_event_get_evt, struct sk_buff *, skb)
{
	struct hci_event_hdr *hdr = (void *) skb->data;
	return hdr->evt;
}

static const struct bpf_func_proto lbm_bluetooth_event_get_evt_proto = {
	.func           = lbm_bluetooth_event_get_evt,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_event_get_plen, struct sk_buff *, skb)
{
	struct hci_event_hdr *hdr = (void *) skb->data;
	return hdr->plen;
}

static const struct bpf_func_proto lbm_bluetooth_event_get_plen_proto = {
	.func           = lbm_bluetooth_event_get_plen,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_bluetooth_event_data_load_bytes, struct sk_buff *, skb, u32, offset,
		void *, to, u32, len)
{
	struct hci_event_hdr *hdr = (void *) skb->data;
	int plen = hdr->plen;

	if ((unlikely(offset > plen)) ||
		(unlikely(len > plen)) ||
		(unlikely(offset+len > plen)))
		goto event_data_load_err;

	memcpy(to, (void *)skb->data+HCI_EVENT_HDR_SIZE+offset, len);
	return 0;

event_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_event_data_load_bytes_proto = {
	.func           = lbm_bluetooth_event_data_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};






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
	case offsetof(struct __lbm_bluetooth, pkt_type):
		*insn++ = BPF_LDX_MEM(BPF_B, si->dst_reg, si->src_reg,
				bpf_target_off(struct sk_buff, cb, 1, target_size));
		break;
	case offsetof(struct __lbm_usb, pkt_len):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct sk_buff, len, 4, target_size));
		break;
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

