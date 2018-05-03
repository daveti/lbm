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
#include <linux/lbm.h>
#include <uapi/linux/lbm_bpf.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci.h>
#include <net/bluetooth/hci_core.h>
#include <net/bluetooth/l2cap.h>

#define LBM_BLUETOOTH_CONN_PARAM_INVALID	0xffffffffffffffff

/* BPF helpers */
BPF_CALL_1(lbm_bluetooth_get_pkt_type, struct sk_buff *, skb)
{
	return hci_skb_pkt_type(skb);
}

static const struct bpf_func_proto lbm_bluetooth_get_pkt_type_proto= {
	.func           = lbm_bluetooth_get_pkt_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


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


BPF_CALL_1(lbm_bluetooth_acl_get_handle, struct sk_buff *, skb)
{
	struct hci_acl_hdr *hdr = (void *) skb->data;
	__u16 handle = __le16_to_cpu(hdr->handle);
	return hci_handle(handle);
}

static const struct bpf_func_proto lbm_bluetooth_acl_get_handle_proto = {
	.func           = lbm_bluetooth_acl_get_handle,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_acl_get_flags, struct sk_buff *, skb)
{
	struct hci_acl_hdr *hdr = (void *) skb->data;
	__u16 handle = __le16_to_cpu(hdr->handle);
	return hci_flags(handle);
}

static const struct bpf_func_proto lbm_bluetooth_acl_get_flags_proto = {
	.func           = lbm_bluetooth_acl_get_flags,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_acl_get_dlen, struct sk_buff *, skb)
{
	struct hci_acl_hdr *hdr = (void *) skb->data;
	return __le16_to_cpu(hdr->dlen);
}

static const struct bpf_func_proto lbm_bluetooth_acl_get_dlen_proto = {
	.func           = lbm_bluetooth_acl_get_dlen,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_bluetooth_acl_data_load_bytes, struct sk_buff *, skb, u32, offset,
		void *, to, u32, len)
{
	struct hci_acl_hdr *hdr = (void *) skb->data;
	int dlen = __le16_to_cpu(hdr->dlen);

	if ((unlikely(offset > dlen)) ||
		(unlikely(len > dlen)) ||
		(unlikely(offset+len > dlen)))
		goto acl_data_load_err;

	memcpy(to, (void *)skb->data+HCI_ACL_HDR_SIZE+offset, len);
	return 0;

acl_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_acl_data_load_bytes_proto = {
	.func           = lbm_bluetooth_acl_data_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_1(lbm_bluetooth_sco_get_handle, struct sk_buff *, skb)
{
	struct hci_sco_hdr *hdr = (void *) skb->data;
	__u16 handle = __le16_to_cpu(hdr->handle);
	return hci_handle(handle);
}

static const struct bpf_func_proto lbm_bluetooth_sco_get_handle_proto = {
	.func           = lbm_bluetooth_sco_get_handle,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_sco_get_flags, struct sk_buff *, skb)
{
	struct hci_sco_hdr *hdr = (void *) skb->data;
	__u16 handle = __le16_to_cpu(hdr->handle);
	return hci_flags(handle);
}

static const struct bpf_func_proto lbm_bluetooth_sco_get_flags_proto = {
	.func           = lbm_bluetooth_sco_get_flags,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_sco_get_dlen, struct sk_buff *, skb)
{
	struct hci_sco_hdr *hdr = (void *) skb->data;
	return hdr->dlen;
}

static const struct bpf_func_proto lbm_bluetooth_sco_get_dlen_proto = {
	.func           = lbm_bluetooth_sco_get_dlen,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_bluetooth_sco_data_load_bytes, struct sk_buff *, skb, u32, offset,
		void *, to, u32, len)
{
	struct hci_sco_hdr *hdr = (void *) skb->data;
	int dlen = hdr->dlen;

	if ((unlikely(offset > dlen)) ||
		(unlikely(len > dlen)) ||
		(unlikely(offset+len > dlen)))
		goto sco_data_load_err;

	memcpy(to, (void *)skb->data+HCI_SCO_HDR_SIZE+offset, len);
	return 0;

sco_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_sco_data_load_bytes_proto = {
	.func           = lbm_bluetooth_sco_data_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_1(lbm_bluetooth_command_get_ogf, struct sk_buff *, skb)
{
	struct hci_command_hdr *hdr = (void *) skb->data;
	__u16 opcode = __le16_to_cpu(hdr->opcode);
	return hci_opcode_ogf(opcode);
}

static const struct bpf_func_proto lbm_bluetooth_command_get_ogf_proto = {
	.func           = lbm_bluetooth_command_get_ogf,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_command_get_ocf, struct sk_buff *, skb)
{
	struct hci_command_hdr *hdr = (void *) skb->data;
	__u16 opcode = __le16_to_cpu(hdr->opcode);
	return hci_opcode_ocf(opcode);
}

static const struct bpf_func_proto lbm_bluetooth_command_get_ocf_proto = {
	.func           = lbm_bluetooth_command_get_ocf,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_command_get_plen, struct sk_buff *, skb)
{
	struct hci_command_hdr *hdr = (void *) skb->data;
	return hdr->plen;
}

static const struct bpf_func_proto lbm_bluetooth_command_get_plen_proto = {
	.func           = lbm_bluetooth_command_get_plen,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_bluetooth_command_data_load_bytes, struct sk_buff *, skb, u32, offset,
		void *, to, u32, len)
{
	struct hci_command_hdr *hdr = (void *) skb->data;
	int plen = hdr->plen;

	if ((unlikely(offset > plen)) ||
		(unlikely(len > plen)) ||
		(unlikely(offset+len > plen)))
		goto command_data_load_err;

	memcpy(to, (void *)skb->data+HCI_COMMAND_HDR_SIZE+offset, len);
	return 0;

command_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_command_data_load_bytes_proto = {
	.func           = lbm_bluetooth_command_data_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


/*
 * NOTE: these HCI layer conn helpers are the same as L2CAP ones
 * However, we may allow user space to pass conn as an argument.
 * In that case, these helpers would be different.
 * But for now, they are dup~
 * May 2, 2018
 * daveti
 */
BPF_CALL_1(lbm_bluetooth_has_conn, struct sk_buff *, skb)
{
	/*
	 * Although both event and command may have hci conn ready
	 * we need to look into the payload to find the index to find
	 * the conn, e.g., handle, bdaddr, etc.
	 */
	switch (hci_skb_pkt_type(skb)) {
	case HCI_ACLDATA_PKT:
		if (skb->lbm_bt.conn)
			return 1;
	case HCI_SCODATA_PKT:
		if (skb->lbm_bt.conn)
			return 1;
	default:
		return 0;
	}
}

static const struct bpf_func_proto lbm_bluetooth_has_conn_proto = {
	.func           = lbm_bluetooth_has_conn,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_dst, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	__u64 baddr = 0;

	if (!hcon)
		baddr = LBM_BLUETOOTH_CONN_PARAM_INVALID;
	else
		memcpy(&baddr, &hcon->dst, sizeof(bdaddr_t));

	return baddr;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_dst_proto = {
	.func           = lbm_bluetooth_get_conn_dst,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_dst_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->dst_type;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_dst_type_proto = {
	.func           = lbm_bluetooth_get_conn_dst_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_src, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	__u64 baddr = 0;

	if (!hcon)
		baddr = LBM_BLUETOOTH_CONN_PARAM_INVALID;
	else
		memcpy(&baddr, &hcon->src, sizeof(bdaddr_t));

	return baddr;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_src_proto = {
	.func           = lbm_bluetooth_get_conn_src,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_src_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->src_type;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_src_type_proto = {
	.func           = lbm_bluetooth_get_conn_src_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_state, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->state;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_state_proto = {
	.func           = lbm_bluetooth_get_conn_state,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_mode, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->mode;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_mode_proto = {
	.func           = lbm_bluetooth_get_conn_mode,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->type;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_type_proto = {
	.func           = lbm_bluetooth_get_conn_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_role, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->role;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_role_proto = {
	.func           = lbm_bluetooth_get_conn_role,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_key_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->key_type;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_key_type_proto = {
	.func           = lbm_bluetooth_get_conn_key_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_auth_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->auth_type;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_auth_type_proto = {
	.func           = lbm_bluetooth_get_conn_auth_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_sec_level, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->sec_level;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_sec_level_proto = {
	.func           = lbm_bluetooth_get_conn_sec_level,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_get_conn_io_capability, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->io_capability;
}

static const struct bpf_func_proto lbm_bluetooth_get_conn_io_capability_proto = {
	.func           = lbm_bluetooth_get_conn_io_capability,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};



/* l2cap */
BPF_CALL_1(lbm_bluetooth_l2cap_get_cid, struct sk_buff *, skb)
{
	struct l2cap_hdr *lh = (void *) skb->data;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		lh = (void *) skb->lbm_bt.data;
	return __le16_to_cpu(lh->cid);
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_cid_proto = {
	.func           = lbm_bluetooth_l2cap_get_cid,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_len, struct sk_buff *, skb)
{
	struct l2cap_hdr *lh = (void *) skb->data;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		lh = (void *) skb->lbm_bt.data;
	return __le16_to_cpu(lh->len);
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_len_proto = {
	.func           = lbm_bluetooth_l2cap_get_len,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_dst, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	__u64 baddr = 0;

	if (!hcon)
		baddr = LBM_BLUETOOTH_CONN_PARAM_INVALID;
	else
		memcpy(&baddr, &hcon->dst, sizeof(bdaddr_t));
	return baddr;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_dst_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_dst,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_dst_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->dst_type;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_dst_type_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_dst_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_src, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	__u64 baddr = 0;

	if (!hcon)
		baddr = LBM_BLUETOOTH_CONN_PARAM_INVALID;
	else
		memcpy(&baddr, &hcon->src, sizeof(bdaddr_t));
	return baddr;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_src_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_src,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_src_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->src_type;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_src_type_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_src_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_state, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->state;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_state_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_state,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_mode, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->mode;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_mode_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_mode,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->type;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_type_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_role, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->role;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_role_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_role,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_key_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->key_type;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_key_type_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_key_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_auth_type, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->auth_type;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_auth_type_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_auth_type,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_sec_level, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->sec_level;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_sec_level_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_sec_level,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conn_io_capability, struct sk_buff *, skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	if (!hcon)
		return LBM_BLUETOOTH_CONN_PARAM_INVALID;
	return hcon->io_capability;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conn_io_capability_proto = {
	.func           = lbm_bluetooth_l2cap_get_conn_io_capability,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_sig_cmd_num, struct sk_buff *, skb)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;

	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = skb->lbm_bt.data + L2CAP_HDR_SIZE;

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		data += L2CAP_CMD_HDR_SIZE;
		len  -= L2CAP_CMD_HDR_SIZE;
		cmd_len = le16_to_cpu(cmd->len);
		data += cmd_len;
		len  -= cmd_len;
		cnt++;
	}

	return cnt;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_sig_cmd_num_proto = {
	.func           = lbm_bluetooth_l2cap_get_sig_cmd_num,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_2(lbm_bluetooth_l2cap_get_sig_cmd_code_idx, struct sk_buff *, skb,
		u32, idx)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;

	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = skb->lbm_bt.data + L2CAP_HDR_SIZE;

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		if (idx == cnt)
			return cmd->code;
		data += L2CAP_CMD_HDR_SIZE;
		len  -= L2CAP_CMD_HDR_SIZE;
		cmd_len = le16_to_cpu(cmd->len);
		data += cmd_len;
		len  -= cmd_len;
		cnt++;
	}

	return 0;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_sig_cmd_code_idx_proto = {
	.func           = lbm_bluetooth_l2cap_get_sig_cmd_code_idx,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};


BPF_CALL_2(lbm_bluetooth_l2cap_get_sig_cmd_id_idx, struct sk_buff *, skb,
		u32, idx)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;

	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = skb->lbm_bt.data + L2CAP_HDR_SIZE;

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		if (idx == cnt)
			return cmd->ident;
		data += L2CAP_CMD_HDR_SIZE;
		len  -= L2CAP_CMD_HDR_SIZE;
		cmd_len = le16_to_cpu(cmd->len);
		data += cmd_len;
		len  -= cmd_len;
		cnt++;
	}

	return 0;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_sig_cmd_id_idx_proto = {
	.func           = lbm_bluetooth_l2cap_get_sig_cmd_id_idx,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};


BPF_CALL_2(lbm_bluetooth_l2cap_get_sig_cmd_len_idx, struct sk_buff *, skb,
		u32, idx)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;

	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = skb->lbm_bt.data + L2CAP_HDR_SIZE;

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		cmd_len = le16_to_cpu(cmd->len);
		if (idx == cnt)
			return cmd_len;
		data += L2CAP_CMD_HDR_SIZE;
		len  -= L2CAP_CMD_HDR_SIZE;
		data += cmd_len;
		len  -= cmd_len;
		cnt++;
	}

	return 0;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_sig_cmd_len_idx_proto = {
	.func           = lbm_bluetooth_l2cap_get_sig_cmd_len_idx,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};


BPF_CALL_5(lbm_bluetooth_l2cap_sig_cmd_data_load_bytes_idx, struct sk_buff *, skb,
		u32, offset, void *, to, u32, len, u32, idx)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len2 = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;

	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = skb->lbm_bt.data + L2CAP_HDR_SIZE;

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		cmd_len = le16_to_cpu(cmd->len);
		if (idx == cnt) {
			if ((unlikely(offset > cmd_len)) ||
				(unlikely(len > cmd_len)) ||
				(unlikely(offset+len > cmd_len)))
				goto sig_cmd_data_load_err;

			/* Copy the bytes */
			memcpy(to, data+L2CAP_CMD_HDR_SIZE+offset, len);
			return 0;
		}
		data += L2CAP_CMD_HDR_SIZE;
		len2  -= L2CAP_CMD_HDR_SIZE;
		data += cmd_len;
		len2  -= cmd_len;
		cnt++;
	}

sig_cmd_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_sig_cmd_data_load_bytes_idx_proto = {
	.func           = lbm_bluetooth_l2cap_sig_cmd_data_load_bytes_idx,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conless_psm, struct sk_buff *, skb)
{
	__le16 psm = get_unaligned((__le16 *)(skb->data+L2CAP_HDR_SIZE));
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		psm = get_unaligned((__le16 *)(skb->lbm_bt.data+L2CAP_HDR_SIZE));
	return __le16_to_cpu(psm);
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conless_psm_proto = {
	.func           = lbm_bluetooth_l2cap_get_conless_psm,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_bluetooth_l2cap_conless_data_load_bytes, struct sk_buff *, skb, u32, offset,
		void *, to, u32, len)
{
	int plen = skb->len;
	u8 *data = (void *)skb->data;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = (void *)skb->lbm_bt.data;
	
	data += L2CAP_PSMLEN_SIZE;
	plen -= L2CAP_PSMLEN_SIZE;

	if ((unlikely(offset > plen)) ||
		(unlikely(len > plen)) ||
		(unlikely(offset+len > plen)))
		goto conless_data_load_err;

	memcpy(to, data+offset, len);
	return 0;

conless_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_conless_data_load_bytes_proto = {
	.func           = lbm_bluetooth_l2cap_conless_data_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_le_sig_cmd_code, struct sk_buff *, skb)
{
	struct l2cap_cmd_hdr *cmd;

	if (skb->len < L2CAP_CMD_HDR_SIZE + L2CAP_HDR_SIZE)
		return 0;

	cmd = (struct l2cap_cmd_hdr *)skb->data+L2CAP_HDR_SIZE;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		cmd = (struct l2cap_cmd_hdr *)skb->lbm_bt.data+L2CAP_HDR_SIZE;

	return cmd->code;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_le_sig_cmd_code_proto = {
	.func           = lbm_bluetooth_l2cap_get_le_sig_cmd_code,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_le_sig_cmd_id, struct sk_buff *, skb)
{
	struct l2cap_cmd_hdr *cmd;

	if (skb->len < L2CAP_CMD_HDR_SIZE + L2CAP_HDR_SIZE)
		return 0;

	cmd = (struct l2cap_cmd_hdr *)skb->data+L2CAP_HDR_SIZE;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		cmd = (struct l2cap_cmd_hdr *)skb->lbm_bt.data+L2CAP_HDR_SIZE;

	return cmd->ident;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_le_sig_cmd_id_proto = {
	.func           = lbm_bluetooth_l2cap_get_le_sig_cmd_id,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_le_sig_cmd_len, struct sk_buff *, skb)
{
	struct l2cap_cmd_hdr *cmd;

	if (skb->len < L2CAP_CMD_HDR_SIZE + L2CAP_HDR_SIZE)
		return 0;

	cmd = (struct l2cap_cmd_hdr *)skb->data+L2CAP_HDR_SIZE;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		cmd = (struct l2cap_cmd_hdr *)skb->lbm_bt.data+L2CAP_HDR_SIZE;

	return le16_to_cpu(cmd->len);
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_le_sig_cmd_len_proto = {
	.func           = lbm_bluetooth_l2cap_get_le_sig_cmd_len,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_bluetooth_l2cap_le_sig_cmd_data_load_bytes, struct sk_buff *, skb, u32, offset,
		void *, to, u32, len)
{
	struct l2cap_cmd_hdr *cmd;
	u8 *data;
	int plen;

	if (skb->len < L2CAP_CMD_HDR_SIZE + L2CAP_HDR_SIZE)
		return 0;

	data = (void *)skb->data;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = (void *)skb->lbm_bt.data;
	data += L2CAP_HDR_SIZE;
	cmd = (void *)data;
	plen = le16_to_cpu(cmd->len);

	data += L2CAP_CMD_HDR_SIZE;
	plen -= L2CAP_CMD_HDR_SIZE;

	if ((unlikely(offset > plen)) ||
		(unlikely(len > plen)) ||
		(unlikely(offset+len > plen)))
		goto conless_data_load_err;

	memcpy(to, data+offset, len);
	return 0;

conless_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_le_sig_cmd_data_load_bytes_proto = {
	.func           = lbm_bluetooth_l2cap_le_sig_cmd_data_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_4(lbm_bluetooth_l2cap_data_load_bytes, struct sk_buff *, skb, u32, offset,
		void *, to, u32, len)
{
	int plen;
	u8 *data;
	struct l2cap_hdr *lh;

	data = (void *)skb->data;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = (void *) skb->lbm_bt.data;

	lh = (void *)data;
	plen = __le16_to_cpu(lh->len);

	if ((unlikely(offset > plen)) ||
		(unlikely(len > plen)) ||
		(unlikely(offset+len > plen)))
		goto l2cap_data_load_err;

	memcpy(to, data+L2CAP_HDR_SIZE+offset, len);
	return 0;

l2cap_data_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_data_load_bytes_proto = {
	.func           = lbm_bluetooth_l2cap_data_load_bytes,
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
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	/* lbm bluetooth specific */
	case BPF_FUNC_lbm_bluetooth_get_pkt_type:
		return &lbm_bluetooth_get_pkt_type_proto;
	case BPF_FUNC_lbm_bluetooth_event_get_evt:
		return &lbm_bluetooth_event_get_evt_proto;
	case BPF_FUNC_lbm_bluetooth_event_get_plen:
		return &lbm_bluetooth_event_get_plen_proto;
	case BPF_FUNC_lbm_bluetooth_event_data_load_bytes:
		return &lbm_bluetooth_event_data_load_bytes_proto;
	case BPF_FUNC_lbm_bluetooth_acl_get_handle:
		return &lbm_bluetooth_acl_get_handle_proto;
	case BPF_FUNC_lbm_bluetooth_acl_get_flags:
		return &lbm_bluetooth_acl_get_flags_proto;
	case BPF_FUNC_lbm_bluetooth_acl_get_dlen:
		return &lbm_bluetooth_acl_get_dlen_proto;
	case BPF_FUNC_lbm_bluetooth_acl_data_load_bytes:
		return &lbm_bluetooth_acl_data_load_bytes_proto;
	case BPF_FUNC_lbm_bluetooth_sco_get_handle:
		return &lbm_bluetooth_sco_get_handle_proto;
	case BPF_FUNC_lbm_bluetooth_sco_get_flags:
		return &lbm_bluetooth_sco_get_flags_proto;
	case BPF_FUNC_lbm_bluetooth_sco_get_dlen:
		return &lbm_bluetooth_sco_get_dlen_proto;
	case BPF_FUNC_lbm_bluetooth_sco_data_load_bytes:
		return &lbm_bluetooth_sco_data_load_bytes_proto;
	case BPF_FUNC_lbm_bluetooth_command_get_ogf:
		return &lbm_bluetooth_command_get_ogf_proto;
	case BPF_FUNC_lbm_bluetooth_command_get_ocf:
		return &lbm_bluetooth_command_get_ocf_proto;
	case BPF_FUNC_lbm_bluetooth_command_get_plen:
		return &lbm_bluetooth_command_get_plen_proto;
	case BPF_FUNC_lbm_bluetooth_command_data_load_bytes:
		return &lbm_bluetooth_command_data_load_bytes_proto;
	/* HCI conn helpers */
	case BPF_FUNC_lbm_bluetooth_has_conn:
		return &lbm_bluetooth_has_conn_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_dst:
		return &lbm_bluetooth_get_conn_dst_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_dst_type:
		return &lbm_bluetooth_get_conn_dst_type_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_src:
		return &lbm_bluetooth_get_conn_src_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_src_type:
		return &lbm_bluetooth_get_conn_src_type_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_state:
		return &lbm_bluetooth_get_conn_state_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_mode:
		return &lbm_bluetooth_get_conn_mode_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_type:
		return &lbm_bluetooth_get_conn_type_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_role:
		return &lbm_bluetooth_get_conn_role_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_key_type:
		return &lbm_bluetooth_get_conn_key_type_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_auth_type:
		return &lbm_bluetooth_get_conn_auth_type_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_sec_level:
		return &lbm_bluetooth_get_conn_sec_level_proto;
	case BPF_FUNC_lbm_bluetooth_get_conn_io_capability:
		return &lbm_bluetooth_get_conn_io_capability_proto;
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
	case offsetof(struct __lbm_bluetooth, len):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct sk_buff, len, 4, target_size));
		break;
	case offsetof(struct __lbm_bluetooth, prio):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct sk_buff, priority, 4, target_size));
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


/* For l2cap */
const struct bpf_func_proto *lbm_bluetooth_l2cap_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	/* Common ones */
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	/* lbm bluetooth l2cap specific */
	case BPF_FUNC_lbm_bluetooth_l2cap_get_cid:
		return &lbm_bluetooth_l2cap_get_cid_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_len:
		return &lbm_bluetooth_l2cap_get_len_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_dst:
		return &lbm_bluetooth_l2cap_get_conn_dst_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_dst_type:
		return &lbm_bluetooth_l2cap_get_conn_dst_type_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_src:
		return &lbm_bluetooth_l2cap_get_conn_src_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_src_type:
		return &lbm_bluetooth_l2cap_get_conn_src_type_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_state:
		return &lbm_bluetooth_l2cap_get_conn_state_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_mode:
		return &lbm_bluetooth_l2cap_get_conn_mode_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_type:
		return &lbm_bluetooth_l2cap_get_conn_type_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_role:
		return &lbm_bluetooth_l2cap_get_conn_role_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_key_type:
		return &lbm_bluetooth_l2cap_get_conn_key_type_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_auth_type:
		return &lbm_bluetooth_l2cap_get_conn_auth_type_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_sec_level:
		return &lbm_bluetooth_l2cap_get_conn_sec_level_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conn_io_capability:
		return &lbm_bluetooth_l2cap_get_conn_io_capability_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_num:
		return &lbm_bluetooth_l2cap_get_sig_cmd_num_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_code_idx:
		return &lbm_bluetooth_l2cap_get_sig_cmd_code_idx_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_id_idx:
		return &lbm_bluetooth_l2cap_get_sig_cmd_id_idx_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_len_idx:
		return &lbm_bluetooth_l2cap_get_sig_cmd_len_idx_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_sig_cmd_data_load_bytes_idx:
		return &lbm_bluetooth_l2cap_sig_cmd_data_load_bytes_idx_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_conless_psm:
		return &lbm_bluetooth_l2cap_get_conless_psm_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_conless_data_load_bytes:
		return &lbm_bluetooth_l2cap_conless_data_load_bytes_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_le_sig_cmd_code:
		return &lbm_bluetooth_l2cap_get_le_sig_cmd_code_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_le_sig_cmd_id:
		return &lbm_bluetooth_l2cap_get_le_sig_cmd_id_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_get_le_sig_cmd_len:
		return &lbm_bluetooth_l2cap_get_le_sig_cmd_len_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_le_sig_cmd_data_load_bytes:
		return &lbm_bluetooth_l2cap_le_sig_cmd_data_load_bytes_proto;
	case BPF_FUNC_lbm_bluetooth_l2cap_data_load_bytes:
		return &lbm_bluetooth_l2cap_data_load_bytes_proto;
	default:
		return NULL;
	}
}

bool lbm_bluetooth_l2cap_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
	/* Make sure we are in range */
	if (off < 0 || off >= sizeof(struct __lbm_bluetooth_l2cap))
		return false;
	if (off % size != 0)
		return false;

	/* Block any write for now */
	if (type == BPF_WRITE)
		return false;

	return true;
}

u32 lbm_bluetooth_l2cap_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size)
{
	return 0;
}

int lbm_bluetooth_l2cap_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog)
{
	return 0;
}

int lbm_bluetooth_l2cap_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
	return 0;
}



int lbm_bluetooth_l2cap_tx_reassemble(struct sk_buff *skb)
{
	struct sk_buff *list;
	unsigned char *ptr;

	if (!skb->len)
		return -EINVAL;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_INGRESS)
		return -EINVAL;

	/* Allocate the reassemble buffer */
	skb->lbm_bt.len = skb->len;
	skb->lbm_bt.data = kmalloc(skb->lbm_bt.len, GFP_KERNEL);
	if (!skb->lbm_bt.data) {
		pr_err("LBM: kmalloc failed in %s\n", __func__);
		goto l2cap_tx_reassemble_err;
	}

	/* skb->len reflects data in skb as well as all fragments
	 * skb->data_len reflects only data in fragments
	 */
	list = skb_shinfo(skb)->frag_list;
	if (!list) {
		/* Non fragmented */
		memcpy(skb->lbm_bt.data, skb->data, skb->lbm_bt.len);
	} else {
		/* Fragmented */
		memcpy(skb->lbm_bt.data, skb->data, skb_headlen(skb));
		ptr = skb->lbm_bt.data + skb_headlen(skb);
		do {
			skb = list;
			list = list->next;
			memcpy(ptr, skb->data, skb->len);
			ptr += skb->len;
		} while (list);
	}

	return 0;

l2cap_tx_reassemble_err:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(lbm_bluetooth_l2cap_tx_reassemble);


static void lbm_bluetooth_debug_conn(struct sk_buff *skb)
{
	struct hci_conn *hcon = (void *)skb->lbm_bt.conn;
	u64 baddr_dst = 0;
	u64 baddr_src = 0;

	memcpy(&baddr_dst, &hcon->dst, sizeof(bdaddr_t));
	memcpy(&baddr_src, &hcon->src, sizeof(bdaddr_t));

	pr_info("conn [%p] - dst [%llx], dst_type [%d], src [%llx], src_type [%d], "
		"state [%d], mode [%d], type [%d], role [%d], key_type [%d], "
		"auth_type [%d], sec_level [%d], io_capability [%d]\n",
		hcon,
		baddr_dst,
		hcon->dst_type,
		baddr_src,
		hcon->src_type,
		hcon->state,
		hcon->mode,
		hcon->type,
		hcon->role,
		hcon->key_type,
		hcon->auth_type,
		hcon->sec_level,
		hcon->io_capability);
}


void lbm_bluetooth_hci_debug_skb(struct sk_buff *skb)
{
	struct hci_event_hdr *evt_hdr;
	struct hci_acl_hdr *acl_hdr;
	struct hci_sco_hdr *sco_hdr;
	struct hci_command_hdr *cmd_hdr;
	__u16 handle;
	__u16 opcode;

	pr_info("LBM: bluetooth hci skb [%p] - dir [%d], len [%d], "
		"priority [%d], type [%d]:",
		skb,
		skb->lbm_bt.dir,
		skb->len,
		skb->priority,
		hci_skb_pkt_type(skb));

	switch (hci_skb_pkt_type(skb)) {
	case HCI_EVENT_PKT:
		evt_hdr = (void *) skb->data;
		pr_info("(event), evt [%d], plen [%d]\n",
			evt_hdr->evt,
			evt_hdr->plen);
		break;
	case HCI_ACLDATA_PKT:
		acl_hdr = (void *) skb->data;
		handle = __le16_to_cpu(acl_hdr->handle);
		pr_info("(acl), handle [%d], flags [%d], dlen [%d]\n",
			hci_handle(handle),
			hci_flags(handle),
			__le16_to_cpu(acl_hdr->dlen));
		lbm_bluetooth_debug_conn(skb);
		break;
	case HCI_SCODATA_PKT:
		sco_hdr = (void *) skb->data;
		handle = __le16_to_cpu(sco_hdr->handle);
		pr_info("(sco), handle [%d], flags [%d], dlen [%d]\n",
			hci_handle(handle),
			hci_flags(handle),
			sco_hdr->dlen);
		lbm_bluetooth_debug_conn(skb);
		break;
	case HCI_COMMAND_PKT:
		cmd_hdr = (void *) skb->data;
		opcode = __le16_to_cpu(cmd_hdr->opcode);
		pr_info("(cmd), ogf [%d], ocf [%d], plen [%d]\n",
			hci_opcode_ogf(opcode),
			hci_opcode_ocf(opcode),
			cmd_hdr->plen);
		break;
	case HCI_DIAG_PKT:
		pr_info("(diag)\n");
		break;
	case HCI_VENDOR_PKT:
		pr_info("(vendor_spec)\n");
		break;
	default:
		pr_info("(unknown)\n");
		break;
	}
}
EXPORT_SYMBOL_GPL(lbm_bluetooth_hci_debug_skb);

void lbm_bluetooth_l2cap_debug_skb(struct sk_buff *skb)
{
	u8 *data;
	u16 cid, len, cmd_len;
	struct l2cap_hdr *lh;
	struct l2cap_cmd_hdr *cmd;
	__le16 psm;
	int i = 0;

	data = (void *) skb->data;
	if (skb->lbm_bt.dir == LBM_CALL_DIR_EGRESS)
		data = skb->lbm_bt.data;
	lh = (void *) data;

	cid = __le16_to_cpu(lh->cid);
	len = __le16_to_cpu(lh->len);
	data += L2CAP_HDR_SIZE;

	pr_info("LBM: bluetooth l2cap skb [%p] - dir [%d], len(skb) [%d], "
		"priority [%d], len(pkt) [%d], cid [%d]:",
		skb,
		skb->lbm_bt.dir,
		skb->len,
		skb->priority,
		len, cid);

	switch (cid) {
	case L2CAP_CID_SIGNALING:
		pr_info("(signaling):");
		while (len > L2CAP_CMD_HDR_SIZE) {
			cmd = (void *) data;
			cmd_len = le16_to_cpu(cmd->len);
			pr_info("cmd_idx [%d], code [%d], id [%d], len(cmd) [%d]",
				i, cmd->code, cmd->ident, cmd_len);
			data += L2CAP_CMD_HDR_SIZE;
			len  -= L2CAP_CMD_HDR_SIZE;
			data += cmd_len;
			len  -= cmd_len;
			i++;
		}
		pr_info("cmd_num [%d]\n", i);
		break;
	case L2CAP_CID_CONN_LESS:
		psm = get_unaligned((__le16 *)data);
		pr_info("(connless), psm [%d]\n", __le16_to_cpu(psm));
		break;
	case L2CAP_CID_LE_SIGNALING:
		cmd = (void *) data;
		cmd_len = le16_to_cpu(cmd->len);
		pr_info("(le_signaling), cmd code [%d], id [%d], len(cmd) [%d]\n",
			cmd->code, cmd->ident, cmd_len);
		break;
	default:
		pr_info("(data)\n");
		break;
	}

	lbm_bluetooth_debug_conn(skb);
}
EXPORT_SYMBOL_GPL(lbm_bluetooth_l2cap_debug_skb);

/* Get the conn early at the HCI layer for RX path */
void *lbm_bluetooth_hci_get_conn(struct sk_buff *skb)
{
	struct hci_acl_hdr *acl_hdr;
	struct hci_sco_hdr *sco_hdr;
	struct hci_conn *conn;
	struct hci_dev *hdev;
	__u16 handle;

	/* Should be set by the lbm bt rx hook */
	hdev = (void *) skb->lbm_bt.hdev;

	switch (hci_skb_pkt_type(skb)) {
	case HCI_ACLDATA_PKT:
		acl_hdr = (void *) skb->data;
		handle = __le16_to_cpu(acl_hdr->handle);
		handle = hci_handle(handle);
		hci_dev_lock(hdev);
		conn = hci_conn_hash_lookup_handle(hdev, handle);
		hci_dev_unlock(hdev);
		/* NOTE: conn could be null */
		return conn;
	case HCI_SCODATA_PKT:
		sco_hdr = (void *) skb->data;
		handle = __le16_to_cpu(sco_hdr->handle);
		handle = hci_handle(handle);
		hci_dev_lock(hdev);
		conn = hci_conn_hash_lookup_handle(hdev, handle);
		hci_dev_unlock(hdev);
		/* NOTE: conn could be null */
		return conn;
	default:
		/* Both ACL and SCO should have conn ready
		 * But no guarantee for other types, e.g., events/cmds
		 */
		return NULL;
	}
}
EXPORT_SYMBOL_GPL(lbm_bluetooth_hci_get_conn);
