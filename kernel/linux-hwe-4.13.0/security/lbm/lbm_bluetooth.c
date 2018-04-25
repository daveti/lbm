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
#include <net/bluetooth/l2cap.h>

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


BPF_CALL_1(lbm_bluetooth_l2cap_get_cid, struct sk_buff *, skb)
{
	struct l2cap_hdr *lh = (void *) skb->data;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
	__u64 baddr = 0;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
	__u64 baddr = 0;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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
	struct l2cap_conn *conn = (struct l2cap_conn *)skb->lbm_bt.conn;
	struct hci_conn *hcon = conn->hcon;
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


BPF_CALL_1(lbm_bluetooth_l2cap_get_sig_cmd_code_idx, struct sk_buff *, skb,
		u32, idx)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;
	u8 code = 0;	/* invalid code */

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		if (idx == cnt) {
			code = cmd->code;
			break;
		}
		data += L2CAP_CMD_HDR_SIZE;
		len  -= L2CAP_CMD_HDR_SIZE;
		cmd_len = le16_to_cpu(cmd->len);
		data += cmd_len;
		len  -= cmd_len;
		cnt++;
	}

	return code;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_sig_cmd_code_idx_proto = {
	.func           = lbm_bluetooth_l2cap_get_sig_cmd_code_idx,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_SIZE,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_sig_cmd_id_idx, struct sk_buff *, skb,
		u32, idx)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;
	u8 id = 0;	/* invalid id */

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		if (idx == cnt) {
			id = cmd->ident;
			break;
		}
		data += L2CAP_CMD_HDR_SIZE;
		len  -= L2CAP_CMD_HDR_SIZE;
		cmd_len = le16_to_cpu(cmd->len);
		data += cmd_len;
		len  -= cmd_len;
		cnt++;
	}

	return id;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_sig_cmd_id_idx_proto = {
	.func           = lbm_bluetooth_l2cap_get_sig_cmd_id_idx,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_SIZE,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_sig_cmd_len_idx, struct sk_buff *, skb,
		u32, idx)
{
	u8 *data = skb->data + L2CAP_HDR_SIZE;
	int len = skb->len - L2CAP_HDR_SIZE;
	int cnt = 0;
	u16 cmd_len;
	struct l2cap_cmd_hdr *cmd;

	while (len >= L2CAP_CMD_HDR_SIZE) {
		cmd = (struct l2cap_cmd_hdr *)data;
		data += L2CAP_CMD_HDR_SIZE;
		len  -= L2CAP_CMD_HDR_SIZE;
		cmd_len = le16_to_cpu(cmd->len);
		if (idx == cnt)
			return cmd_len;
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
	.arg2_type	= ARG_CONST_SIZE,
};


BPF_CALL_1(lbm_bluetooth_l2cap_get_conless_psm, struct sk_buff *, skb)
{
	__le16 psm = get_unaligned((__le16 *)(skb->data+L2CAP_HDR_SIZE));
	return psm;
}

static const struct bpf_func_proto lbm_bluetooth_l2cap_get_conless_psm_proto = {
	.func           = lbm_bluetooth_l2cap_get_conless_psm,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
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
	case offsetof(struct __lbm_bluetooth, type):
		*insn++ = BPF_LDX_MEM(BPF_B, si->dst_reg, si->src_reg,
				bpf_target_off(struct sk_buff, cb, 1, target_size));
		break;
	case offsetof(struct __lbm_usb, len):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct sk_buff, len, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, prio):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct sk_buff, prioirty, 4, target_size));
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
const struct bpf_func_proto *lbm_bluetooth_func_l2cap_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	/* Common ones */
	/* lbm bluetooth l2cap specific */
	default:
		return NULL;
	}
}

bool lbm_bluetooth_l2cap_is_valid_access(int off, int size,
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

u32 lbm_bluetooth_l2cap_convert_ctx_access(enum bpf_access_type type,
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

	/* Allocate the reassemble buffer */
	skb->lbm_bt.len = skb->len;
	skb->lbm_bt.data = kmalloc(skb->lbm_bt.len, GFP_KERNEL);
	if (!skb->lbm_bt.data) {
		pr_err("LBM: kmalloc failed in %s\n", __func__);
		goto l2cap_tx_reassemble;
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

