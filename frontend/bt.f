# Bluetooth hci

# u32
bt.hci.len
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_bluetooth, len)),	/* ret value is saved into R2 */

bt.hci.prio
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_bluetooth, prio)),	/* ret value is saved into R2 */

bt.hci.type
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),	/* save the ctx */
	BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_get_pkt_type),	/* bt.hci.type is returned into R0 */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),	/* recover the ctx */

# Ditto
bt.hci.event.evt
	lbm_bluetooth_event_get_evt
bt.hci.event.plen
	lbm_bluetooth_event_get_plen
bt.hci.acl.handle
	lbm_bluetooth_acl_get_handle
bt.hci.acl.flags
	lbm_bluetooth_acl_get_flags
bt.hci.aci.dlen
	lbm_bluetooth_acl_get_dlen
bt.hci.sco.handle
	lbm_bluetooth_sco_get_handle
bt.hci.sco.flags
	lbm_bluetooth_sco_get_flags
bt.hci.sco.dlen
	lbm_bluetooth_sco_get_dlen
bt.hci.command.ogf
	lbm_bluetooth_command_get_ogf
bt.hci.command.ocf
	lbm_bluetooth_command_get_ocf
bt.hci.command.plen
	lbm_bluetooth_command_get_plen

# Needs stack allocation and manual assembly
bt.hci.event.data
bt.hci.acl.data
bt.hci.sco.data
bt.hci.command.data

# Bluetooth l2cap
# NOTE: all fields under l2cap are using BPF helpers
bt.l2cap.cid
	lbm_bluetooth_l2cap_get_cid
bt.l2cap.len
	lbm_bluetooth_l2cap_get_len
bt.l2cap.conn.dst
	lbm_bluetooth_l2cap_get_conn_dst
bt.l2cap.conn.dst_type
	lbm_bluetooth_l2cap_get_conn_dst_type
bt.l2cap.conn.src
	lbm_bluetooth_l2cap_get_conn_src
bt.l2cap.conn.src_type
	lbm_bluetooth_l2cap_get_conn_src_type
bt.l2cap.conn.state
	lbm_bluetooth_l2cap_get_conn_state
bt.l2cap.conn.mode
	lbm_bluetooth_l2cap_get_conn_mode
bt.l2cap.conn.type
	lbm_bluetooth_l2cap_get_conn_type
bt.l2cap.conn.role
	lbm_bluetooth_l2cap_get_conn_role
bt.l2cap.conn.key_type
	lbm_bluetooth_l2cap_get_conn_key_type
bt.l2cap.conn.auth_type
	lbm_bluetooth_l2cap_get_conn_auth_type
bt.l2cap.conn.sec_level
	lbm_bluetooth_l2cap_get_conn_sec_level
bt.l2cap.conn.io_capability
	lbm_bluetooth_l2cap_get_conn_io_capability
bt.l2cap.sig.cmd.num
	lbm_bluetooth_l2cap_get_sig_cmd_num
bt.l2cap.sig.cmd.code[i]	/* indexed */
	lbm_bluetooth_l2cap_get_sig_cmd_code_idx
bt.l2cap.sig.cmd.id[i]
	lbm_bluetooth_l2cap_get_sig_cmd_id_idx
bt.l2cap.sig.cmd.len[i]
	lbm_bluetooth_l2cap_get_sig_cmd_len_idx
bt.l2cap.conless.psm
	lbm_bluetooth_l2cap_get_conless_psm
bt.l2cap.le.sig.cmd.code
	lbm_bluetooth_l2cap_get_le_sig_cmd_code
bt.l2cap.le.sig.cmd.id
	lbm_bluetooth_l2cap_get_le_sig_cmd_id
bt.l2cap.le.sig.cmd.len
	lbm_bluetooth_l2cap_get_le_sig_cmd_len

# Load-bytes helpers
bt.l2cap.sig.cmd.data
bt.l2cap.conless.data
bt.l2cap.le.sig.cmd.data
bt.l2cap.data
