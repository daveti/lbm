# Defending against Blueborne attacks
# Tackling l2cap configure response with pending state
# May 5, 2018
# daveti

# Start eBPF

/* Get the CID */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_l2cap_get_cid),	/* bt.l2cap.cid is returned into R0 */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */
BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),			/* r6 = cid */

/* Check the CID for Signaling */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0x01, 2),		/* if cid == 0x01: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* Get the command num */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_num),	/* bt.l2cap.sig.cmd.num is returned into R0 */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */
BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),			/* r6 = cmd.num */

/* Make sure we have a valid command */
BPF_JMP_IMM(BPF_JGE, BPF_REG_6, 1, 2),			/* if cmd_num >= 1: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* Check the first cmd - ideally we should loop checking all the cmds */

/* Check the cmd code */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_MOV64_IMM(BPF_REG_2, 0),				/* idx = 0 */
BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_code_idx),	/* bt.l2cap.sig.cmd.code is returned into R0 */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */
BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),			/* r6 = cmd.code */

/* Check for configure response */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0x05, 2),		/* if cmd.code == 0x05: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* Check the cmd id */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_MOV64_IMM(BPF_REG_2, 0),				/* idx = 0 */
BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_id_idx),		/* bt.l2cap.sig.cmd.id is returned into R0 */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */
BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),			/* r6 = cmd.id */

/* Check for id */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0x01, 2),		/* if cmd.code == 0x01: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* Load the result */	
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_MOV32_IMM(BPF_REG_2, 5),				/* offset: 0 */
BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),			/* to: stack allocation */
BPF_ALU64_IMM(BPF_SUB, BPF_REG_3, 2),			/* 2  bytes */
BPF_MOV32_IMM(BPF_REG_4, 2),				/* len: 2 */
BPF_MOV32_IMM(BPF_REG_5, 0),				/* idx: 0 */
BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_l2cap_sig_cmd_data_load_bytes_idx),	/* ignore the ret value checking */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */

/* Check for pending (LE) */
BPF_LDX_MEM(BPF_H, BPF_REG_6, BPF_REG_10, -2),		/* save the result into r6 */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0x0400, 2),		/* if result == 0x0400: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* Get the cmd len */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_MOV64_IMM(BPF_REG_2, 0),				/* idx = 0 */
BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_l2cap_get_sig_cmd_len_idx),	/* bt.l2cap.sig.cmd.len is returned into R0 */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */
BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),			/* r6 = cmd.len */

/* Check the len to defend against Blueborne */
BPF_JMP_IMM(BPF_JGE, BPF_REG_6, 70, 2),			/* if cmd.len >= 70 (blueborne): goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* drop the pkt */
BPF_EXIT_INSN(),					/* ret 1 */

# End eBPF
