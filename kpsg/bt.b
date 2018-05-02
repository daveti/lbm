# A bluetooth software stack guard for the HCI layer on RX path
# NOTE:
#  - Only ACL/SCO/EVENT pkts are permitted
#  - Each pkt type is checked against the minimum length
# References:
# 1. Bluetooth Core v5.0 Chap 5
# 2. https://lxr.missinglinkelectronics.com/linux+v4.13/net/bluetooth/hci_core.c#L4077
# May 2, 2018
# daveti

# Start eBPF

/* Get the pkt type */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_CALL_FUNC(BPF_FUNC_lbm_bluetooth_get_pkt_type),	/* bt.hci.type is returned into R0 */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */
BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),			/* r6 = type */

/* Get the pkt len */
BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offset(struct __lbm_bluetooth, len)),	/* r7 = len */

/* Check the pkt type for minimum pkt len */
BPF_JMP_IMM(BPF_JNEQ, BPF_REG_6, 2, 5),			/* if type != acl: goto PC+5 */
BPF_JMP_IMM(BPF_JLT, BPF_REG_7, 4, 2),			/* else: if len < 4: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* 	else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* drop the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

BPF_JMP_IMM(BPF_JNEQ, BPF_REG_6, 3, 5),			/* if type != sco: goto PC+5 */
BPF_JMP_IMM(BPF_JLT, BPF_REG_7, 3, 2),			/* else: if len < 3: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* 	else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* drop the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

BPF_JMP_IMM(BPF_JNEQ, BPF_REG_6, 2, 3),			/* if type != evt: goto PC+3 */
BPF_JMP_IMM(BPF_JLT, BPF_REG_7, 3, 2),			/* else: if len < 2: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* 	else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* drop the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

# End eBPF
