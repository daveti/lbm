# Replicate USBFirewall using (e)BPF
# Based on USBFirewall Haskell translation for the USB spec on enumeration phase
# Focusing on the RX path - protecting the USB host stack (USB responses)
# To protect the USB device stack, TX path protection is needed (USB requests)
# NOTE: the best we could do now is to check the constant values
# and we only care about control transfer during the enumeration phase
# - USB responses without payload is ignored
# - USB Get_Descriptor for configuration will returen all descriptors (config/interface/endpoint)
# - Essentially, to cover the enumeration phase, all we need is to check Get_Descriptor
#	for device, config, and string
# Apr 30, 2018
# daveti
#
# USB stack protection for Get_Status
# Aug 28, 2018
# daveti

# Start eBPF
BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1, offsetof(struct __lbm_usb, setup_packet)),
BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 0, 2),			/* if setup_packet != null: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* get the first 4 bytes from the setup pkt */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_MOV32_IMM(BPF_REG_2, 0),				/* offset: 0 */
BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),			/* to: stack allocation */
BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -4),			/* 4  bytes */
BPF_MOV32_IMM(BPF_REG_4, 4),				/* len: 4 */
BPF_CALL_FUNC(BPF_FUNC_lbm_usb_setup_packet_load_bytes),/* ignore the ret value checking */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */

/* Ignore bRequestType */

/* check the bRequest from the setup pkt */
BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_10, -3),		/* save the bRequest into r6 */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 2),			/* if bRequest == 0x0 (Get_Status): goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* check the wValue from the setup pkt to double confirm */
BPF_LDX_MEM(BPF_H, BPF_REG_6, BPF_REG_10, -2),		/* save the wValue into r6 */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 2),			/* if wValue == 0: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* make sure we have a valid response payload */
BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __lbm_usb, actual_length)),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, 0, 2),			/* if actual_length == 2: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 1),                            /* else: drop the pkt (malformed) */
BPF_EXIT_INSN(),                                        /* ret 1 */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* accept the pkt */
BPF_EXIT_INSN(),                                        /* ret 0 */

# End eBPF
