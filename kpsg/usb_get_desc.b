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
# USB stack protection for Get_Descriptor resposne
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
BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -4),			/* 4 bytes */
BPF_MOV32_IMM(BPF_REG_4, 4),				/* len: 4 */
BPF_CALL_FUNC(BPF_FUNC_lbm_usb_setup_packet_load_bytes),/* ignore the ret value checking */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */

/* check the bRequestType from the setup pkt */
BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_10, -4),		/* save the bRequestType into r6 */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0x80, 2),		/* if bRequestType == 0x80: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* check the bRequest from the setup pkt */
BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_10, -3),		/* save the bRequest into r6 */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0x06, 2),		/* if bRequest == 0x06 (Get_Descriptor): goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* check the desc_type from wValue from the setup pkt */
BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_10, -1),		/* save the desc_type into r6 */
BPF_JMP_IMM(BPF_JGE, BPF_REG_6, 0x1, 2),		/* if desc_type >= 0x1: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* else: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */
BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 0x3, 1),		/* if desc_type > 0x3: goto PC+1; */
BPF_JMP_A(2),						/* else: move on (NOTE: this awkwardness is due to the missing of BPF_JLT on kernel 4.13 */
BPF_MOV64_IMM(BPF_REG_0, 0),                            /* PC+1: allow the pkt */
BPF_EXIT_INSN(),					/* ret 0 */

/* make sure we have a valid response payload */
BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __lbm_usb, actual_length)),
BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 0, 2),			/* if actual_length > 2: goto PC+2; */
BPF_MOV64_IMM(BPF_REG_0, 1),                            /* else: drop the pkt (malformed) */
BPF_EXIT_INSN(),                                        /* ret 1 */

/* get the bLength and bDescriptorType from the response payload */
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),			/* save the ctx */
BPF_MOV32_IMM(BPF_REG_2, 0),				/* offset: 0 */
BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),			/* to: stack allocation */
BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -2),			/* 2 byte */
BPF_MOV32_IMM(BPF_REG_4, 2),				/* len: 2 */
BPF_CALL_FUNC(BPF_FUNC_lbm_usb_transfer_buffer_load_bytes),/* ignore the ret value checking */
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),			/* recover the ctx */
BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_10, -1),		/* save the bDescriptorType into r8 */
BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_10, -2),		/* save the bLength into r9 */

/* The desc_type from setup pkt should match bDescriptorType from the payload */
BPF_JMP_REG(BPF_JEQ, BPF_REG_6, BPF_REG_8, 2),		/* if desc_type == bDescriptorType: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 1),                            /* else: drop the pkt */
BPF_EXIT_INSN(),                                        /* ret 1 */

/* Check for the minimum length based on the desc type */
BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 1, 8),			/* if desc_type != 1: goto PC+8 */
BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, 18, 2),			/* else: if actual_length == 18: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* else: else: drop the pkt, ret 1 */
BPF_EXIT_INSN(),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 18, 2),			/* else: if bLength == 18: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* else: else: drop the pkt, ret 1 */
BPF_EXIT_INSN(),
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: accept the pkt, ret 0 */
BPF_EXIT_INSN(),

BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 2, 8),			/* if desc_type != 2: goto PC+8 */
BPF_JMP_IMM(BPF_JGE, BPF_REG_7, 9, 2),			/* else: if actual_length >= 9: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* else: else: drop the pkt, ret 1 */
BPF_EXIT_INSN(),
BPF_JMP_IMM(BPF_JGE, BPF_REG_9, 9, 2),			/* else: if bLength >= 9: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* else: else: drop the pkt, ret 1 */
BPF_EXIT_INSN(),
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: accept the pkt, ret 0 */
BPF_EXIT_INSN(),

BPF_JMP_IMM(BPF_JNE, BPF_REG_6, 3, 8),			/* if desc_type != 3: goto PC+8 */
BPF_JMP_IMM(BPF_JGE, BPF_REG_7, 4, 2),			/* else: if actual_length >= 4: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* else: else: drop the pkt, ret 1 */
BPF_EXIT_INSN(),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 4, 2),			/* else: if bLength >= 4: goto PC+2 */
BPF_MOV64_IMM(BPF_REG_0, 1),				/* else: else: drop the pkt, ret 1 */
BPF_EXIT_INSN(),
BPF_MOV64_IMM(BPF_REG_0, 0),				/* else: accept the pkt, ret 0 */
BPF_EXIT_INSN(),

BPF_MOV64_IMM(BPF_REG_0, 0),
BPF_EXIT_INSN(),
# End eBPF
