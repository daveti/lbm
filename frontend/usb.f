# Some instructions about eBPF:
# 1. R1 points to the contex of the eBPF program,
#	for USB, this is struct __lbm_usb in the user space, and struct urb in the kernel space
#	lbm kernel will take care of the mapping between __lbm_usb and urb during runtime 
# 2. The register mapping between eBPF and x86_64:
#	R0 - rax
#	R1 - rdi
#	R2 - rsi
#	R3 - rdx
#	R4 - rcx
#	R5 - r8
#	R6 - rbx
#	R7 - r13
#	R8 - r14
#	R9 - r15
#	R10 - rbp
# 3. Based on above, we have:
#	R0: return value from eBPF helpers (in-kernel functions), and exit value of the eBPF program
#	R1-R5: arguments passed for eBPF helpers
#	R6-R9: callee saved registers that eBPF helpers will perserve
#	R10: read-only frame pointer to access stack

# Can treat as u32
usb.pipe
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, pipe)),	/* usb.pipe is saved into R2 */

usb.stream_id
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, stream_id)),

usb.status
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, status)),

usb.transfer_flags
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, transfer_flags)),

usb.transfer_buffer_length
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, transfer_buffer_length)),

usb.actual_length
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, actual_length)),

usb.setup_packet
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, setup_packet)),	/* this is essentially a pointer value for null checking */

usb.start_frame
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, start_frame)),

usb.number_of_packets
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, number_of_packets)),

usb.interval
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, interval)),

usb.error_count
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_user, error_count)),

usb.devnum
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),	/* save the ctx */
	BPF_CALL_FUNC(BPF_FUNC_lbm_usb_get_devnum),	/* usb.devnum is returned into R0 */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),	/* recover the ctx */

# Can treat as u32 although the actual length are either u8 or le16
# Ditto
usb.bcdUSB
usb.bDeviceClass
usb.bDeviceSubClass
usb.bDeviceProtocol
usb.bMaxPacketSize0
usb.idVendor
usb.idProduct
usb.bcdDevice
usb.iManufacturer
usb.iProduct
usb.iSerialNumber
usb.bNumConfigurations

# Strings
# Need to get the length before we could futher get each byte within the string
usb.devpath
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),	/* save the ctx */
	BPF_CALL_FUNC(BPF_FUNC_lbm_usb_get_devpath_len),	/* devpath length is return into R0 */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),	/* recover the ctx */
	BPF_MOV32_IMM(BPF_REG_7, length_of_devpath_from_user_input),	/* load the length of devpath from user input */
	BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_7, 2),	/* if devpath_kernel_len == devpath_user_len: goto PC+2 */
	BPF_MOV64_IMM(BPF_REG_0, 0),	/* here devpath_kernel_len != devpath_user_len: return 0 - allow the pkt */
	BPF_EXIT_INSN(),

	/* Here we need to compare 2 strings with the same length */
	/* Since loop is not allowed in eBPF, we need to unrolling here */
	/* Given that the length of the target string is known during the compilation, say L */
	/* L = N*8 + M, where N = L/8, M = L mod 8 */
	/* When N > 0, we need to emit N blocks of eBPF instuctions like below: */
	/* NOTE: this is also the start of the jump above (PC+2) */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),	/* save the ctx */
	BPF_MOV64_IMM(BPF_REG_2, n*8),	/* offset, n = 0, 1, 2, ..., N-1 */
	BPF_CALL_FUNC(BPF_FUNC_lbm_usb_devpath_load_8_bytes), /* the nth 8-byte is returned into R0 */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),	/* recover the ctx */
	BPF_MOV64_IMM(BPF_REG_7, nth_8_byte_from_user_input),	/* load the nth 8-byte from user input */
	BPF_JMP_REG(BPF_JEQ, BPF_REG_0, BPF_REG_7, 2),	/* if nth_8_byte_kernel == nth_8_byte_user: goto PC+2 */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),	/* return 0 if nth_8_byte_kernel != nth_8_byte_user: allow the pkt */
	/* Repeat above until n == N-1 */
	/* The last block is to deal with M - which is basically the same */
	/* except that we do not have 8 bytes to fill up the register */

	/* Another version here is the stack copy version */
	/* However, since memory (stack) write is disallowed for now */
	/* the original lbm_usb_devpath_load_bytes would not work,
	/* although I could make it work... */
usb.manufacturer
usb.product
usb.serial

# Bytes
# These fields requires manual assembly generation
usb.data
usb.request
