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
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),	/* save the ctx */
	BPF_CALL_FUNC(BPF_FUNC_lbm_usb_get_devnum),	/* usb.devnum is returned into R0 */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),	/* recover the ctx */

# Can treat as u32 although the actual length are either u8 or le16
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
usb.devpath
usb.manufacturer
usb.product
usb.serial
# Bytes
usb.data
usb.request
