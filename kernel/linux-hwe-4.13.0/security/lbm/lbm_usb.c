/*
 * BPF verifier ops and helper calles for lbm usb
 * The BPF ctx is struct urb!
 * Apr 3, 2018
 * daveti
 * root@davejingtian.org
 */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/usb.h>
#include <uapi/linux/lbm_bpf.h>

/* BPF helpers */
BPF_CALL_1(lbm_usb_get_devnum, struct urb *, urb)
{
	return urb->dev->devnum;
}

static const struct bpf_func_proto lbm_usb_get_devnum_proto = {
	.func           = lbm_usb_get_devnum,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_devpath_len, struct urb *, urb)
{
	return strlen(urb->dev->devpath);
}

static const struct bpf_func_proto lbm_usb_get_devpath_len_proto = {
	.func           = lbm_usb_get_devpath_len,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_product_len, struct urb *, urb)
{
	return strlen(urb->dev->product);
}

static const struct bpf_func_proto lbm_usb_get_product_len_proto = {
	.func           = lbm_usb_get_product_len,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_manufacturer_len, struct urb *, urb)
{
	return strlen(urb->dev->manufacturer);
}

static const struct bpf_func_proto lbm_usb_get_manufacturer_len_proto = {
	.func           = lbm_usb_get_manufacturer_len,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_serial_len, struct urb *, urb)
{
	return strlen(urb->dev->serial);
}

static const struct bpf_func_proto lbm_usb_get_serial_len_proto = {
	.func           = lbm_usb_get_serial_len,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_usb_devpath_load_bytes, struct urb *, urb, u32, offset,
		void *, to, u32, len)
{
	if ((unlikely(offset > strlen(urb->dev->devpath))) ||
		(unlikely(len > strlen(urb->dev->devpath))) ||
		(unlikely(offset+len > strlen(urb->dev->devpath))))
		goto devpath_load_err;

	memcpy(to, (void *)urb->dev->devpath+offset, len);
	return 0;

devpath_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_usb_devpath_load_bytes_proto = {
	.func           = lbm_usb_devpath_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_2(lbm_usb_devpath_load_bytes_reg, struct urb *, urb, u32, offset)
{
	u64 reg = 0;
	int len = sizeof(reg);

	if (unlikely(offset > strlen(urb->dev->devpath)))
		return reg;

	if (offset + len > strlen(urb->dev->devpath))
		len = strlen(urb->dev->devpath) - offset;

	memcpy(&reg, (void *)urb->dev->devpath+offset, len);
	return reg;
}

static const struct bpf_func_proto lbm_usb_devpath_load_bytes_reg_proto = {
	.func           = lbm_usb_devpath_load_bytes_reg,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
};


BPF_CALL_4(lbm_usb_product_load_bytes, struct urb *, urb, u32, offset,
		void *, to, u32, len)
{
	if ((unlikely(offset > strlen(urb->dev->product))) ||
		(unlikely(len > strlen(urb->dev->product))) ||
		(unlikely(offset+len > strlen(urb->dev->product))))
		goto product_load_err;

	memcpy(to, (void *)urb->dev->product+offset, len);
	return 0;

product_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_usb_product_load_bytes_proto = {
	.func           = lbm_usb_product_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_2(lbm_usb_product_load_bytes_reg, struct urb *, urb, u32, offset)
{
	u64 reg = 0;
	int len = sizeof(reg);

	if (unlikely(offset > strlen(urb->dev->product)))
		return reg;

	if (offset + len > strlen(urb->dev->product))
		len = strlen(urb->dev->product) - offset;

	memcpy(&reg, (void *)urb->dev->product+offset, len);
	return reg;
}

static const struct bpf_func_proto lbm_usb_product_load_bytes_reg_proto = {
	.func           = lbm_usb_product_load_bytes_reg,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
};


BPF_CALL_4(lbm_usb_manufacturer_load_bytes, struct urb *, urb, u32, offset,
		void *, to, u32, len)
{
	if ((unlikely(offset > strlen(urb->dev->manufacturer))) ||
		(unlikely(len > strlen(urb->dev->manufacturer))) ||
		(unlikely(offset+len > strlen(urb->dev->manufacturer))))
		goto manufacturer_load_err;

	memcpy(to, (void *)urb->dev->manufacturer+offset, len);
	return 0;

manufacturer_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_usb_manufacturer_load_bytes_proto = {
	.func           = lbm_usb_manufacturer_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_2(lbm_usb_manufacturer_load_bytes_reg, struct urb *, urb, u32, offset)
{
	u64 reg = 0;
	int len = sizeof(reg);

	if (unlikely(offset > strlen(urb->dev->manufacturer)))
		return reg;

	if (offset + len > strlen(urb->dev->manufacturer))
		len = strlen(urb->dev->manufacturer) - offset;

	memcpy(&reg, (void *)urb->dev->manufacturer+offset, len);
	return reg;
}

static const struct bpf_func_proto lbm_usb_manufacturer_load_bytes_reg_proto = {
	.func           = lbm_usb_manufacturer_load_bytes_reg,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
};


BPF_CALL_4(lbm_usb_serial_load_bytes, struct urb *, urb, u32, offset,
		void *, to, u32, len)
{
	if ((unlikely(offset > strlen(urb->dev->serial))) ||
		(unlikely(len > strlen(urb->dev->serial))) ||
		(unlikely(offset+len > strlen(urb->dev->serial))))
		goto serial_load_err;

	memcpy(to, (void *)urb->dev->serial+offset, len);
	return 0;

serial_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_usb_serial_load_bytes_proto = {
	.func           = lbm_usb_serial_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_2(lbm_usb_serial_load_bytes_reg, struct urb *, urb, u32, offset)
{
	u64 reg = 0;
	int len = sizeof(reg);

	if (unlikely(offset > strlen(urb->dev->serial)))
		return reg;

	if (offset + len > strlen(urb->dev->serial))
		len = strlen(urb->dev->serial) - offset;

	memcpy(&reg, (void *)urb->dev->serial+offset, len);
	return reg;
}

static const struct bpf_func_proto lbm_usb_serial_load_bytes_reg_proto = {
	.func           = lbm_usb_serial_load_bytes_reg,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
};


BPF_CALL_4(lbm_usb_setup_packet_load_bytes, struct urb *, urb, u32, offset,
		void *, to, u32, len)
{
	if ((unlikely(offset > sizeof(struct usb_ctrlrequest))) ||
		(unlikely(len > sizeof(struct usb_ctrlrequest))) ||
		(unlikely(offset+len > sizeof(struct usb_ctrlrequest))))
		goto setup_pkt_load_err;

	memcpy(to, (void *)urb->setup_packet+offset, len);
	return 0;

setup_pkt_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_usb_setup_packet_load_bytes_proto = {
	.func           = lbm_usb_setup_packet_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};


BPF_CALL_4(lbm_usb_transfer_buffer_load_bytes, struct urb *, urb, u32, offset,
		void *, to, u32, len)
{
	if ((unlikely(offset > urb->actual_length)) ||
		(unlikely(len > urb->actual_length)) ||
		(unlikely(offset+len > urb->actual_length)))
		goto trans_buf_load_err;

	memcpy(to, (void *)urb->transfer_buffer+offset, len);
	return 0;

trans_buf_load_err:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto lbm_usb_transfer_buffer_load_bytes_proto = {
	.func           = lbm_usb_transfer_buffer_load_bytes,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg4_type      = ARG_CONST_SIZE,
};

/* More helpers for struct usb_device_descriptor */
BPF_CALL_1(lbm_usb_get_bcdUSB, struct urb *, urb)
{
	return __le16_to_cpu(urb->dev->descriptor.bcdUSB);
}

static const struct bpf_func_proto lbm_usb_get_bcdUSB_proto = {
	.func           = lbm_usb_get_bcdUSB,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_bDeviceClass, struct urb *, urb)
{
	return urb->dev->descriptor.bDeviceClass;
}

static const struct bpf_func_proto lbm_usb_get_bDeviceClass_proto = {
	.func           = lbm_usb_get_bDeviceClass,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_bDeviceSubClass, struct urb *, urb)
{
	return urb->dev->descriptor.bDeviceSubClass;
}

static const struct bpf_func_proto lbm_usb_get_bDeviceSubClass_proto = {
	.func           = lbm_usb_get_bDeviceSubClass,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_bDeviceProtocol, struct urb *, urb)
{
	return urb->dev->descriptor.bDeviceProtocol;
}

static const struct bpf_func_proto lbm_usb_get_bDeviceProtocol_proto = {
	.func           = lbm_usb_get_bDeviceProtocol,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_bMaxPacketSize0, struct urb *, urb)
{
	return urb->dev->descriptor.bMaxPacketSize0;
}

static const struct bpf_func_proto lbm_usb_get_bMaxPacketSize0_proto = {
	.func           = lbm_usb_get_bMaxPacketSize0,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_idVendor, struct urb *, urb)
{
	return __le16_to_cpu(urb->dev->descriptor.idVendor);
}

static const struct bpf_func_proto lbm_usb_get_idVendor_proto = {
	.func           = lbm_usb_get_idVendor,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_idProduct, struct urb *, urb)
{
	return __le16_to_cpu(urb->dev->descriptor.idProduct);
}

static const struct bpf_func_proto lbm_usb_get_idProduct_proto = {
	.func           = lbm_usb_get_idProduct,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_bcdDevice, struct urb *, urb)
{
	return __le16_to_cpu(urb->dev->descriptor.bcdDevice);
}

static const struct bpf_func_proto lbm_usb_get_bcdDevice_proto = {
	.func           = lbm_usb_get_bcdDevice,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_iManufacturer, struct urb *, urb)
{
	return urb->dev->descriptor.iManufacturer;
}

static const struct bpf_func_proto lbm_usb_get_iManufacturer_proto = {
	.func           = lbm_usb_get_iManufacturer,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_iProduct, struct urb *, urb)
{
	return urb->dev->descriptor.iProduct;
}

static const struct bpf_func_proto lbm_usb_get_iProduct_proto = {
	.func           = lbm_usb_get_iProduct,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_iSerialNumber, struct urb *, urb)
{
	return urb->dev->descriptor.iSerialNumber;
}

static const struct bpf_func_proto lbm_usb_get_iSerialNumber_proto = {
	.func           = lbm_usb_get_iSerialNumber,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_bNumConfigurations, struct urb *, urb)
{
	return urb->dev->descriptor.bNumConfigurations;
}

static const struct bpf_func_proto lbm_usb_get_bNumConfigurations_proto = {
	.func           = lbm_usb_get_bNumConfigurations,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};



/* BPF verifier ops */
const struct bpf_func_proto *lbm_usb_func_proto(enum bpf_func_id func_id)
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
	/* daveti: internally used by net/filter
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_raw_smp_processor_id_proto;
	*/
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	/* lbm usb specific */
	case BPF_FUNC_lbm_usb_get_devnum:
		return &lbm_usb_get_devnum_proto;
	case BPF_FUNC_lbm_usb_get_devpath_len:
		return &lbm_usb_get_devpath_len_proto;
	case BPF_FUNC_lbm_usb_get_product_len:
		return &lbm_usb_get_product_len_proto;
	case BPF_FUNC_lbm_usb_get_manufacturer_len:
		return &lbm_usb_get_manufacturer_len_proto;
	case BPF_FUNC_lbm_usb_get_serial_len:
		return &lbm_usb_get_serial_len_proto;
	case BPF_FUNC_lbm_usb_devpath_load_bytes:
		return &lbm_usb_devpath_load_bytes_proto;
	case BPF_FUNC_lbm_usb_product_load_bytes:
		return &lbm_usb_product_load_bytes_proto;
	case BPF_FUNC_lbm_usb_manufacturer_load_bytes:
		return &lbm_usb_manufacturer_load_bytes_proto;
	case BPF_FUNC_lbm_usb_serial_load_bytes:
		return &lbm_usb_serial_load_bytes_proto;
	case BPF_FUNC_lbm_usb_devpath_load_bytes_reg:
		return &lbm_usb_devpath_load_bytes_reg_proto;
	case BPF_FUNC_lbm_usb_product_load_bytes_reg:
		return &lbm_usb_product_load_bytes_reg_proto;
	case BPF_FUNC_lbm_usb_manufacturer_load_bytes_reg:
		return &lbm_usb_manufacturer_load_bytes_reg_proto;
	case BPF_FUNC_lbm_usb_serial_load_bytes_reg:
		return &lbm_usb_serial_load_bytes_reg_proto;
	case BPF_FUNC_lbm_usb_setup_packet_load_bytes:
		return &lbm_usb_setup_packet_load_bytes_proto;
	case BPF_FUNC_lbm_usb_transfer_buffer_load_bytes:
		return &lbm_usb_transfer_buffer_load_bytes_proto;
	/* new helpers to access struct usb_device_descriptor */
	case BPF_FUNC_lbm_usb_get_bcdUSB:
		return &lbm_usb_get_bcdUSB_proto;
	case BPF_FUNC_lbm_usb_get_bDeviceClass:
		return &lbm_usb_get_bDeviceClass_proto;
	case BPF_FUNC_lbm_usb_get_bDeviceSubClass:
		return &lbm_usb_get_bDeviceSubClass_proto;
	case BPF_FUNC_lbm_usb_get_bDeviceProtocol:
		return &lbm_usb_get_bDeviceProtocol_proto;
	case BPF_FUNC_lbm_usb_get_bMaxPacketSize0:
		return &lbm_usb_get_bMaxPacketSize0_proto;
	case BPF_FUNC_lbm_usb_get_idVendor:
		return &lbm_usb_get_idVendor_proto;
	case BPF_FUNC_lbm_usb_get_idProduct:
		return &lbm_usb_get_idProduct_proto;
	case BPF_FUNC_lbm_usb_get_bcdDevice:
		return &lbm_usb_get_bcdDevice_proto;
	case BPF_FUNC_lbm_usb_get_iManufacturer:
		return &lbm_usb_get_iManufacturer_proto;
	case BPF_FUNC_lbm_usb_get_iProduct:
		return &lbm_usb_get_iProduct_proto;
	case BPF_FUNC_lbm_usb_get_iSerialNumber:
		return &lbm_usb_get_iSerialNumber_proto;
	case BPF_FUNC_lbm_usb_get_bNumConfigurations:
		return &lbm_usb_get_bNumConfigurations_proto;
	default:
		return NULL;
	}
}

bool lbm_usb_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
	/* Make sure we are in range */
	if (off < 0 || off >= sizeof(struct __lbm_usb))
		return false;
	if (off % size != 0)
		return false;

	/* Block any write for now */
	if (type == BPF_WRITE)
		return false;

	return true;
}

u32 lbm_usb_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct __lbm_usb, pipe):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, pipe, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, stream_id):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, stream_id, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, status):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, status, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, transfer_flags):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, transfer_flags, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, transfer_buffer_length):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, transfer_buffer_length, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, actual_length):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, actual_length, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, setup_packet):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct urb, setup_packet),
				si->dst_reg, si->src_reg,
				offsetof(struct urb, setup_packet));
		break;
	case offsetof(struct __lbm_usb, start_frame):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, start_frame, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, number_of_packets):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, number_of_packets, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, interval):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, interval, 4, target_size));
		break;
	case offsetof(struct __lbm_usb, error_count):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				bpf_target_off(struct urb, error_count, 4, target_size));
		break;
	}

	return insn - insn_buf;
}

int lbm_usb_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog)
{
	return 0;
}

int lbm_usb_test_run_urb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
	return 0;
}

