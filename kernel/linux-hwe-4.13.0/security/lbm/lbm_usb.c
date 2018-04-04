/*
 * BPF verifier ops and helper calles for lbm-usb
 * Apr 3, 2018
 * root@davejingtian.org
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/usb.h>

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


BPF_CALL_1(lbm_usb_get_devpath, struct urb *, urb)
{
	return urb->dev->devpath;
}

static const struct bpf_func_proto lbm_usb_get_devpath_proto = {
	.func           = lbm_usb_get_devpath,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_product, struct urb *, urb)
{
	return urb->dev->product;
}

static const struct bpf_func_proto lbm_usb_get_product_proto = {
	.func           = lbm_usb_get_product,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_manufacturer, struct urb *, urb)
{
	return urb->dev->manufacturer;
}

static const struct bpf_func_proto lbm_usb_get_manufacturer_proto = {
	.func           = lbm_usb_get_manufacturer,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_serial, struct urb *, urb)
{
	return urb->dev->serial;
}

static const struct bpf_func_proto lbm_usb_get_serial_proto = {
	.func           = lbm_usb_get_serial,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_pipe, struct urb *, urb)
{
	return urb->pipe;
}

static const struct bpf_func_proto lbm_usb_get_pipe_proto = {
	.func           = lbm_usb_get_pipe,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_status, struct urb *, urb)
{
	return urb->status;
}

static const struct bpf_func_proto lbm_usb_get_status_proto = {
	.func           = lbm_usb_get_status,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_transfer_buffer_length, struct urb *, urb)
{
	return urb->transfer_buffer_length;
}

static const struct bpf_func_proto lbm_usb_get_transfer_buffer_length_proto = {
	.func           = lbm_usb_get_transfer_buffer_length,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_actual_length, struct urb *, urb)
{
	return urb->actual_length;
}

static const struct bpf_func_proto lbm_usb_get_actual_length_proto = {
	.func           = lbm_usb_get_actual_length,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_1(lbm_usb_get_setup_packet, struct urb *, urb)
{
	return urb->setup_packet;
}

static const struct bpf_func_proto lbm_usb_get_setup_packet_proto = {
	.func           = lbm_usb_get_setup_packet,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};


BPF_CALL_4(lbm_usb_setup_packet_load_bytes, struct urb *, urb, u32, offset,
		void *, to, u32, len)
{
	void *ptr;

	if ((unlikely(offset > sizeof(struct usb_ctrlrequest))) ||
		(unlikely(len > sizeof(struct usb_ctrlrequest))) ||
		(unlikely(offset+len > sizeof(struct usb_ctrlrequest))))
		goto setup_pkt_load_err;

	memcpy(to, ptr, len);
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
	void *ptr;

	if ((unlikely(offset > urb->actual_length)) ||
		(unlikely(len > urb->actual_length)) ||
		(unlikely(offset+len > urb->actual_length)))
		goto trans_buf_load_err;

	memcpy(to, ptr, len);
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



/* BPF verifier ops */
const struct bpf_func_proto *lbm_usb_func_proto(enum bpf_func_id func_id)
{
}

bool lbm_usb_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
}

u32 lbm_usb_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size)
{
}

int lbm_usb_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog)
{
}

int lbm_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
}

