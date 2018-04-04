/*
 * Internal header file for lbm-usb
 * Apr 3, 2018
 * root@davejingtian.org
 */
#ifndef __LBM_USB_H__
#define __LBM_USB_H__

struct bpf_func_proto;
struct bpf_insn_access_aux;
struct bpf_insn;
struct bpf_prog;
union bpf_attr;
enum bpf_func_id;
enum bpf_access_type;

/* BPF verifier ops */
const struct bpf_func_proto *lbm_usb_func_proto(enum bpf_func_id func_id);
bool lbm_usb_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info);
u32 lbm_usb_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size);
int lbm_usb_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog);
int lbm_test_run_urb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr);

#endif /* __LBM_USB_H__ */
