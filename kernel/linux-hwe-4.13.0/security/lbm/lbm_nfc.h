/*
 * Internal header file for lbm nfc
 * Apr 5, 2018
 * root@davejingtian.org
 */
#ifndef __LBM_NFC_H__
#define __LBM_NFC_H__

struct bpf_func_proto;
struct bpf_insn_access_aux;
struct bpf_insn;
struct bpf_prog;
union bpf_attr;
enum bpf_func_id;
enum bpf_access_type;

/* BPF verifier ops */
const struct bpf_func_proto *lbm_nfc_func_proto(enum bpf_func_id func_id);
bool lbm_nfc_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info);
u32 lbm_nfc_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size);
int lbm_nfc_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog);
int lbm_nfc_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr);

#endif /* __LBM_NFC_H__ */
