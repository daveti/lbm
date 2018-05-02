/*
 * lbm.h
 * Header file used by LBM internals and modules
 * Mar 19, 2018
 * root@davejingtian.org
 * https://davejingtian.org
 */
#ifndef __LINUX_LBM_H__
#define __LINUX_LBM_H__

#define LBM_MOD_NAME_LEN		32
#define LBM_BPF_NAME_LEN		32
#define LBM_SUBSYS_INDEX_USB		0
#define LBM_SUBSYS_INDEX_BLUETOOTH	1
#define LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP	2	/* daveti: we overload subsys with l2cap */
#define LBM_SUBSYS_INDEX_NFC		3
#define LBM_CALL_DIR_INGRESS		0
#define LBM_CALL_DIR_EGRESS		1
#define LBM_CALL_DIR_INEGRESS		2
#define LBM_RES_ALLOW			0
#define LBM_RES_DROP			1

struct bpf_prog;
struct sk_buff;

struct lbm_mod{
	char name[LBM_MOD_NAME_LEN];
	int subsys_index;			/* The index value is used to deploy hooks for certain subsys */
	int (*lbm_ingress_hook)(void *pkt);	/* The return value should be 0 or 1 - no others */
	int (*lbm_egress_hook)(void *pkt);
};

int lbm_bluetooth_l2cap_tx_reassemble(struct sk_buff *skb);
void *lbm_bluetooth_hci_get_conn(struct sk_buff *skb);

void lbm_bluetooth_hci_debug_skb(struct skb_buff *skb);
void lbm_bluetooth_l2cap_debug_skb(struct skb_buff *skb);

int lbm_is_enabled(void);
int lbm_is_bpf_debug_enabled(void);
int lbm_is_usb_debug_enabled(void);
int lbm_is_bluetooth_debug_enabled(void);
int lbm_is_bluetooth_l2cap_debug_enabled(void);
int lbm_is_nfc_debug_enabled(void);

int lbm_filter_pkt(int subsys, int dir, void *pkt);

int lbm_find_prog_sub_type(struct bpf_prog *prog, int subsys, int dir);
int lbm_load_bpf_prog(struct bpf_prog *prog, const char __user *name);

int lbm_register_mod(struct lbm_mod *mod);
int lbm_deregister_mod(struct lbm_mod *mod);

#endif /* __LINUX_LBM_H__ */
