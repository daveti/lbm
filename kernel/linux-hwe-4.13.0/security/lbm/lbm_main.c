/*
 * Linux (e)BPF Module
 *
 * Mar 19, 2018
 * root@davejingtian.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */
#include <linux/module.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/lbm.h>
#include "lbm_usb.h"
#include "lbm_bluetooth.h"
#include "lbm_nfc.h"

#define LBM_SUB_SYS_NUM_MAX		16
#define LBM_MOD_NUM_MAX			32	/* not used for now */
#define LBM_MOD_ACT_ADD			0
#define LBM_MOD_ACT_DEL			1
#define LBM_TMP_BUF_LEN			256
#define LBM_STAT_TX_CNT			0
#define LBM_STAT_TX_CNT_FILTERED	1
#define LBM_STAT_RX_CNT			2
#define LBM_STAT_RX_CNT_FILTERED	3
#define LBM_STAT_NUM_MAX		4

/* Global vars */
static struct hlist_head lbm_bpf_ingress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_bpf_egress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_ingress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_egress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_db;

static DEFINE_SPINLOCK(lbm_bpf_ingress_db_lock);	/* TODO: mutex may be enough for db locks */
static DEFINE_SPINLOCK(lbm_bpf_egress_db_lock);
static DEFINE_SPINLOCK(lbm_mod_ingress_db_lock);
static DEFINE_SPINLOCK(lbm_mod_egress_db_lock);
static DEFINE_SPINLOCK(lbm_mod_db_lock);

struct lbm_bpf_mod_info {
	struct hlist_node entry;
	struct rcu_head rcu;
	struct bpf_prog *bpf;
	struct lbm_mod *mod;
	int (*lbm_hook)(void *pkt);
	char bpf_name[LBM_BPF_NAME_LEN];	/* A better place may be bpf_prog but it is only used by lbm, so here is fine */
};

struct lbm_mod_info {
	struct hlist_node entry;
	struct rcu_head rcu;
	struct lbm_mod *mod;
};

static int lbm_mod_num;
static int lbm_enable;
static int lbm_main_debug;
static int lbm_bpf_debug;
static int lbm_usb_debug;
static int lbm_bluetooth_debug;
static int lbm_bluetooth_l2cap_debug;
static int lbm_nfc_debug;
static int lbm_stats_enable;

/* BPF map should be working so we literally do not need these */
static unsigned long lbm_stats_db[LBM_SUB_SYS_NUM_MAX][LBM_STAT_NUM_MAX];
static int lbm_perf_enable[LBM_SUB_SYS_NUM_MAX][2];	/* tx: 0, rx: 1 */

static struct dentry *lbm_sysfs_dir;
static struct dentry *lbm_sysfs_enable;
static struct dentry *lbm_sysfs_debug;
static struct dentry *lbm_sysfs_stats;
static struct dentry *lbm_sysfs_perf;
static struct dentry *lbm_sysfs_mod;
static struct dentry *lbm_sysfs_bpf_ingress;
static struct dentry *lbm_sysfs_bpf_egress;
static struct dentry *lbm_sysfs_mod_ingress;
static struct dentry *lbm_sysfs_mod_egress;


/* BPF verifier operations per subsys */
struct bpf_verifier_ops lbm_usb_prog_ops = {
	.get_func_proto         = lbm_usb_func_proto,
	.is_valid_access        = lbm_usb_is_valid_access,
	.convert_ctx_access     = lbm_usb_convert_ctx_access,
	.gen_prologue           = lbm_usb_prologue,
	.test_run               = lbm_usb_test_run_urb,
};

struct bpf_verifier_ops lbm_bluetooth_prog_ops = {
	.get_func_proto         = lbm_bluetooth_func_proto,
	.is_valid_access        = lbm_bluetooth_is_valid_access,
	.convert_ctx_access     = lbm_bluetooth_convert_ctx_access,
	.gen_prologue           = lbm_bluetooth_prologue,
	.test_run               = lbm_bluetooth_test_run_skb,
};

struct bpf_verifier_ops lbm_bluetooth_l2cap_prog_ops = {
	.get_func_proto         = lbm_bluetooth_l2cap_func_proto,
	.is_valid_access        = lbm_bluetooth_l2cap_is_valid_access,
	.convert_ctx_access     = lbm_bluetooth_l2cap_convert_ctx_access,
	.gen_prologue           = lbm_bluetooth_l2cap_prologue,
	.test_run               = lbm_bluetooth_l2cap_test_run_skb,
};

struct bpf_verifier_ops lbm_nfc_prog_ops = {
	.get_func_proto         = lbm_nfc_func_proto,
	.is_valid_access        = lbm_nfc_is_valid_access,
	.convert_ctx_access     = lbm_nfc_convert_ctx_access,
	.gen_prologue           = lbm_nfc_prologue,
	.test_run               = lbm_nfc_test_run_skb,
};

/* HACK */
const struct bpf_verifier_ops lbm_prog_ops;

/* Helpers */
static inline int check_calldir(int dir)
{
	switch (dir) {
	case LBM_CALL_DIR_INGRESS:
	case LBM_CALL_DIR_EGRESS:
	case LBM_CALL_DIR_INEGRESS:
		return 0;
	default:
		return -1;
	}
}

static inline int check_subsys(int idx)
{
	switch (idx) {
	case LBM_SUBSYS_INDEX_USB:
	case LBM_SUBSYS_INDEX_BLUETOOTH:
	case LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP:
	case LBM_SUBSYS_INDEX_NFC:
		return 0;
	default:
		return -1;
	}
}

inline int lbm_is_enabled(void)
{
	return lbm_enable;
}

inline int lbm_is_bpf_debug_enabled(void)
{
	return lbm_bpf_debug;
}

inline int lbm_is_usb_debug_enabled(void)
{
	return lbm_usb_debug;
}

inline int lbm_is_bluetooth_debug_enabled(void)
{
	return lbm_bluetooth_debug;
}

inline int lbm_is_bluetooth_l2cap_debug_enabled(void)
{
	return lbm_bluetooth_l2cap_debug;
}

inline int lbm_is_nfc_debug_enabled(void)
{
	return lbm_nfc_debug;
}


/* Essential filter function used by different subsys */
int lbm_filter_pkt(int subsys, int dir, void *pkt)
{
	struct lbm_bpf_mod_info *p;
	int res;

	if (!lbm_enable)
		return LBM_RES_ALLOW;

	/* Defensive checking */
	if (!pkt) {
		pr_err("%s: null pkt -- aborted\n", __func__);
		return -1;
	}
	if (check_subsys(subsys)) {
		pr_err("%s: invalid subsys [%d]\n", __func__, subsys);
		return -1;
	}
	if (check_calldir(dir)) {
		pr_err("%s: invalid calldir [%d]\n", __func__, dir);
		return -1;
	}

	/* Run the damn bpf/mod
	 * Current policy is to stop until we hit the first drop.
	 * TODO: expose policy to the user space to speed up here.
	 */
	res = LBM_RES_ALLOW;
	if (dir == LBM_CALL_DIR_INGRESS) {
		if (lbm_stats_enable)
			lbm_stats_db[subsys][LBM_STAT_RX_CNT]++;

		/* BPF */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_bpf_ingress_db[subsys], entry) {
			res = BPF_PROG_RUN(p->bpf, pkt);
			if (res == LBM_RES_DROP) {
				if (lbm_main_debug)
					pr_info("LBM: bpf ingress [%s] drop pkt [%p]\n",
						p->bpf_name, pkt);
				break;
			}
		}
		rcu_read_unlock();
		if (res == LBM_RES_DROP)
			goto filter_pkt_early_ret;

		/* MOD */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_mod_ingress_db[subsys], entry) {
			res = p->lbm_hook(pkt);
			if (res == LBM_RES_DROP) {
				if (lbm_main_debug)
					pr_info("LBM: mod ingress [%s] drop pkt [%p]\n",
						p->mod->name, pkt);
				break;
			}
		}
		rcu_read_unlock();
		if (res == LBM_RES_DROP)
			goto filter_pkt_early_ret;
	} else if (dir == LBM_CALL_DIR_EGRESS) {
		if (lbm_stats_enable)
			lbm_stats_db[subsys][LBM_STAT_TX_CNT]++;

		/* BPF */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_bpf_egress_db[subsys], entry) {
			res = BPF_PROG_RUN(p->bpf, pkt);
			if (res == LBM_RES_DROP) {
				if (lbm_main_debug)
					pr_info("LBM: bpf egress [%s] drop pkt [%p]\n",
						p->bpf_name, pkt);
				break;
			}
		}
		rcu_read_unlock();
		if (res == LBM_RES_DROP)
			goto filter_pkt_early_ret;

		/* MOD */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_mod_egress_db[subsys], entry) {
			res = p->lbm_hook(pkt);
			if (res == LBM_RES_DROP) {
				if (lbm_main_debug)
					pr_info("LBM: mod egress [%s] drop pkt [%p]\n",
						p->mod->name, pkt);
				break;
			}
		}
		rcu_read_unlock();
	} else {
		pr_err("LBM: %s - bad dir [%d]\n", __func__, dir);
		return -1;
	}

filter_pkt_early_ret:
	if (lbm_stats_enable && (res == LBM_RES_DROP)) {
		if (dir == LBM_CALL_DIR_INGRESS)
			lbm_stats_db[subsys][LBM_STAT_RX_CNT_FILTERED]++;
		else
			lbm_stats_db[subsys][LBM_STAT_TX_CNT_FILTERED]++;
	}
	if (lbm_main_debug)
		pr_info("LBM: %s - subsys [%d], dir [%d], pkt [%p], res [%d]\n",
			__func__, subsys, dir, pkt, res);
	return res;
}

int lbm_find_prog_sub_type(struct bpf_prog *prog, int subsys, int dir)
{
	struct bpf_verifier_ops *ops;
	/* Caller guaranteed null check */

	switch (subsys) {
	case LBM_SUBSYS_INDEX_USB:
		ops = &lbm_usb_prog_ops;
		break;
	case LBM_SUBSYS_INDEX_BLUETOOTH:
		ops = &lbm_bluetooth_prog_ops;
		break;
	case LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP:
		ops = &lbm_bluetooth_l2cap_prog_ops;
		break;
	case LBM_SUBSYS_INDEX_NFC:
		ops = &lbm_nfc_prog_ops;
		break;
	default:
		pr_err("LBM: unsupported subsys [%d] in [%s]\n",
			subsys, __func__);
		return -1;
	}

	prog->aux->ops = ops;
	prog->aux->lbm_subsys_idx = subsys;
	prog->aux->lbm_call_dir = dir;
	prog->type = BPF_PROG_TYPE_LBM;		/* TODO: shall we consider a subtype here? */

	return 0;
}

static int find_bpf_given_name_db(char *name, struct hlist_head *db)
{
	struct lbm_bpf_mod_info *p;
	int exist = 0;

	rcu_read_lock();
	hlist_for_each_entry_rcu(p, db, entry) {
		if (unlikely(strncasecmp(p->bpf_name, name, LBM_BPF_NAME_LEN) == 0)) {
			exist = 1;
			break;
		}
	}
	rcu_read_unlock();

	return exist;
}

static int find_bpf_given_name(char *name, int subsys)
{
	int i;

	for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
		if ((find_bpf_given_name_db(name, &lbm_bpf_ingress_db[i])) || 
			(find_bpf_given_name_db(name, &lbm_bpf_egress_db[i])))
			return 1;
	}

	return 0;
}

int lbm_load_bpf_prog(struct bpf_prog *prog, const char __user *name)
{
	struct lbm_bpf_mod_info *p;
	char tmp_name[LBM_BPF_NAME_LEN];
	unsigned long flags;
	int len;

	/* Check subsys */
	if (check_subsys(prog->aux->lbm_subsys_idx)) {
		pr_err("LBM: invalid subsys [%d] in %s\n",
			prog->aux->lbm_subsys_idx, __func__);
		return -1;
	}

	/* Check calldir */
	if (check_calldir(prog->aux->lbm_call_dir)) {
		pr_err("LBM: invalid calldir [%d] in %s\n",
			prog->aux->lbm_call_dir, __func__);
		return -1;
	}

	/* Get the bpf name */
	memset(tmp_name, 0x0, LBM_BPF_NAME_LEN);
	len = strncpy_from_user(tmp_name, name, LBM_BPF_NAME_LEN);
	if (unlikely(len < 0)) {
		pr_err("LBM: strncpy_from_user failed within %s\n", __func__);
		return -1;
	}
	if (unlikely(len == LBM_BPF_NAME_LEN)) {
		pr_warn("LBM: name length beyond limit within %s - truncated\n", __func__);
		tmp_name[LBM_BPF_NAME_LEN-1] = '\0';
	}

	/* Make sure it does not exist */
	if (find_bpf_given_name(tmp_name, prog->aux->lbm_subsys_idx)) {
		pr_err("LBM: existing bpf found during %s - aborted\n", __func__);
		return -1;
	}

	/* Alloc a bpf_mod_info */
	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		pr_err("LBM: kmalloc failed within %s\n", __func__);
		return -1;
	}
	p->mod = NULL;
	p->lbm_hook = NULL;
	p->bpf = prog;
	memcpy(p->bpf_name, tmp_name, LBM_BPF_NAME_LEN);

	/* Add into DBs */
	if ((prog->aux->lbm_call_dir == LBM_CALL_DIR_INGRESS) ||
		(prog->aux->lbm_call_dir == LBM_CALL_DIR_INEGRESS)) {
		spin_lock_irqsave(&lbm_bpf_ingress_db_lock, flags);
		hlist_add_tail_rcu(&p->entry, &lbm_bpf_ingress_db[prog->aux->lbm_subsys_idx]);
		spin_unlock_irqrestore(&lbm_bpf_ingress_db_lock, flags);
		bpf_prog_inc(prog);
		if (lbm_main_debug)
			pr_info("LBM: bpf [%s] added into bpf ingress db for subsys [%d]\n",
				p->bpf_name, p->bpf->aux->lbm_subsys_idx);
	}
	if ((prog->aux->lbm_call_dir == LBM_CALL_DIR_EGRESS) ||
		(prog->aux->lbm_call_dir == LBM_CALL_DIR_INEGRESS)) {
		spin_lock_irqsave(&lbm_bpf_egress_db_lock, flags);
		hlist_add_tail_rcu(&p->entry, &lbm_bpf_egress_db[prog->aux->lbm_subsys_idx]);
		spin_unlock_irqrestore(&lbm_bpf_egress_db_lock, flags);
		bpf_prog_inc(prog);
		if (lbm_main_debug)
			pr_info("LBM: bpf [%s] added into bpf egress db for subsys [%d]\n",
				p->bpf_name, p->bpf->aux->lbm_subsys_idx);
	}

	return 0;
}




static int find_mod_given_name(char *name)
{
	struct lbm_mod_info *p;
	int exist = 0;

	rcu_read_lock();
	hlist_for_each_entry_rcu(p, &lbm_mod_db, entry) {
		if (unlikely(strncasecmp(p->mod->name, name, LBM_MOD_NAME_LEN) == 0)) {
			exist = 1;
			break;
		}
	}
	rcu_read_unlock();

	return exist;
}

int lbm_register_mod(struct lbm_mod *mod)
{
	struct lbm_mod_info *p;
	struct lbm_bpf_mod_info *q;
	unsigned long flags;

	if (!lbm_enable) {
		pr_err("LBM: %s failed when LBM disabled\n", __func__);
		return -1;
	}

	if (!mod) {
		pr_err("LBM: null mod in %s\n", __func__);
		return -1;
	}

	if (!check_subsys(mod->subsys_index)) {
		pr_err("LBM: invalid subsys index [%d]\n", mod->subsys_index);
		return -1;
	}

	/* Make sure it is not in the list */
	if (find_mod_given_name(mod->name)) {
		pr_err("LBM: mod [%s] already exists\n", mod->name);
		return -1;
	}

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		pr_err("LBM: kmalloc failed for mod_info\n");
		return -ENOMEM;
	}
	p->mod = mod;

	/* Add this mod into DB */
	spin_lock_irqsave(&lbm_mod_db_lock, flags);
	hlist_add_tail_rcu(&p->entry, &lbm_mod_db);
	lbm_mod_num++;
	spin_unlock_irqrestore(&lbm_mod_db_lock, flags);
	if (lbm_main_debug)
		pr_info("LBM: mod [%s] added into the mod db\n", mod->name);

	/* Add into ingree and egree DBs */
	if (mod->lbm_ingress_hook) {
		q = kmalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			pr_err("LBM: kmalloc failed for bpf_mod_info on ingress\n");
			return -ENOMEM;
		}
		q->bpf = NULL;
		q->mod = mod;
		q->lbm_hook = mod->lbm_ingress_hook;

		spin_lock_irqsave(&lbm_mod_ingress_db_lock, flags);
		hlist_add_tail_rcu(&q->entry, &lbm_mod_ingress_db[mod->subsys_index]);
		spin_unlock_irqrestore(&lbm_mod_ingress_db_lock, flags);
		if (lbm_main_debug)
			pr_info("LBM: mod [%s] added into mod ingress db for subsys [%d]\n",
				mod->name, mod->subsys_index);
	}

	if (mod->lbm_egress_hook) {
		q = kmalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			pr_err("LBM: kmalloc failed for bpf_mod_info on egress\n");
			return -ENOMEM;
		}
		q->bpf = NULL;
		q->mod = mod;
		q->lbm_hook = mod->lbm_egress_hook;

		spin_lock_irqsave(&lbm_mod_egress_db_lock, flags);
		hlist_add_tail_rcu(&q->entry, &lbm_mod_egress_db[mod->subsys_index]);
		spin_unlock_irqrestore(&lbm_mod_egress_db_lock, flags);
		if (lbm_main_debug)
			pr_info("LBM: mod [%s] added into mod egress db for subsys [%d]\n",
				mod->name, mod->subsys_index);
	}

	return 0;
}

int lbm_deregister_mod(struct lbm_mod *mod)
{
	struct lbm_mod_info *p;
	struct lbm_bpf_mod_info *q;
	unsigned long flags;

	if (!lbm_enable) {
		pr_err("LBM: %s failed when LBM disabled\n", __func__);
		return -1;
	}

	if (!mod) {
		pr_err("LBM: null mod in %s\n", __func__);
		return -1;
	}

	if (!check_subsys(mod->subsys_index)) {
		pr_err("LBM: invalid subsys index [%d]\n", mod->subsys_index);
		return -1;
	}

	/* Make sure it is in the list */
	if (!find_mod_given_name(mod->name)) {
		pr_err("LBM: mod [%s] does not exists\n", mod->name);
		return -1;
	}

	/* Remove this from ingress and egress DBs */
	if (mod->lbm_ingress_hook) {
		spin_lock_irqsave(&lbm_mod_ingress_db_lock, flags);
		hlist_for_each_entry_rcu(q, &lbm_mod_ingress_db[mod->subsys_index], entry) {
			if (strncasecmp(q->mod->name, mod->name, LBM_MOD_NAME_LEN) == 0) {
				hlist_del_rcu(&q->entry);
				kfree_rcu(q, rcu);
				break;
			}
		}
		spin_unlock_irqrestore(&lbm_mod_ingress_db_lock, flags);
		if (lbm_main_debug)
			pr_info("LBM: mod [%s] removed from mod ingress db for subsys [%d]\n",
				mod->name, mod->subsys_index);
	}
	if (mod->lbm_egress_hook) {
		spin_lock_irqsave(&lbm_mod_egress_db_lock, flags);
		hlist_for_each_entry_rcu(q, &lbm_mod_egress_db[mod->subsys_index], entry) {
			if (strncasecmp(q->mod->name, mod->name, LBM_MOD_NAME_LEN) == 0) {
				hlist_del_rcu(&q->entry);
				kfree_rcu(q, rcu);
				break;
			}
		}
		spin_unlock_irqrestore(&lbm_mod_egress_db_lock, flags);
		if (lbm_main_debug)
			pr_info("LBM: mod [%s] removed from mod egress db for subsys [%d]\n",
				mod->name, mod->subsys_index);
	}

	/* Remove this mod from DB */
	spin_lock_irqsave(&lbm_mod_db_lock, flags);
	hlist_for_each_entry_rcu(p, &lbm_mod_db, entry) {
		if (strncasecmp(p->mod->name, mod->name, LBM_MOD_NAME_LEN) == 0) {
			hlist_del_rcu(&p->entry);
			kfree_rcu(p, rcu);
			lbm_mod_num--;
			break;
		}
	}
	spin_unlock_irqrestore(&lbm_mod_db_lock, flags);
	if (lbm_main_debug)
		pr_info("LBM: mod [%s] removed from mod db\n", mod->name);

	return 0;
}



/* sysfs */
static inline int update_boolean_value(char *val, int *target)
{
	int rv, value;

	rv = kstrtoint(val, 0, &value);
	if (rv < 0)
		return rv;

	if ((value == 0) || (value == 1)) {
		*target = value;
		return 0;
	}

	return -1;
}

static ssize_t lbm_sysfs_debug_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	ssize_t len;

	len = scnprintf(tmp_buf, LBM_TMP_BUF_LEN, "main:%d,bpf:%d,usb:%d,"
			"bluetooth:%d,bluetooth-l2cap:%d,nfc:%d\n",
			lbm_main_debug,
			lbm_bpf_debug,
			lbm_usb_debug,
			lbm_bluetooth_debug,
			lbm_bluetooth_l2cap_debug,
			lbm_nfc_debug);
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_debug_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	char *p;
	ssize_t res;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto debug_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto debug_write_out;
	}

	/* Write follows the same syntax of read output */
	while ((p = strsep(&data, ",")) != NULL) {
		if (strncmp(p, "main:", 5) == 0)
			res = update_boolean_value(p+5, &lbm_main_debug);
		else if (strncmp(p, "bpf:", 4) == 0)
			res = update_boolean_value(p+4, &lbm_bpf_debug);
		else if (strncmp(p, "usb:", 4) == 0)
			res = update_boolean_value(p+4, &lbm_usb_debug);
		else if (strncmp(p, "bluetooth:", 10) == 0)
			res = update_boolean_value(p+10, &lbm_bluetooth_debug);
		else if (strncmp(p, "bluetooth-l2cap:", 16) == 0)
			res = update_boolean_value(p+16, &lbm_bluetooth_l2cap_debug);
		else if (strncmp(p, "nfc:", 4) == 0)
			res = update_boolean_value(p+4, &lbm_nfc_debug);
		else {
			pr_err("LBM: %s - unsupported debug option [%s]\n",
				__func__, p);
			res = -EINVAL;
			break;
		}
	}

	if (!res)
		return datalen;

debug_write_out:
	return res;
}

static ssize_t lbm_sysfs_enable_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	ssize_t len;

	len = scnprintf(tmp_buf, LBM_TMP_BUF_LEN, "%d\n", lbm_enable);
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_enable_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t res;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto enable_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto enable_write_out;
	}

	res = update_boolean_value(data, &lbm_enable);
	if (!res)
		return datalen;

enable_write_out:
	return res;
}

static ssize_t lbm_sysfs_stats_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	ssize_t len;

	len = scnprintf(tmp_buf, LBM_TMP_BUF_LEN, "enabled: %d\n"
			"usb: %lu %lu %lu %lu\n"
			"bluetooth: %lu %lu %lu %lu\n"
			"bluetooth l2cap: %lu %lu %lu %lu\n"
			"nfc: %lu %lu %lu %lu\n",
			lbm_stats_enable,
			lbm_stats_db[LBM_SUBSYS_INDEX_USB][LBM_STAT_TX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_USB][LBM_STAT_TX_CNT_FILTERED],
			lbm_stats_db[LBM_SUBSYS_INDEX_USB][LBM_STAT_RX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_USB][LBM_STAT_RX_CNT_FILTERED],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH][LBM_STAT_TX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH][LBM_STAT_TX_CNT_FILTERED],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH][LBM_STAT_RX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH][LBM_STAT_RX_CNT_FILTERED],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][LBM_STAT_TX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][LBM_STAT_TX_CNT_FILTERED],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][LBM_STAT_RX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][LBM_STAT_RX_CNT_FILTERED],
			lbm_stats_db[LBM_SUBSYS_INDEX_NFC][LBM_STAT_TX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_NFC][LBM_STAT_TX_CNT_FILTERED],
			lbm_stats_db[LBM_SUBSYS_INDEX_NFC][LBM_STAT_RX_CNT],
			lbm_stats_db[LBM_SUBSYS_INDEX_NFC][LBM_STAT_RX_CNT_FILTERED]);
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_stats_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t res;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto stats_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto stats_write_out;
	}

	res = update_boolean_value(data, &lbm_stats_enable);
	if (!res) {
		if (lbm_stats_enable)
			/* Have a fresh start */
			memset(lbm_stats_db, 0x0, sizeof(lbm_stats_db));
		return datalen;
	}

stats_write_out:
	return res;
}

static ssize_t lbm_sysfs_perf_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	ssize_t len;

	len = scnprintf(tmp_buf, LBM_TMP_BUF_LEN, "enabled:%d, usb:%d|%d, bluetooth:%d|%d, "
			"bluetooth-l2cap: %d|%d, nfc:%d|%d\n",
			lbm_stats_enable,
			lbm_perf_enable[LBM_SUBSYS_INDEX_USB][0],
			lbm_perf_enable[LBM_SUBSYS_INDEX_USB][1],
			lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH][0],
			lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH][1],
			lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][0],
			lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][1],
			lbm_perf_enable[LBM_SUBSYS_INDEX_NFC][0],
			lbm_perf_enable[LBM_SUBSYS_INDEX_NFC][1]);
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_perf_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	char *p;
	ssize_t res;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto perf_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto perf_write_out;
	}

	/* Write follows this syntax:
	 * usb:tx:0,usb:rx:1,bluetooth:rx:1,...
	 */
	while ((p = strsep(&data, ",")) != NULL) {
		if (strncmp(p, "usb:tx:", 7) == 0)
			res = update_boolean_value(p+7, &lbm_perf_enable[LBM_SUBSYS_INDEX_USB][0]);
 		else if (strncmp(p, "usb:rx:", 7) == 0)
			res = update_boolean_value(p+7, &lbm_perf_enable[LBM_SUBSYS_INDEX_USB][1]);
 		else if (strncmp(p, "bluetooth:tx:", 13) == 0)
			res = update_boolean_value(p+13, &lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH][0]);
 		else if (strncmp(p, "bluetooth:rx:", 13) == 0)
			res = update_boolean_value(p+13, &lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH][1]);
 		else if (strncmp(p, "bluetooth-l2cap:tx:", 19) == 0)
			res = update_boolean_value(p+13, &lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][0]);
 		else if (strncmp(p, "bluetooth-l2cap:rx:", 19) == 0)
			res = update_boolean_value(p+13, &lbm_perf_enable[LBM_SUBSYS_INDEX_BLUETOOTH_L2CAP][1]);
 		else if (strncmp(p, "nfc:tx:", 7) == 0)
			res = update_boolean_value(p+7, &lbm_perf_enable[LBM_SUBSYS_INDEX_NFC][0]);
		else if (strncmp(p, "nfc:rx:", 7) == 0)
			res = update_boolean_value(p+7, &lbm_perf_enable[LBM_SUBSYS_INDEX_NFC][1]);
 		else {
 			pr_err("LBM: %s - unsupported endable option [%s]\n", __func__, p);
			res = -EINVAL;
			break;
		}
	}

	if (!res)
		return datalen;

perf_write_out:
	return res;
}


static ssize_t lbm_sysfs_mod_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	struct lbm_mod_info *p;
	ssize_t len = 0;

	rcu_read_lock();
	hlist_for_each_entry_rcu(p, &lbm_mod_db, entry) {
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "%s\n",
			p->mod->name);
	}
	rcu_read_unlock();
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static int remove_mod_ingress_given_name(char *name)
{
	struct lbm_bpf_mod_info *q;
	unsigned long flags;
	int res;
	int i;

	res = -1;
	spin_lock_irqsave(&lbm_mod_ingress_db_lock, flags);
	for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
		hlist_for_each_entry_rcu(q, &lbm_mod_ingress_db[i], entry) {
			if (strncasecmp(q->mod->name, name, LBM_MOD_NAME_LEN) == 0) {
				hlist_del_rcu(&q->entry);
				kfree_rcu(q, rcu);
				res = 0;
				if (lbm_main_debug)
					pr_info("LBM: mod [%s] removed from mod ingress db for subsys [%d]\n",
						name, i);
				goto ingress_found_mod;
			}
		}
	}
ingress_found_mod:
	spin_unlock_irqrestore(&lbm_mod_ingress_db_lock, flags);
	return res;
}

static int remove_mod_egress_given_name(char *name)
{
	struct lbm_bpf_mod_info *q;
	unsigned long flags;
	int res;
	int i;

	res = -1;
	spin_lock_irqsave(&lbm_mod_egress_db_lock, flags);
	for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
		hlist_for_each_entry_rcu(q, &lbm_mod_egress_db[i], entry) {
			if (strncasecmp(q->mod->name, name, LBM_MOD_NAME_LEN) == 0) {
				hlist_del_rcu(&q->entry);
				kfree_rcu(q, rcu);
				res = 0;
				if (lbm_main_debug)
					pr_info("LBM: mod [%s] removed from mod egress db for subsys [%d]\n",
						name, i);
				goto ingress_found_mod;
			}
		}
	}
ingress_found_mod:
	spin_unlock_irqrestore(&lbm_mod_egress_db_lock, flags);
	return res;
}

static ssize_t lbm_sysfs_mod_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	char *p;
	char *name;
	ssize_t res;
	unsigned long flags;
	struct lbm_mod_info *q;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto mod_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto mod_write_out;
	}

	/* Only allow rm
	 * Syntax: "rm:modname1,rm:modname2,..."
	 */
	res = 0;
	while ((p = strsep(&data, ",")) != NULL) {
		if (strncmp(p, "rm:", 3) == 0) {
			name = p + 3;
			/* Clear ingress and egress DBs before finally removing the mod */
			remove_mod_ingress_given_name(name);
			remove_mod_egress_given_name(name);

			/* Remove this mod from DB */
			spin_lock_irqsave(&lbm_mod_db_lock, flags);
			hlist_for_each_entry_rcu(q, &lbm_mod_db, entry) {
				if (strncasecmp(q->mod->name, name, LBM_MOD_NAME_LEN) == 0) {
					hlist_del_rcu(&q->entry);
					kfree_rcu(q, rcu);
					lbm_mod_num--;
					if (lbm_main_debug)
						pr_info("LBM: mod [%s] removed from mod db\n", name);
					break;
				}
			}
			spin_unlock_irqrestore(&lbm_mod_db_lock, flags);
		} else {
			pr_err("LBM: %s - unsupported modules option [%s]\n",
				__func__, p);
			res = -EINVAL;
			break;
		}
	}

	if (!res)
		return datalen;

mod_write_out:
	return res;
}

static ssize_t lbm_sysfs_bpf_ingress_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	struct lbm_bpf_mod_info *p;
	ssize_t len = 0;
	int i;

	rcu_read_lock();
	for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "subsys [%d]: ", i);
		hlist_for_each_entry_rcu(p, &lbm_bpf_ingress_db[i], entry) {
			len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "%s ",
					p->bpf_name);
		}
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "\n");
	}
	rcu_read_unlock();
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_bpf_ingress_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	char *p;
	char *name;
	ssize_t res;
	unsigned long flags;
	struct lbm_bpf_mod_info *q;
	int i;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto bpf_ingress_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto bpf_ingress_write_out;
	}

	/* Only allow rm
	 * Syntax: "rm:bpfname1,rm:bpfname2,..."
	 */
	res = 0;
	while ((p = strsep(&data, ",")) != NULL) {
		if (strncmp(p, "rm:", 3) == 0) {
			name = p + 3;
			/* Remove this from DB */
			spin_lock_irqsave(&lbm_bpf_ingress_db_lock, flags);
			for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
				hlist_for_each_entry_rcu(q, &lbm_bpf_ingress_db[i], entry) {
					if (strncasecmp(q->bpf_name, name, LBM_MOD_NAME_LEN) == 0) {
						bpf_prog_sub(q->bpf, 1);
						hlist_del_rcu(&q->entry);
						kfree_rcu(q, rcu);
						if (lbm_main_debug)
							pr_info("LBM: bpf [%s] removed from bpf ingress db for subsys [%d]\n",
								name, i);
						goto bpf_ingress_write_found;
					}
				}
			}
bpf_ingress_write_found:
			spin_unlock_irqrestore(&lbm_bpf_ingress_db_lock, flags);
		} else {
			pr_err("LBM: %s - unsupported bpf ingress option [%s]\n",
				__func__, p);
			res = -EINVAL;
			break;
		}
	}

	if (!res)
		return datalen;

bpf_ingress_write_out:
	return res;
}

static ssize_t lbm_sysfs_bpf_egress_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	struct lbm_bpf_mod_info *p;
	ssize_t len = 0;
	int i;

	rcu_read_lock();
	for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "subsys [%d]: ", i);
		hlist_for_each_entry_rcu(p, &lbm_bpf_egress_db[i], entry) {
			len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "%s ",
					p->bpf_name);
		}
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "\n");
	}
	rcu_read_unlock();
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_bpf_egress_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	char *p;
	char *name;
	ssize_t res;
	unsigned long flags;
	struct lbm_bpf_mod_info *q;
	int i;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto bpf_egress_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto bpf_egress_write_out;
	}

	/* Only allow rm
	 * Syntax: "rm:bpfname1,rm:bpfname2,..."
	 */
	res = 0;
	while ((p = strsep(&data, ",")) != NULL) {
		if (strncmp(p, "rm:", 3) == 0) {
			name = p + 3;
			/* Remove this from DB */
			spin_lock_irqsave(&lbm_bpf_egress_db_lock, flags);
			for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
				hlist_for_each_entry_rcu(q, &lbm_bpf_egress_db[i], entry) {
					if (strncasecmp(q->bpf_name, name, LBM_MOD_NAME_LEN) == 0) {
						bpf_prog_sub(q->bpf, 1);
						hlist_del_rcu(&q->entry);
						kfree_rcu(q, rcu);
						if (lbm_main_debug)
							pr_info("LBM: bpf [%s] removed from bpf egress db for subsys [%d]\n",
								name, i);
						goto bpf_egress_write_found;
					}
				}
			}
bpf_egress_write_found:
			spin_unlock_irqrestore(&lbm_bpf_egress_db_lock, flags);
		} else {
			pr_err("LBM: %s - unsupported bpf egress option [%s]\n",
				__func__, p);
			res = -EINVAL;
			break;
		}
	}

	if (!res)
		return datalen;

bpf_egress_write_out:
	return res;
}

static ssize_t lbm_sysfs_mod_ingress_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	struct lbm_bpf_mod_info *p;
	ssize_t len = 0;
	int i;

	rcu_read_lock();
	for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "subsys [%d]: ", i);
		hlist_for_each_entry_rcu(p, &lbm_mod_ingress_db[i], entry) {
			len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "%s ",
					p->mod->name);
		}
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "\n");
	}
	rcu_read_unlock();
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_mod_ingress_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	char *p;
	char *name;
	ssize_t res;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto mod_ingress_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto mod_ingress_write_out;
	}

	/* Only allow rm
	 * Syntax: "rm:modname1,rm:modname2,..."
	 */
	while ((p = strsep(&data, ",")) != NULL) {
		if (strncmp(p, "rm:", 3) == 0) {
			name = p + 3;
			/* Remove this from DB */
			res = remove_mod_ingress_given_name(name);
			if (res) {
				pr_err("LBM: %s - removing mod ingress [%s] failed\n",
					__func__, name);
				break;
			}
		} else {
			pr_err("LBM: %s - unsupported mod ingress option [%s]\n",
				__func__, p);
			res = -EINVAL;
			break;
		}
	}

	if (!res)
		return datalen;

mod_ingress_write_out:
	return res;
}

static ssize_t lbm_sysfs_mod_egress_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	struct lbm_bpf_mod_info *p;
	ssize_t len = 0;
	int i;

	rcu_read_lock();
	for (i = 0; i < LBM_SUB_SYS_NUM_MAX; i++) {
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "subsys [%d]: ", i);
		hlist_for_each_entry_rcu(p, &lbm_mod_egress_db[i], entry) {
			len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "%s ",
					p->mod->name);
		}
		len += scnprintf(tmp_buf+len, LBM_TMP_BUF_LEN-len, "\n");
	}
	rcu_read_unlock();
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static ssize_t lbm_sysfs_mod_egress_write(struct file *file, const char __user *buf,
					size_t datalen, loff_t *ppos)
{
	char *data;
	char *p;
	char *name;
	ssize_t res;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	res = -EINVAL;
	if (*ppos != 0)
		goto mod_egress_write_out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		res = PTR_ERR(data);
		goto mod_egress_write_out;
	}

	/* Only allow rm
	 * Syntax: "rm:modname1,rm:modname2,..."
	 */
	while ((p = strsep(&data, ",")) != NULL) {
		if (strncmp(p, "rm:", 3) == 0) {
			name = p + 3;
			/* Remove this from DB */
			res = remove_mod_egress_given_name(name);
			if (res) {
				pr_err("LBM: %s - removing mod egress [%s] failed\n",
					__func__, name);
				break;
			}
		} else {
			pr_err("LBM: %s - unsupported mod egress option [%s]\n",
				__func__, p);
			res = -EINVAL;
			break;
		}
	}

	if (!res)
		return datalen;

mod_egress_write_out:
	return res;
}



static const struct file_operations lbm_sysfs_debug_ops = {
	.read = lbm_sysfs_debug_read,
	.write = lbm_sysfs_debug_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_enable_ops = {
	.read = lbm_sysfs_enable_read,
	.write = lbm_sysfs_enable_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_stats_ops = {
	.read = lbm_sysfs_stats_read,
	.write = lbm_sysfs_stats_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_perf_ops = {
	.read = lbm_sysfs_perf_read,
	.write = lbm_sysfs_perf_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_mod_ops = {
	.read = lbm_sysfs_mod_read,
	.write = lbm_sysfs_mod_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_bpf_ingress_ops = {
	.read = lbm_sysfs_bpf_ingress_read,
	.write = lbm_sysfs_bpf_ingress_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_bpf_egress_ops = {
	.read = lbm_sysfs_bpf_egress_read,
	.write = lbm_sysfs_bpf_egress_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_mod_ingress_ops = {
	.read = lbm_sysfs_mod_ingress_read,
	.write = lbm_sysfs_mod_ingress_write,
	.llseek = generic_file_llseek,
};

static const struct file_operations lbm_sysfs_mod_egress_ops = {
	.read = lbm_sysfs_mod_egress_read,
	.write = lbm_sysfs_mod_egress_write,
	.llseek = generic_file_llseek,
};


int lbm_init_sysfs(void)
{
	if (lbm_main_debug)
		pr_info("LBM: into %s\n", __func__);
	
	lbm_sysfs_dir = securityfs_create_dir("lbm", NULL);
	if (IS_ERR(lbm_sysfs_dir))
		return -1;

	lbm_sysfs_enable = securityfs_create_file("enable", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_enable_ops);
	if (IS_ERR(lbm_sysfs_enable))
		goto init_sysfs_failed;

	lbm_sysfs_debug = securityfs_create_file("debug", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_debug_ops);
	if (IS_ERR(lbm_sysfs_debug))
		goto init_sysfs_failed;

	lbm_sysfs_stats = securityfs_create_file("stats", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_stats_ops);
	if (IS_ERR(lbm_sysfs_stats))
		goto init_sysfs_failed;

	lbm_sysfs_perf = securityfs_create_file("perf", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_perf_ops);
	if (IS_ERR(lbm_sysfs_perf))
		goto init_sysfs_failed;

	lbm_sysfs_mod = securityfs_create_file("modules", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_mod_ops);
	if (IS_ERR(lbm_sysfs_mod))
		goto init_sysfs_failed;

	lbm_sysfs_bpf_ingress = securityfs_create_file("bpf_ingress", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_bpf_ingress_ops);
	if (IS_ERR(lbm_sysfs_bpf_ingress))
		goto init_sysfs_failed;

	lbm_sysfs_bpf_egress = securityfs_create_file("bpf_egress", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_bpf_egress_ops);
	if (IS_ERR(lbm_sysfs_bpf_egress))
		goto init_sysfs_failed;

	lbm_sysfs_mod_ingress = securityfs_create_file("mod_ingress", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_mod_ingress_ops);
	if (IS_ERR(lbm_sysfs_mod_ingress))
		goto init_sysfs_failed;

	lbm_sysfs_mod_egress = securityfs_create_file("mod_egress", 0600, lbm_sysfs_dir,
				NULL, &lbm_sysfs_mod_egress_ops);
	if (IS_ERR(lbm_sysfs_mod_egress))
		goto init_sysfs_failed;

	return 0;

init_sysfs_failed:
	securityfs_remove(lbm_sysfs_enable);
	securityfs_remove(lbm_sysfs_debug);
	securityfs_remove(lbm_sysfs_stats);
	securityfs_remove(lbm_sysfs_perf);
	securityfs_remove(lbm_sysfs_mod);
	securityfs_remove(lbm_sysfs_bpf_ingress);
	securityfs_remove(lbm_sysfs_bpf_egress);
	securityfs_remove(lbm_sysfs_mod_ingress);
	securityfs_remove(lbm_sysfs_mod_egress);
	securityfs_remove(lbm_sysfs_dir);
	return -1;
}


/* init/exit */
static int __init lbm_init(void)
{
	if (lbm_init_sysfs()) {
		pr_err("LBM initialization failed\n");
		return -1;
	} else 
		pr_info("LBM initialized\n");

	return 0;
}

late_initcall(lbm_init);        /* Start LBM late */

MODULE_DESCRIPTION("Linux (e)BPF Modules");
MODULE_LICENSE("GPL");

