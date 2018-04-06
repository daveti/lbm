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
#define LBM_TMP_BUF_LEN			128

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
static atomic_t lbm_main_debug = ATOMIC_INIT(1);
static atomic_t lbm_bpf_debug = ATOMIC_INIT(1);
static atomic_t lbm_usb_debug = ATOMIC_INIT(1);
static atomic_t lbm_bluetooth_debug = ATOMIC_INIT(0);
static atomic_t lbm_nfc_debug = ATOMIC_INIT(0);

/* BPF map should be working so we literally do not need these */
static atomic_long_t lbm_usb_pkt_sent = ATOMIC_LONG_INIT(0);
static atomic_long_t lbm_usb_pkt_sent_filtered = ATOMIC_LONG_INIT(0);
static atomic_long_t lbm_usb_pkt_recv = ATOMIC_LONG_INIT(0);
static atomic_long_t lbm_usb_pkt_recv_filtered = ATOMIC_LONG_INIT(0);

static struct dentry *lbm_sysfs_dir;
static struct dentry *lbm_sysfs_debug;
static struct dentry *lbm_sysfs_stats;
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
	case LBM_SUBSYS_INDEX_NFC:
		return 0;
	default:
		return -1;
	}
}


/* Essential filter function used by different subsys */
int lbm_filter_pkt(int subsys, int dir, void *pkt)
{
	struct lbm_bpf_mod_info *p;
	int res;

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
	if ((dir == LBM_CALL_DIR_INGRESS) ||
		(dir == LBM_CALL_DIR_INEGRESS)) {
		/* BPF */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_bpf_ingress_db[subsys], entry) {
			res = BPF_PROG_RUN(p->bpf, pkt);
			if (res == LBM_RES_DROP)
				break;
		}
		rcu_read_unlock();
		if (res == LBM_RES_DROP)
			goto filter_pkt_early_ret;

		/* MOD */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_mod_ingress_db[subsys], entry) {
			res = p->lbm_hook(pkt);
			if (res == LBM_RES_DROP)
				break;
		}
		rcu_read_unlock();
		if (res == LBM_RES_DROP)
			goto filter_pkt_early_ret;
	}
	if ((dir == LBM_CALL_DIR_EGRESS) ||
		(dir == LBM_CALL_DIR_INEGRESS)) {
		/* BPF */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_bpf_egress_db[subsys], entry) {
			res = BPF_PROG_RUN(p->bpf, pkt);
			if (res == LBM_RES_DROP)
				break;
		}
		rcu_read_unlock();
		if (res == LBM_RES_DROP)
			goto filter_pkt_early_ret;

		/* MOD */
		rcu_read_lock();
		hlist_for_each_entry_rcu(p, &lbm_mod_egress_db[subsys], entry) {
			res = p->lbm_hook(pkt);
			if (res == LBM_RES_DROP)
				break;
		}
		rcu_read_unlock();
	}

filter_pkt_early_ret:
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
		if (lbm_main_debug)
			pr_info("LBM: bpf [%s] added into bpf ingress db for subsys [%d]\n",
				p->bpf_name, p->bpf->aux->lbm_subsys_idx);
	}
	if ((prog->aux->lbm_call_dir == LBM_CALL_DIR_EGRESS) ||
		(prog->aux->lbm_call_dir == LBM_CALL_DIR_INEGRESS)) {
		spin_lock_irqsave(&lbm_bpf_egress_db_lock, flags);
		hlist_add_tail_rcu(&p->entry, &lbm_bpf_egress_db[prog->aux->lbm_subsys_idx]);
		spin_unlock_irqrestore(&lbm_bpf_egress_db_lock, flags);
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

	return 0;
}



/* sysfs */
static ssize_t lbm_sysfs_debug_read(struct file *filp,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	char tmp_buf[LBM_TMP_BUF_LEN];
	ssize_t len;

	len = scnprintf(tmp_buf, LBM_TMP_BUF_LEN, "main:%d\nbpf:%d\nusb:%d\n%"
			"bluetooth:%d\nnfc:%d\n",
			atomic_read(&lbm_main_debug),
			atomic_read(&lbm_bpf_debug),
			atomic_read(&lbm_usb_debug),
			atomic_read(&lbm_bluetooth_debug),
			atomic_read(&lbm_nfc_debug));
	return simple_read_from_buffer(buf, count, ppos, tmp_buf, len);
}

static const struct file_operations lbm_sysfs_debug_ops = {
	.read = lbm_sysfs_debug_read,
	.write = lbm_sysfs_debug_write,
	.llseek = generic_file_llseek,
};
static const struct file_operations lbm_sysfs_stats_ops;
static const struct file_operations lbm_sysfs_mod_ops;
static const struct file_operations lbm_sysfs_bpf_ingress_ops;
static const struct file_operations lbm_sysfs_bpf_egress_ops;
static const struct file_operations lbm_sysfs_mod_ingress_ops;
static const struct file_operations lbm_sysfs_mod_egress_ops;

int lbm_init_sysfs(void)
{
	lbm_sysfs_dir = securityfs_create_dir("lbm", NULL);
	if (IS_ERR(lbm_sysfs_dir))
		return -1;

	lbm_sysfs_debug = securityfs_create_file("debug", 0666, lbm_sysfs_dir,
				NULL, &lbm_sysfs_debug_ops);
	if (IS_ERR(lbm_sysfs_debug))
		goto init_sysfs_failed;

	lbm_sysfs_stats = securityfs_create_file("stats", 0444, lbm_sysfs_dir,
				NULL, &lbm_sysfs_stats_ops);
	if (IS_ERR(lbm_sysfs_stats))
		goto init_sysfs_failed;

	lbm_sysfs_mod = securityfs_create_file("modules", 0666, lbm_sysfs_dir,
				NULL, &lbm_sysfs_mod_ops);
	if (IS_ERR(lbm_sysfs_mod))
		goto init_sysfs_failed;

	lbm_sysfs_bpf_ingress = securityfs_create_file("bpf_ingress", 0666, lbm_sysfs_dir,
				NULL, &lbm_sysfs_bpf_ingress_ops);
	if (IS_ERR(lbm_sysfs_bpf_ingress))
		goto init_sysfs_failed;

	lbm_sysfs_bpf_egress = securityfs_create_file("bpf_egress", 0666, lbm_sysfs_dir,
				NULL, &lbm_sysfs_bpf_egress_ops);
	if (IS_ERR(lbm_sysfs_bpf_egress))
		goto init_sysfs_failed;

	lbm_sysfs_mod_ingress = securityfs_create_file("mod_ingress", 0666, lbm_sysfs_dir,
				NULL, &lbm_sysfs_mod_ingress_ops);
	if (IS_ERR(lbm_sysfs_mod_ingress))
		goto init_sysfs_failed;

	lbm_sysfs_mod_egress = securityfs_create_file("mod_egress", 0666, lbm_sysfs_dir,
				NULL, &lbm_sysfs_mod_egress_ops);
	if (IS_ERR(lbm_sysfs_mod_egress))
		goto init_sysfs_failed;

	return 0;

init_sysfs_failed:
	securityfs_remove(lbm_sysfs_debug);
	securityfs_remove(lbm_sysfs_stats);
	securityfs_remove(lbm_sysfs_mod);
	securityfs_remove(lbm_sysfs_bpf_ingress);
	securityfs_remove(lbm_sysfs_bpf_egress);
	securityfs_remove(lbm_sysfs_mod_ingress);
	securityfs_remove(lbm_sysfs_mod_egress);
	securityfs_remove(lbm_sysfs_dir);
	return -1;
}


/* init/exit */
void __init lbm_init(void)
{
	if (lbm_init_sysfs())
		pr_err("LBM initialization failed\n");
	else
		pr_info("LBM initialized\n");
}

void lbm_exit(void)
{
}
