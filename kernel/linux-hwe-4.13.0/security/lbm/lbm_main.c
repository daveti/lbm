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
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/lbm.h>
#include "lbm_usb.h"

#define LBM_SUB_SYS_NUM_MAX		16
#define LBM_MOD_NUM_MAX			32	/* not used for now */
#define LBM_MOD_ACT_ADD			0
#define LBM_MOD_ACT_DEL			1

/* Global vars */
static struct hlist_head lbm_bpf_ingress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_bpf_egress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_ingress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_egress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_db;

static DEFINE_SPINLOCK(lbm_bpf_ingress_db_lock);
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
};

struct lbm_mod_info {
	struct hlist_node entry;
	struct lbm_mod *mod;
}

static int lbm_mod_num;
static int lbm_main_debug = 1;


/* BPF verifier operations per subsys */
const struct bpf_verifier_ops lbm_usb_prog_ops = {
	.get_func_proto         = lbm_usb_func_proto,
	.is_valid_access        = lbm_usb_is_valid_access,
	.convert_ctx_access     = lbm_usb_convert_ctx_access,
	.gen_prologue           = lbm_usb_prologue,
	.test_run               = lbm_usb_test_run_urb,
};


int lbm_filter_pkt(int subsys, int dir, void *pkt)
{
}

int lbm_find_prog_sub_type(struct bpf_prog *prog, int subsys, int dir)
{
}

int lbm_load_bpf_prog(struct bpf_prog *prog)
{
}


static int check_mod_subsys(int idx)
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
		pr_error("lbm-main: null mod in %s\n", __func__);
		return -1;
	}

	if (!check_mod_subsys(mod->subsys_index)) {
		pr_error("lbm-main: invalid subsys index [%d]\n", mod->subsys_index);
		return -1;
	}

	/* Make sure it is not in the list */
	if (find_mod_given_name(mod->name)) {
		pr_error("lbm-main: mod [%s] already exists\n", mod->name);
		return -1;
	}

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		pr_error("lbm-main: kmalloc failed for mod_info\n");
		return -ENOMEM;
	}
	p->mod = mod;

	/* Add this mod into DB */
	spin_lock_irqsave(&lbm_mod_db, flags);
	hlist_add_tail_rcu(&p->entry, &lbm_mod_db);
	lbm_mod_num++;
	spin_unlock_irqrestore(&lbm_mod_db, flags);
	if (lbm_main_debug)
		pr_info("lbm-main: mod [%s] added into the mod db\n", mod->name);

	/* Add into ingree and egree DBs */
	if (mod->lbm_ingress_hook) {
		q = kmalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			pr_error("lbm-main: kmalloc failed for bpf_mod_info on ingress\n");
			return -ENOMEM;
		}
		q->bpf = NULL;
		q->mod = mod;
		q->lbm_hook = mod->lbm_ingress_hook;

		spin_lock_irqsave(&lbm_mod_ingress_lock, flags);
		hlist_add_tail_rcu(&q->entry, &lbm_mod_ingress_db[mod->subsys_index]);
		spin_unlock_irqrestore(&lbm_mod_ingress_lock, flags);
		if (lbm_main_debug)
			pr_info("lbm-main: mod [%s] added into mod ingress db for subsys [%d]\n",
				mod->name, mod->subsys_index);
	}

	if (mod->lbm_egress_hook) {
		q = kmalloc(sizeof(*q), GFP_KERNEL);
		if (!q) {
			pr_error("lbm-main: kmalloc failed for bpf_mod_info on egress\n");
			return -ENOMEM;
		}
		q->bpf = NULL;
		q->mod = mod;
		q->lbm_hook = mod->lbm_egress_hook;

		spin_lock_irqsave(&lbm_mod_egress_lock, flags);
		hlist_add_tail_rcu(&q->entry, &lbm_mod_egress_db[mod->subsys_index]);
		spin_unlock_irqrestore(&lbm_mod_egress_lock, flags);
		if (lbm_main_debug)
			pr_info("lbm-main: mod [%s] added into mod egress db for subsys [%d]\n",
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
		pr_error("lbm-main: null mod in %s\n", __func__);
		return -1;
	}

	if (!check_mod_subsys(mod->subsys_index)) {
		pr_error("lbm-main: invalid subsys index [%d]\n", mod->subsys_index);
		return -1;
	}

	/* Make sure it is in the list */
	if (!find_mod_given_name(mod->name)) {
		pr_error("lbm-main: mod [%s] does not exists\n", mod->name);
		return -1;
	}

	/* Remove this mod from DB */
	spin_lock_irqsave(&lbm_mod_db, flags);
	hlist_for_each_entry_rcu(p, &lbm_mod_db, entry) {
		if (strncasecmp(p->mod->name, mod->name, LBM_MOD_NAME_LEN) == 0) {
			hlist_del_rcu(&p->entry);
			kfree_rcu(p, rcu);
			lbm_mod_num--;
			break;
		}
	}
	spin_unlock_irqrestore(&lbm_mod_db, flags);
	if (lbm_main_debug)
		pr_info("lbm-main: mod [%s] removed from mod db\n", mod->name);

	/* Remove this from ingress and egress DBs */
	if (mod->lbm_ingress_hook) {
		spin_lock_irqsave(&lbm_mod_ingress_db, flags);
		hlist_for_each_entry_rcu(q, &lbm_mod_ingress_db[mod->subsys_index], entry) {
			if (strncasecmp(q->mod->name, mod->name, LBM_MOD_NAME_LEN) == 0) {
				hlist_del_rcu(&q->entry);
				kfree_rcu(q, rcu);
				break;
			}
		}
		spin_unlock_irqrestore(&lbm_mod_ingress_db, flags);
		if (lbm_main_debug)
			pr_info("lbm-main: mod [%s] removed from mod ingress db for subsys [%d]\n",
				mod->name, mod->subsys_index);
	}

	if (mod->lbm_egress_hook) {
		spin_lock_irqsave(&lbm_mod_egress_db, flags);
		hlist_for_each_entry_rcu(q, &lbm_mod_egress_db[mod->subsys_index], entry) {
			if (strncasecmp(q->mod->name, mod->name, LBM_MOD_NAME_LEN) == 0) {
				hlist_del_rcu(&q->entry);
				kfree_rcu(q, rcu);
				break;
			}
		}
		spin_unlock_irqrestore(&lbm_mod_egress_db, flags);
		if (lbm_main_debug)
			pr_info("lbm-main: mod [%s] removed from mod egress db for subsys [%d]\n",
				mod->name, mod->subsys_index);
	}

	return 0;
}

/* init/exit */
int lbm_init(void)
{
	pr_info("lbm-main initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(lbm_init);

void lbm_exit(void)
{
}
EXPORT_SYMBOL_GPL(lbm_exit);
