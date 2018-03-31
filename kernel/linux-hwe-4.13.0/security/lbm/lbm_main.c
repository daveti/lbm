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
#include <linux/lbm.h>

#define LBM_SUB_SYS_NUM_MAX		16
#define LBM_MOD_NUM_MAX			16

/* Global vars */
static struct hlist_head lbm_bpf_ingress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_bpf_egress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_ingress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_egress_db[LBM_SUB_SYS_NUM_MAX];
static struct hlist_head lbm_mod_db[LBM_MOD_NUM_MAX];

static DEFINE_SPINLOCK(lbm_bpf_ingress_db_lock);
static DEFINE_SPINLOCK(lbm_bpf_egress_db_lock);
static DEFINE_SPINLOCK(lbm_mod_ingress_db_lock);
static DEFINE_SPINLOCK(lbm_mod_egress_db_lock);
static DEFINE_SPINLOCK(lbm_mod_db_lock);

struct lbm_bpf_mod_info{
	struct hlist_node entry;
	struct rcu_head rcu;
	struct bpf_prog *bpf;
	struct lbm_mod *mod;
	int (*lbm_hook)(void *pkt);
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

int lbm_register_mod(struct lbm_mod *mod)
{
}

void lbm_deregister_mod(struct lbm_mod *mod)
{
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
