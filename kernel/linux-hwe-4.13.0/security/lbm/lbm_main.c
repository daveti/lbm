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
#include <linux/lbm.h>

/* init/exit */
int lbm_init(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(lbm_init);

void lbm_exit(void)
{
}
EXPORT_SYMBOL_GPL(lbm_exit);
