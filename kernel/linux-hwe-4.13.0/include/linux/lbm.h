/*
 * lbm.h
 * Header file used by LBM internals and modules
 * Mar 19, 2018
 * root@davejingtian.org
 * https://davejingtian.org
 */
#define LBM_MOD_NAME_LEN		32
#define LBM_SUBSYS_INDEX_USB		0
#define LBM_SUBSYS_INDEX_BLUETOOTH	1

struct lbm_mod{
	char name[LBM_MOD_NAME_LEN];
	int subsys_index;			/* The index value is used to deploy hooks for certain subsys */
	int (*lbm_frontend_hook)(void *buf);	/* The return value should be 0 or 1 - no others */
	int (*lbm_backend_hook)(void *pkt);
};

int lbm_register_mod(struct lbm_mod *mod);
void lbm_deregister_mod(struct lbm_mod *mod);
