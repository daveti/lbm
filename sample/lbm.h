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

#endif /* __LINUX_LBM_H__ */
