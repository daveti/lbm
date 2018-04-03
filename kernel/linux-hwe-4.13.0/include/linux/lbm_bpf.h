/*
 * lbm bpf header file the user space
 * Only used internally by uapi/linux/bpf.h
 * Apr 3, 2018
 * root@davejingtian.org
 */
#ifndef __LINUX_LBM_BPF_H__
#define __LINUX_LBM_BPF_H__

/* lbm defined bpf helpers */
#define __LBM_BPF_FUNC_MAPPER(FN)		\
	FN(lbm_usb_get_devnum),			\
	FN(lbm_usb_get_devpath),		\
	FN(lbm_usb_get_product),		\
	FN(lbm_usb_get_manufacturer),		\
	FN(lbm_usb_get_serial),			\
	FN(lbm_usb_get_pipe),			\
	FN(lbm_usb_get_status),			\
	FN(lbm_usb_get_transfer_buffer_length),	\
	FN(lbm_usb_get_actual_length),		\
	FN(lbm_usb_load_setup_packet),		\
	FN(lbm_usb_load_transfer_buffer),		

#endif /* __LINUX_LBM_BPF_H__ */
