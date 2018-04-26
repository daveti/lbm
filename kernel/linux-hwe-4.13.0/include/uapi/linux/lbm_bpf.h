/*
 * lbm bpf header file the user space
 * Only used internally by uapi/linux/bpf.h
 * and crafting eBPF assembly manually
 * Apr 3, 2018
 * daveti
 * root@davejingtian.org
 */
#ifndef _UAPI__LINUX_LBM_BPF_H__
#define _UAPI__LINUX_LBM_BPF_H__

/* lbm defined bpf helpers */
#define __LBM_BPF_FUNC_MAPPER(FN)			\
	FN(lbm_usb_get_devnum),				\
	FN(lbm_usb_get_devpath_len),			\
	FN(lbm_usb_get_product_len),			\
	FN(lbm_usb_get_manufacturer_len),		\
	FN(lbm_usb_get_serial_len),			\
	FN(lbm_usb_devpath_load_bytes),			\
	FN(lbm_usb_product_load_bytes),			\
	FN(lbm_usb_manufacturer_load_bytes),		\
	FN(lbm_usb_serial_load_bytes),			\
	FN(lbm_usb_devpath_load_bytes_reg),		\
	FN(lbm_usb_product_load_bytes_reg),		\
	FN(lbm_usb_manufacturer_load_bytes_reg),	\
	FN(lbm_usb_serial_load_bytes_reg),		\
	FN(lbm_usb_setup_packet_load_bytes),		\
	FN(lbm_usb_transfer_buffer_load_bytes),		\
	FN(lbm_usb_get_bcdUSB),				\
	FN(lbm_usb_get_bDeviceClass),			\
	FN(lbm_usb_get_bDeviceSubClass),		\
	FN(lbm_usb_get_bDeviceProtocol),		\
	FN(lbm_usb_get_bMaxPacketSize0),		\
	FN(lbm_usb_get_idVendor),			\
	FN(lbm_usb_get_idProduct),			\
	FN(lbm_usb_get_bcdDevice),			\
	FN(lbm_usb_get_iManufacturer),			\
	FN(lbm_usb_get_iProduct),			\
	FN(lbm_usb_get_iSerialNumber),			\
	FN(lbm_usb_get_bNumConfigurations),		\
	FN(lbm_bluetooth_event_get_evt),		\
	FN(lbm_bluetooth_event_get_plen),		\
	FN(lbm_bluetooth_event_data_load_bytes),	\
	FN(lbm_bluetooth_acl_get_handle),		\
	FN(lbm_bluetooth_acl_get_flags),		\
	FN(lbm_bluetooth_acl_get_dlen),			\
	FN(lbm_bluetooth_acl_data_load_bytes),		\
	FN(lbm_bluetooth_sco_get_handle),		\
	FN(lbm_bluetooth_sco_get_flags),		\
	FN(lbm_bluetooth_sco_get_dlen),			\
	FN(lbm_bluetooth_sco_data_load_bytes),		\
	FN(lbm_bluetooth_command_get_ogf),		\
	FN(lbm_bluetooth_command_get_ocf),		\
	FN(lbm_bluetooth_command_get_plen),		\
	FN(lbm_bluetooth_command_data_load_bytes),

/* lbm defined user-space bpf contexts */
struct __lbm_usb {
	__u32 pipe;
	__u32 stream_id;
	__u32 status;
	__u32 transfer_flags;
	__u32 transfer_buffer_length;
	__u32 actual_length;
	__u32 setup_packet;
	__u32 start_frame;
	__u32 number_of_packets;
	__u32 interval;
	__u32 error_count;
};

struct __lbm_bluetooth {
	__u32 type;		/* Note that this is the pkt_type from cb rather than skb */
	__u32 len;		/* skb->len */
	__u32 prio;		/* skb->priority */
};

struct __lbm_bluetooth_l2cap {
	__u32 todo;
};

struct __lbm_nfc {
	__u32 todo;
};

#endif /* _UAPI__LINUX_LBM_BPF_H__ */
