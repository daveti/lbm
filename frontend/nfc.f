# NFC nci

# u32
nfc.nci.len
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset(struct __lbm_nfc, len)),	/* ret value is saved into R2 */

nfc.nci.mt
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),	/* save the ctx */
	BPF_CALL_FUNC(BPF_FUNC_lbm_nfc_nci_get_mt),	/* nfc.nci.mt is returned into R0 */
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),	/* recover the ctx */
