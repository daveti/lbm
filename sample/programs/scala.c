
#include "libbpf.h"

const char * prog_name = "../sample/programs/scala";
const char * prog_source_file = "../eval/scala.l";
unsigned int prog_subsystem = 0; // Subsystem code (LBM kernel ABI)
const char * prog_expr = "# Scalability for lbm rules\n"
"usb.serial == \"7777\"\n"
"\n"; // Original LBM rule expression
const char * prog_original = "BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),\n"
"BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),\n"
"BPF_CALL_FUNC(BPF_FUNC_lbm_usb_get_serial_len),\n"
"BPF_MOV64_IMM(BPF_REG_1, 4),\n"
"BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 8),\n"
"BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),\n"
"BPF_MOV64_IMM(BPF_REG_2, 0),\n"
"BPF_CALL_FUNC(BPF_FUNC_lbm_usb_serial_load_bytes_reg),\n"
"BPF_LD_IMM64(BPF_REG_1, 0x0000000037373737UL),\n"
"BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 2),\n"
"BPF_MOV64_IMM(BPF_REG_1, 1),\n"
"BPF_JMP_A(1),\n"
"BPF_MOV64_IMM(BPF_REG_1, 0),\n"
"BPF_MOV64_IMM(BPF_REG_2, 1),\n"
"BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 1),\n"
"BPF_MOV64_IMM(BPF_REG_2, 0),\n"
"BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 0, 2),\n"
"BPF_MOV64_IMM(BPF_REG_0, 0),\n"
"BPF_EXIT_INSN(),\n"
"BPF_MOV64_IMM(BPF_REG_0, 1),\n"
"BPF_EXIT_INSN(),\n"; // C BPF assembly

struct bpf_insn prog[] = {
BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),
BPF_CALL_FUNC(BPF_FUNC_lbm_usb_get_serial_len),
BPF_MOV64_IMM(BPF_REG_1, 4),
BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 8),
BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),
BPF_MOV64_IMM(BPF_REG_2, 0),
BPF_CALL_FUNC(BPF_FUNC_lbm_usb_serial_load_bytes_reg),
BPF_LD_IMM64(BPF_REG_1, 0x0000000037373737UL),
BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_1, 2),
BPF_MOV64_IMM(BPF_REG_1, 1),
BPF_JMP_A(1),
BPF_MOV64_IMM(BPF_REG_1, 0),
BPF_MOV64_IMM(BPF_REG_2, 1),
BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 1),
BPF_MOV64_IMM(BPF_REG_2, 0),
BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 0, 2),
BPF_MOV64_IMM(BPF_REG_0, 0),
BPF_EXIT_INSN(),
BPF_MOV64_IMM(BPF_REG_0, 1),
BPF_EXIT_INSN(),
};

unsigned int prog_size = sizeof(prog)/sizeof(struct bpf_insn); 