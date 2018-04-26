import pprint
from ir import *

class Backend(object):
    pass

class RegisterAllocator():
    def __init__(self, registers):
        self.all_registers = registers
        self.available = []
        self.reserved = []

        # deepcopy list
        for reg in self.all_registers:
            self.available.append(reg)

    def _valid_register(self, register):
        return register in self.all_registers

    def reserve(self, register):
        if not self._valid_register(register):
            raise ValueError("Unknown register %s to reserve" % register)

        if register not in self.reserved:
            self.available.remove(register)
            self.reserved.append(register)
            return register
        else:
            raise ValueError("Cannot reserve %s: already reserved" % register)

    def reserve_any(self):
        if len(self.available) == 0:
            raise ValueError("Out of registers")

        return self.reserve(self.available[0])

    def release(self, register):
        if not self._valid_register(register):
            raise ValueError("Unknown register %s to reserve" % register)

        if register in self.reserved:
            self.available.append(register)
            self.reserved.remove(register)
        else:
            raise ValueError("Cannot release %s: not reserved" % register)

class CBackend(Backend):
    def __init__(self, ir, environment):
        self.ir = ir
        self.env = environment
        self.label_count = 0
        self.code = []

    def EMIT(self, label, insn):
        self.code += [[label, insn]]

    def new_label(self):
        self.label_count += 1
        return "L%d" % self.label_count

    def compile(self):
        reg = RegisterAllocator(["BPF_REG_6", "BPF_REG_7", "BPF_REG_8"])
        temp_map = {}

        def islive(variable, ir):
            for stmt in ir:
                if stmt.dst == variable:
                    return stmt

                if isinstance(stmt.src, IRBinop):
                    if stmt.src.lhs == variable:
                        return stmt
                    if stmt.src.rhs == variable:
                        return stmt

            return None

        # allocate registers (huehuehue)
        #print
        #print "register alloc"

        live_tmps = []
        for i, stmt in enumerate(self.ir):
            register_local = reg.reserve_any()
            dst = stmt.dst
            src = stmt.src

            temp_map[dst] = register_local

            live_tmps.append(dst)

            # Check if each temporary is still live from the current statement
            # Make sure to create a temporary list to allow removal of entries from the list
            for tmp in [x for x in live_tmps]:
                next_ref = islive(tmp, self.ir[i+1:])

                if next_ref is None:
                    live_tmps.remove(tmp)
                    reg.release(temp_map[tmp])
                    #print "%s is dead" % (tmp)

        #print temp_map

        #print
        #print "emit"

        # label (optional), insn
        self.EMIT("LSTART", "")

        # Save the context somewhere safe
        self.EMIT("", "BPF_MOV64_REG(BPF_REG_9, BPF_REG_1)")

        for stmt in self.ir:
            #print stmt

            dst = stmt.dst
            src = stmt.src
            tmp_ref = temp_map[dst]

            if isinstance(src, IRBinop):
                op = src.op

                if op == "EQ" or op == "NE" or op == "LT" or op == "LTE" or op == "GT" or op == "GTE":
                    lhs = src.lhs
                    rhs = src.rhs
                    jumpkind = ""

                    if op == "EQ":    jumpkind = "BPF_JEQ"
                    elif op == "NE":  jumpkind = "BPF_JNE"
                    elif op == "LT":  jumpkind = "BPF_JLT"
                    elif op == "LTE": jumpkind = "BPF_JLE"
                    elif op == "GT":  jumpkind = "BPF_JGT"
                    elif op == "GTE": jumpkind = "BPF_JGE"
                    else: assert 0

                    if isinstance(lhs, IRTemp) and isinstance(rhs, int):
                        tmp = temp_map[lhs]
                        label = self.new_label()

                        self.EMIT("", "BPF_MOV64_IMM(%s, 1)" % (tmp_ref))
                        self.EMIT("", "BPF_JMP_IMM(%s, %s, %d, %s)" % (jumpkind, tmp, rhs, label))
                        self.EMIT("", "BPF_MOV64_IMM(%s, 0)" % (tmp_ref))
                        self.EMIT(label, "")
                    elif isinstance(lhs, IRTemp) and isinstance(rhs, IRTemp):
                        tmp_lhs = temp_map[lhs]
                        tmp_rhs = temp_map[rhs]
                        label = self.new_label()

                        self.EMIT("", "BPF_MOV64_IMM(%s, 1)" % (tmp_ref))
                        self.EMIT("", "BPF_JMP_REG(%s, %s, %s, %s)" % (jumpkind, tmp_lhs, tmp_rhs, label))
                        self.EMIT("", "BPF_MOV64_IMM(%s, 0)" % (tmp_ref))
                        self.EMIT(label, "")
                    else:
                        raise ValueError("Unsupported operand combination for binop(EQ)")
                elif op == "AND":
                    lhs = src.lhs
                    rhs = src.rhs

                    lhs_temp = temp_map[lhs]
                    rhs_temp = temp_map[rhs]

                    self.EMIT("", "BPF_ALU64_REG(BPF_AND, %s, %s)" % (lhs_temp, rhs_temp))
                    self.EMIT("", "BPF_MOV64_REG(%s, %s)" % (tmp_ref, lhs_temp))
                elif op == "OR":
                    lhs = src.lhs
                    rhs = src.rhs

                    lhs_temp = temp_map[lhs]
                    rhs_temp = temp_map[rhs]

                    self.EMIT("", "BPF_ALU64_REG(BPF_OR, %s, %s)" % (lhs_temp, rhs_temp))
                    self.EMIT("", "BPF_MOV64_REG(%s, %s)" % (tmp_ref, lhs_temp))
                else:
                    raise ValueError("Unsupported binop: " + op)
            elif isinstance(src, IRLoadCtx):
                # This makes the assumption that BPF_REG_9 stores the context
                self.EMIT("", "BPF_LDX_MEM(BPF_W, %s, BPF_REG_9, %d)" % (tmp_ref, src.offset))
            elif isinstance(src, IRCall):
                # This makes the assumption that BPF_REG_9 stores the context
                # Restore the context for the function call
                self.EMIT("", "BPF_MOV64_REG(BPF_REG_1, BPF_REG_9)")
                self.EMIT("", "BPF_CALL_FUNC(BPF_FUNC_%s)" % (src.name))
                self.EMIT("", "BPF_MOV64_REG(%s, BPF_REG_0)" % (tmp_ref))
            # XXX: IRByteCmp is a leaky abstraction. The byte cmp should be
            # done entirely at the IR level, but our IR is too weak :'(
            elif isinstance(src, IRByteCmp):
                match_label = self.new_label()
                bad_label = self.new_label()
                end_procedure = self.new_label()

                # Get the length of the string to compare
                self.EMIT("", "BPF_MOV64_REG(BPF_REG_1, BPF_REG_9)")
                self.EMIT("", "BPF_CALL_FUNC(BPF_FUNC_%s)" % (src.length_fn))
                self.EMIT("", "BPF_MOV64_IMM(%s, %d)" % (tmp_ref, len(src.byte_string)))

                # string_len != byte_string_len -> goto out (fastpath)
                self.EMIT("", "BPF_JMP_REG(BPF_JNE, BPF_REG_0, %s, %s)" % (tmp_ref, bad_label))

                # Do we need to worry about endianess here?
                # Pad the byte string if necessary
                bytes_to_cmp = src.byte_string + "\x00"*(len(src.byte_string) % 8)

                # okay we have strings that match in length, lets compare them
                # for each set of 8-bytes
                for word_cnt in range(len(bytes_to_cmp)/8):
                    from struct import unpack

                    self.EMIT("", "BPF_MOV64_REG(BPF_REG_1, BPF_REG_9)")
                    self.EMIT("", "BPF_MOV64_IMM(BPF_REG_2, %d)" % (word_cnt*8))
                    self.EMIT("", "BPF_CALL_FUNC(BPF_FUNC_%s)" % (src.byte_fn))

                    chunk = unpack("<Q", bytes_to_cmp[word_cnt*8:(word_cnt+1)*8])[0]
                    self.EMIT("", "BPF_LD_IMM64(%s, 0x%016xUL)" % (tmp_ref, chunk))
                    self.EMIT("", "BPF_JMP_REG(BPF_JNE, BPF_REG_0, %s, %s)" % (tmp_ref, bad_label))

                self.EMIT(match_label, "BPF_MOV64_IMM(%s, 1)" % (tmp_ref))
                self.EMIT("", "BPF_JMP_A(%s)" % (end_procedure))
                self.EMIT(bad_label, "BPF_MOV64_IMM(%s, 0)" % (tmp_ref))
                self.EMIT(end_procedure, "")
            else:
                raise ValueError("Unsupported IR: " + str(type(src)));

        drop_packet = self.new_label()
        allow_packet = self.new_label()

        last_result = temp_map[self.ir[-1].dst]

        # if last_result != 0:
        #   goto drop
        # else:
        #   goto allow

        self.EMIT("", "BPF_JMP_IMM(BPF_JNE, %s, 0, %s)" % (last_result, drop_packet))
        self.EMIT(allow_packet, "BPF_MOV64_IMM(BPF_REG_0, 0)")
        self.EMIT("", "BPF_JMP_A(LEND)")
        self.EMIT(drop_packet, "BPF_MOV64_IMM(BPF_REG_0, 1)")

        # return code should be in R0
        self.EMIT("LEND", "BPF_EXIT_INSN()")

        return self.code

    def assemble(self, program):
        # pc, label, insn
        new_program = []

        # a map of labels to PC values
        labels = {}
        pc = 0

        # Pass 1: clean up instructions and label PC values
        for idx, insn in enumerate(program):
            insn[0] = insn[0].strip().rstrip()
            insn[1] = insn[1].strip().rstrip()

            # blank line
            if len(insn[0]) == 0 and len(insn[1]) == 0:
                continue

            # We have a label
            if len(insn[0]) > 0:
                if insn[0] in labels:
                    raise ValueError("Duplicate label found during assembly: %s" % insn[0])

                labels[insn[0]] = pc

            # We have an instruction
            if len(insn[1]) > 0:
                new_program.append(insn[1])
                pc += 1

        # Pass 2: replace labels with PC-relative values
        for pc in xrange(len(new_program)):
            insn = new_program[pc]

            # O(n^2) label replace
            for label, label_pc in labels.iteritems():
                pos = insn.find(label)

                if pos == -1:
                    continue

                delta = label_pc - pc
                
                if delta <= 0:
                    raise ValueError("PC-relative branch is negative or zero: address %d" % pc)

                new_program[pc] = insn.replace(label, str(delta))

        return new_program
