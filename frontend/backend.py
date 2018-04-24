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
        reg = RegisterAllocator(["BPF_REG_6", "BPF_REG_7", "BPF_REG_8", "BPF_REG_9"])
        temp_map = {}

        def islive(variable, ir):
            for stmt in ir:
                if stmt.dst == variable:
                    return stmt
                if stmt.src.lhs == variable:
                    return stmt
                if stmt.src.rhs == variable:
                    return stmt

            return None

        # allocate registers (huehuehue)
        print
        print "register alloc"

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
                    print "%s is dead" % (tmp)

        print temp_map

        print
        print "emit"

        # label (optional), insn
        self.EMIT("LSTART", "")

        for stmt in self.ir:
            print stmt
            dst = stmt.dst
            src = stmt.src
            tmp_ref = temp_map[dst]

            if isinstance(src, IRBinop):
                op = src.op

                if op == "EQ":
                    if isinstance(src.lhs, str):
                        if src.lhs == "usb.iProduct":
                            self.EMIT("", "BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 20)")
                        elif src.lhs == "usb.iManufacturer":
                            self.EMIT("", "BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 30)")
                        else:
                            raise ValueError("Unsupported object: " + src.lhs)

                        imm = src.rhs
                        label = self.new_label()

                        self.EMIT("", "BPF_MOV64_IMM(%s, 1)" % (tmp_ref))
                        self.EMIT("", "BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, %d, %s)" % (imm, label))
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
            else:
                raise ValueError("Unsupported IR: " + src);

        self.EMIT("LEND", "")

        return self.code

    def assemble(self, program):
        pass
