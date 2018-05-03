import pprint
import lark
from lark import Lark, Transformer, Tree
from lark.tree import Visitor

import common
from ir import *
from backend import *
from symbol import *

class FlattenExpressions(Transformer):
    def atom(self, args):
        return args[0]

class AtomToIntegral(Transformer):
    def number(self, args):
        number = Number(0)

        if args[0].type == "DEC_NUMBER":
            number.value = int(args[0])
        elif args[0].type == "HEX_NUMBER":
            number.value = int(args[0], 16)
        else:
            raise ValueError("Unknown number subtype")

        if number.value < 0:
            e = args[0]
            error = common.generate_error(e.line, e.column, "signed-integers not supported")
            raise ValueError(error)

        if number.value & (2**64-1) != number.value:
            e = args[0]
            error = common.generate_error(e.line, e.column, "integer is beyond the maximum integral type (64-bits)")
            raise ValueError(error)

        return number

    def string(self, args):
        return str(args[0])[1:-1]

    def attribute(self, args):
        return args[1]

    def struct(self, args):
        identifier = ".".join(args)
        symbol = lookup_symbol(identifier)

        if symbol is None:
            e = args[0]
            error = common.generate_error(e.line, e.column, "unknown symbol '%s'" % identifier)
            raise ValueError(error)

        return symbol

class CanonicalizeTree(Transformer):
    def comparison(self, args):
        assert len(args) == 3

        if args[0].data == "number" and args[2].data == "struct":
            return Tree("comparison", args[::-1])
        else:
            return Tree("comparison", args)

class ExpressionizeTree(Transformer):
    def comparison(self, args):
        return self.handle(Tree("comparison", args))

    def logical_or(self, args):
        return self.handle(Tree("logical_or", args))

    def logical_and(self, args):
        return self.handle(Tree("logical_and", args))

    def handle(self, tree):
        # Force an order of operation using parens when a logical operation
        # has more than one pair of operands being used
        # Make the code generation stage easier to reason about
        while len(tree.children) > 3:
            lhs = tree.children[0]
            op = tree.children[1]
            rhs = tree.children[2]

            tree.children = [Tree(tree.data, [lhs, op, rhs])] + tree.children[3:]

        return tree

def lbm_tree_to_ir(tree):
    ir = []
    tree_value = {}
    temp_count = 0

    for t in tree.iter_subtrees():
        # Create temporaries for all tree roots
        if id(t) not in tree_value and t.data != "number":
            tree_value[id(t)] = IRTemp(temp_count)
            temp_count += 1

        if t.data == "comparison" or t.data == "logical_or" or t.data == "logical_and":
            lhs = t.children[0]
            op = t.children[1]
            rhs = t.children[2]

            if isinstance(lhs, Symbol):
                if isinstance(lhs, SymbolContext):
                    lhs_tmp = IRTemp(temp_count)
                    temp_count += 1

                    ir.append(IRAssign(lhs_tmp, IRLoadCtx(lhs.offset)))
                    lhs = lhs_tmp
                elif isinstance(lhs, SymbolHelper):
                    lhs_tmp = IRTemp(temp_count)
                    temp_count += 1

                    ir.append(IRAssign(lhs_tmp, IRCall(lhs.name)))
                    lhs = lhs_tmp
                elif isinstance(lhs, SymbolString):
                    assignment = tree_value[id(t)]

                    lhs_tmp = IRTemp(temp_count)
                    temp_count += 1

                    # special case
                    ir.append(IRAssign(lhs_tmp, IRByteCmp(lhs.length, lhs.load, rhs)))
                    ir.append(IRAssign(assignment, IRBinop(op.type, lhs_tmp, 1)))
                    continue
                else:
                    raise ValueError("Unsupported symbol type: %s" % type(lhs))
            elif isinstance(lhs, Number):
                if lhs.value > (2**32-1):
                    lhs_tmp = IRTemp(temp_count)
                    temp_count += 1

                    ir.append(IRAssign(lhs_tmp, lhs))
                    lhs = lhs_tmp

            if isinstance(rhs, Symbol):
                if isinstance(rhs, SymbolContext):
                    rhs_tmp = IRTemp(temp_count)
                    temp_count += 1

                    ir.append(IRAssign(rhs_tmp, IRLoadCtx(rhs.offset)))
                    rhs = rhs_tmp
                elif isinstance(rhs, SymbolHelper):
                    rhs_tmp = IRTemp(temp_count)
                    temp_count += 1

                    ir.append(IRAssign(rhs_tmp, IRCall(rhs.name)))
                    rhs = rhs_tmp
                else:
                    raise ValueError("Unsupported symbol type: %s" % type(rhs))
            elif isinstance(rhs, Number):
                if rhs.value > (2**32-1):
                    rhs_tmp = IRTemp(temp_count)
                    temp_count += 1

                    ir.append(IRAssign(rhs_tmp, rhs))
                    rhs = rhs_tmp

            # Lookup the temporary assignments for operands, if any
            if id(lhs) in tree_value:
                lhs = tree_value[id(lhs)]

            if id(rhs) in tree_value:
                rhs = tree_value[id(rhs)]

            # lookup the temporary variable destination
            assignment = tree_value[id(t)]

            # emit an assignment
            ir.append(IRAssign(assignment, IRBinop(op.type, lhs, rhs)))
        elif t.data =="start":
            if len(t.children) == 0:
                error = common.generate_error(1, 0, "empty program with no expressions")
                raise ValueError(error)
            elif not isinstance(t.children[0], Tree):
                error = common.generate_error(1, 0, "cannot convert bare integral value to truth value")
                raise ValueError(error)
        else:
            raise ValueError("lbm_tree_to_ir: unable to convert %s to IR" % str(t))

    return ir

def lbm_print_ir(ir):
    for stmt_id, stmt in enumerate(ir):
        print "%d: %s" % (stmt_id, stmt)

def parse_and_assemble(expression, debug):
    parser = common.load_grammar("lbm-dsl.g")

    tree = common.parse_lbm_dsl(parser, expression)

    # We got a parse error
    if tree is None:
        return

    if debug:
        print("Before: \n" + tree.pretty())
        print("")

    tree = ExpressionizeTree().transform(tree)
    tree = FlattenExpressions().transform(tree)
    tree = CanonicalizeTree().transform(tree)

    # Should be performed last
    tree = AtomToIntegral().transform(tree)

    if debug:
        print("After transformations: \n" + tree.pretty())

    ir = lbm_tree_to_ir(tree)

    if debug:
        print("")
        print("IR")
        lbm_print_ir(ir)

    ## Generate code

    backend = CBackend(ir, {})
    code = backend.compile()

    if debug:
        pprint.pprint(code)

    program = backend.assemble(code)

    # Print the program with replaced labels
    for pc, insn in enumerate(program):
        print "%s," % (insn)

if __name__ == "__main__":
    #expression = "usb.idProduct == 0xf00d && usb.idVendor == 1234 && usb.actual_length == 33 "
    expression = "usb.idProduct == 0xf00d && usb.idVendor == 1234 && usb.idProduct == 5 && usb.idVendor == 0xffffffff && usb.idVendor == 0xffffffff"
    #expression = "40 == usb.actual_length || usb.pipe == 1 && usb.status == 50 || usb.transfer_flags == 0|| usb.transfer_flags == 0&& usb.transfer_flags == 0&& usb.transfer_flags == 0"
    #expression = "(((((usb >= - 0x3) || (usb == (usb == (50 && 10))) ||(usb == 1))))) && usb == 2"
    #expression = "1 || 2 || 3"
    #expression = "(usb.productId[0:1] == 0xf00d && usb.mfg == \"test\")"

    parse_and_compile(expression)
