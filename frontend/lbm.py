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
        if args[0].type == "DEC_NUMBER":
            return int(args[0])
        elif args[0].type == "HEX_NUMBER":
            return int(args[0], 16)
        else:
            raise ValueError("Unknown number subtype")

    def attribute(self, args):
        return str(args[1])

    def struct(self, args):
        identifier = ""

        if len(args) == 1:
            identifier = str(args[0])
        else:
            identifier = str(args[0]) + "." + args[1]

        symbol = lookup_symbol(identifier)

        if symbol is None:
            raise ValueError("Unknown symbol: " + identifier)

        return symbol

class CheckNumbers(Visitor):
    def number(self, tree):
        print "WOW", tree.children[0].type

class FlattenTree(Visitor):
    def comparison(self, tree):
        print "WOW", tree
    def logical_and(self, tree):
        print "AND", tree

def expressionize_tree(tree):
    for t in tree.iter_subtrees():
        if t.data == "comparison" or t.data == "logical_or" or t.data == "logical_and":
            # Force an order of operation using parens when a logical operation
            # has more than one pair of operands being used
            # Make the code generation stage easier to reason about
            while len(t.children) > 3:
                lhs = t.children[0]
                op = t.children[1]
                rhs = t.children[2]

                t.children = [Tree(t.data, [lhs, op, rhs])] + t.children[3:]

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
                else:
                    raise ValueError("Unsupported symbol type: %s" % type(lhs))

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

            # Lookup the temporary assignments for operands, if any
            if id(lhs) in tree_value:
                lhs = tree_value[id(lhs)]

            if id(rhs) in tree_value:
                rhs = tree_value[id(rhs)]

            # lookup the temporary variable destination
            assignment = tree_value[id(t)]

            # emit an assignment
            ir.append(IRAssign(assignment, IRBinop(op.type, lhs, rhs)))

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
        print("Raw Tree: " + str(tree))
        print("")

        print("Before: " + tree.pretty())
        print("")

    #dfs(tree)
    expressionize_tree(tree)

    tree = FlattenExpressions().transform(tree)
    tree = AtomToIntegral().transform(tree)
    #CheckNumbers().visit(tree)
    #FlattenTree().visit(tree)

    if debug:
        print("After: " + tree.pretty())

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
