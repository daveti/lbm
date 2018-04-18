import pprint
import lark
from lark import Lark, Transformer, Tree
from lark.tree import Visitor

from common import *
from ir import *

# Post-order DFS
def dfs(t):
    for c in t.children:
        if isinstance(c, Tree):
            dfs(c)

    if t.data == "comparison" or t.data == "logical_or" or t.data == "logical_and":
        while len(t.children) > 3:
            lhs = t.children[0]
            op = t.children[1]
            rhs = t.children[2]

            t.children = [Tree(t.data, [lhs, op, rhs])] + t.children[3:]

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

    # TODO: handle accesses
    def struct(self, args):
        if len(args) == 1:
            return str(args[0])

        return str(args[0]) + "." + args[1]

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

def main():
    parser = load_grammar("lbm-dsl.g")

    expression = "(((((usb >= - 0x3) || (usb == (usb == (50 && 10))) ||(usb == 1))))) && usb == 2"
    #expression = "1 || 2 || 3"
    #expression = "(usb.productId[0:1] == 0xf00d && usb.mfg == \"test\")"

    tree = parse_lbm_dsl(parser, expression)

    if tree is None:
        return

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

    print("After: " + tree.pretty())

    ir = lbm_tree_to_ir(tree)

    print("")
    print("IR")
    lbm_print_ir(ir)



if __name__ == "__main__":
    main()
