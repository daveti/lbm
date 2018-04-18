import pprint
import lark
from lark import Lark, Transformer, Tree
from lark.tree import Visitor

from common import *

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
    def logical_or(self, args):
        print "XXX", args
        return args[0]

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
            while len(t.children) > 3:
                lhs = t.children[0]
                op = t.children[1]
                rhs = t.children[2]

                t.children = [Tree(t.data, [lhs, op, rhs])] + t.children[3:]

def lbm_tree_to_ir(tree):
    ir = []
    temp = 0
    tree_value = {}

    for t in tree.iter_subtrees():
        #print "XX", t

        if id(t) not in tree_value and t.data != "number":
            tree_value[id(t)] = temp
            temp += 1

        if t.data == "comparison" or t.data == "logical_or" or t.data == "logical_and":
            lhs = t.children[0]
            op = t.children[1]
            rhs = t.children[2]

            # Lookup the temporaries for previous expressions
            if id(lhs) in tree_value:
                lhs = tree_value[id(lhs)]

            if id(rhs) in tree_value:
                rhs = tree_value[id(rhs)]

            if isinstance(lhs, Tree) and lhs.data == "number":
                lhs = lhs.children[0]
            if isinstance(rhs, Tree) and rhs.data == "number":
                rhs = rhs.children[0]

            assignment = tree_value[id(t)]

            ir.append([assignment, lhs, op, rhs])
            #ops.append([assignment2, assignment, op, rhs])

    return ir

def lbm_print_ir(ir):
    for stmt_id, stmt in enumerate(ir):
        destination = "t%d" % stmt[0]
        op = "%s" % stmt[2].type
        lhs = stmt[1]
        rhs = stmt[3]

        if isinstance(lhs, int):
            lhs = "t%d" % lhs
        else:
            lhs = str(lhs)

        if isinstance(rhs, int):
            rhs = "t%d" % rhs
        else:
            rhs = str(rhs)

        print "%d: %s <- binop(%-3s, %s, %s)" % (stmt_id, destination, op, lhs, rhs)

def main():
    parser = load_grammar("lbm-dsl.g")

    #expression = "(((((usb >= - 0x3) || (usb == (usb == (50 && 10))) ||(usb == 1))))) && usb == 2"
    #expression = "1 || 2 || 3"
    expression = "(usb.productId == 0xf00d)"

    tree = parse_lbm_dsl(parser, expression)

    if tree is None:
        return

    print("Raw Tree: " + str(tree))
    print("")

    print("Before: " + tree.pretty())
    print("")

    #dfs(tree)
    expressionize_tree(tree)

    #tree = FlattenExpressions().transform(tree)
    #CheckNumbers().visit(tree)
    #FlattenTree().visit(tree)

    print("AFTER: " + tree.pretty())

    ir = lbm_tree_to_ir(tree)
    lbm_print_ir(ir)

    print("")
    print("IR")


if __name__ == "__main__":
    main()
