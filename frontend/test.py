import pprint
import lark
from lark import Lark, Transformer

from common import *

testcases = [
"""
abc.def[20:10]
""",

"""
1 == 2 && (10 >= 20 || 5)
""",

"""
(1 == 2 && 10 >= 1)
""",

"""
(usb.data == 10)
""",

"""
usb.data.asd[1:10] == 10 *
""",

"""
usb.data.asd1:10] == 10
"""
]

def main():
    parser = load_grammar("lbm-dsl.g")

    for i, expression in enumerate(testcases):
        print("Test %d:" % (i+1))
        tree = parse_lbm_dsl(parser, expression)

        if tree is None:
            continue

        print(tree.pretty())

if __name__ == "__main__":
    main()
