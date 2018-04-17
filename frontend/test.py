import pprint
import lark
from lark import Lark, Transformer

l = Lark(open('lbm-dsl.g', 'r').read())

try:
    print( l.parse("abc.def[20:10]").pretty() )
    print( l.parse("1 == 2 && (10 >= 20 || 5)").pretty() )
    print( l.parse("(1 == 2 && 10 >= 1)").pretty() )
    print( l.parse("(usb.data == 10)").pretty() )
    print(l.parse("usb.data.asd[1:10] == 10").pretty())
except lark.lexer.UnexpectedInput as e:
    print e.message
