import lark
from lark import Lark

def load_grammar(filename):
    try:
        with open(filename, 'r') as fp:
            try:
                parser = Lark(fp.read(), parser="lalr")
                return parser
            except lark.common.ParseError as e:
                raise ValueError("Parsing error for \"%s\": %s" % (filename, e.message))
    except IOError:
        raise

def parse_lbm_dsl(parser, expression):
    try:
        tree = parser.parse(expression)
        return tree
    except lark.lexer.UnexpectedInput as e:
        lines = expression.split("\n")

        # gcc-like error messages
        print("error:%d:%d: unknown character '%s'" % (e.line, e.column, e.context[0]))
        print(" " + lines[e.line-1])
        print(" " + " "*(e.column) + "^")
    except lark.common.UnexpectedToken as e:
        lines = expression.split("\n")

        print("error:%d:%d: unexpected token '%s'" % (e.line, e.column, e.token))
        print(" " + lines[e.line-1])
        print(" " + " "*(e.column) + "^"*(len(str(e.token))))

    return None

