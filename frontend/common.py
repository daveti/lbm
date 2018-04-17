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
        expected = e.expected
        error_message = ""

        # Make some error messages regarding parens a bit friendlier
        if len(expected) == 1:
            if expected[0] == "__RPAR":
                error_message = "expected ')'"
            elif expected[0] == "$END": # seen when extra RPAR
                if e.token == ")":
                    error_message = "extraneous ')' after condition"

        if error_message == "":
            error_message = "unexpected token '%s'" % str(e.token)

        print("error:%d:%d: %s" % (e.line, e.column, error_message))
        print(" " + lines[e.line-1])
        print(" " + " "*(e.column) + "^"*(len(str(e.token))))

    return None

