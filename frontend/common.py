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

# gcc-like error messages
def generate_error_with_ctx(line, column, message, context, highlight_width=1):
    message = generate_error(line, column, message)
    message += " " + context + "\n"
    message += " " + " "*(column) + "^"*(highlight_width)

    return message

def generate_error(line, column, message):
    return "error:%d:%d: %s" % (line, column, message) + "\n"

def parse_lbm_dsl(parser, expression):
    try:
        tree = parser.parse(expression)
        return tree
    except lark.lexer.UnexpectedInput as e:
        lines = expression.split("\n")

        error = generate_error_with_ctx(e.line, e.column, "unknown character '%s'" % e.context[0], lines[e.line-1])

        raise ValueError(error)
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

        error = generate_error_with_ctx(e.line, e.column, error_message, lines[e.line-1],
                highlight_width=len(str(e.token)))

        raise ValueError(error)

