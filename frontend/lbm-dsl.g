// A valid program must be an expression or the empty string
start: expression?
?expression: test
?test : logical_or

?logical_or : logical_and (OR logical_and)*
?logical_and : comparison (AND comparison)*
?comparison : atom (cmp_op atom)*
?cmp_op : LT | GT | LTE | GTE | EQ | NE

access : LBRACKET number COLON number RBRACKET
?attribute : "." IDENTIFIER
number : DEC_NUMBER | HEX_NUMBER

struct : IDENTIFIER (attribute)* access?
string : STRING
?atom : number
      | "-" number
      | struct
      | string
      | "(" expression ")"

// Tokens
LBRACKET : "["
RBRACKET : "]"
COLON : ":"
DOT : "."

AND : "&&"
OR : "||"

NE : "!="
EQ : "=="
LT : "<"
GT : ">"
GTE : ">="
LTE : "<="

// Support C++ style and Python style comments
COMMENT: /(\/\/|#)[^\n]*/
NEWLINE: ( /\r?\n[\t ]*/ | COMMENT )+

DEC_NUMBER: /[0-9]\d*/i
HEX_NUMBER: /0x[\da-f]*/i

%import common.CNAME -> IDENTIFIER
%import common.ESCAPED_STRING -> STRING

// Ignores comments, newlines, and any whitespace
%ignore NEWLINE
%ignore /[\t \f]+/ // Whitespace
