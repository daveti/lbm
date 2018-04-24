class IRExpr(object):
    pass

class IRStmt(object):
    pass

class IRTemp(IRExpr):
    def __init__(self, number=-1):
        self.number = number

    def __repr__(self):
        if self.number >= 0:
            return "t%d" % self.number
        else:
            return "temp"

class IRLoadCtx(IRExpr):
    def __init__(self, offset):
        self.offset = offset

    def __repr__(self):
        return "loadctx(%d)" % (self.offset)

# XXX: technically a call is a statement as it has side-effects on the program's state
# In our case, we dont have the concept of an IR basic block, meaning we need to consider
# a call as something that merely returns a value. Register allocation and clobbering must
# be handled by the backend code generation stage
class IRCall(IRExpr):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "call(%s)" % (self.name)

class IRBinop(IRExpr):
    def __init__(self, op, lhs, rhs):
        self.op = op
        self.lhs = lhs
        self.rhs = rhs

    def __repr__(self):
        return "binop(%s, %s, %s)" % (self.op, repr(self.lhs), repr(self.rhs))

class IRAssign(IRStmt):
    def __init__(self, dst, src):
        self.dst = dst
        self.src = src

    def __repr__(self):
        return "%s := %s" % (repr(self.dst), repr(self.src))

