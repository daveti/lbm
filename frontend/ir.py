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

