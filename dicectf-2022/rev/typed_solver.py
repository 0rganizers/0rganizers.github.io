import parsy as P
from collections import namedtuple
import z3

Cons = namedtuple("Cons", "head tail")

def Oper(op, lhs, rhs):
    if op == "Add":
        return Eval(lhs) + Eval(rhs) # Not technically Eval, but good enough for constant values
    elif op == "Mult":
        return Eval(lhs) * Eval(rhs) # Not technically Eval, but good enough for constant values
    else:
        assert False, op

def isNil(x):
    return x is Nil or x == "Nil"

def isCons(x):
    return isinstance(x, Cons)

def Sum(x):
    if isNil(x.tail):
        return 0
    elif isCons(x.tail) and isNil(x.tail.tail):
        Eval(x.tail.head)
        return x.tail.head
    elif isCons(x.tail) and isCons(x.tail.tail):
        return Eval(Cons("Sum", Cons(Oper("Add", x.tail.head, x.tail.tail.head), x.tail.tail.tail)))
    else:
        assert False

def Prod(x):
    if isNil(x.tail):
        return 1
    elif isCons(x.tail) and isNil(x.tail.tail):
        Eval(x.tail.head)
        return x.tail.head
    elif isCons(x.tail) and isCons(x.tail.tail):
        return Eval(Cons("Prod", Cons(Oper("Mult", x.tail.head, x.tail.tail.head), x.tail.tail.tail)))
    else:
        assert False

def EvalBothAndSub(x):
    if isCons(x.tail) and isCons(x.tail.tail) and isNil(x.tail.tail.tail):
        X = Eval(x.tail.head)
        Y = Eval(x.tail.tail.head)
        solv.add(X > Y)
        return X - Y

def ApplyAll(x):
    if isCons(x.tail) and isNil(x.tail.tail):
        return Eval(x.tail.head)
    elif isCons(x.tail) and isCons(x.tail.tail):
        return Cons(x.tail.head, Eval(Cons("ApplyAll", x.tail.tail)))
    else:
        assert False

def WTF1(x):
    if isCons(x.tail) and isNil(x.tail.tail):
        return Eval(x.tail.head)
    elif isinstance(x.tail, Cons) and isinstance(x.tail.tail, Cons):
        Eval(x.tail.head)
        return Eval(Cons("WTF1", x.tail.tail))
    else:
        print(x)
        assert False

def AssertAllEqual(x):
    if isCons(x.tail) and isNil(x.tail.tail):
        return 0
    elif isCons(x.tail) and isCons(x.tail.tail):
        t = Eval(x.tail.head)
        u = Eval(x.tail.tail.head)
        solv.add(u == t)
        return Eval(Cons("AssertAllEqual", Cons(x.tail.tail.head, x.tail.tail.tail)))

def AssertNotEqual(x):
    if isCons(x.tail) and isCons(x.tail.tail) and isNil(x.tail.tail.tail):
        solv.add(Eval(x.tail.head) != Eval(x.tail.tail.head))
        return 0
    else:
        assert False

def Map(x):
    if isCons(x.tail) and isNil(x.tail.tail):
        return Nil
    elif isCons(x.tail) and isCons(x.tail.tail):
        s = x.tail.head
        w = x.tail.tail.head
        t = x.tail.tail.tail
        return Cons(Eval(Cons(s, Cons(w, Nil))), Eval(Cons("Map", Cons(s, t))))
    else:
        assert False

def WeirdEquals(x):
    if isCons(x.tail) and isNil(x.tail.tail):
        sxyt = x.tail.head
        if isCons(sxyt.tail) and isCons(sxyt.tail.tail):
            s = sxyt.head
            x = sxyt.tail.head
            yt = sxyt.tail.tail
            if isCons(yt.tail) and isNil(yt.tail.tail):
                y = yt.head
                t = yt.tail.head
                return Cons("AssertAllEqual", Cons(Cons(s, Cons(x, Cons(y, Nil))), Cons(t, Nil)))
    assert False

def WeirdNotEquals(x):
    if isCons(x.tail) and isNil(x.tail.tail):
        sxyt = x.tail.head
        if isCons(sxyt.tail) and isCons(sxyt.tail.tail):
            s = sxyt.head
            x = sxyt.tail.head
            yt = sxyt.tail.tail
            if isCons(yt.tail) and isNil(yt.tail.tail):
                y = yt.head
                t = yt.tail.head
                return Cons("AssertNotEqual", Cons(Cons(s, Cons(x, Cons(y, Nil))), Cons(t, Nil)))
    assert False


def EveryThird(x):
    if isNil(x.tail):
        return Nil
    elif isCons(x.tail) and isCons(x.tail.tail) and isCons(x.tail.tail.tail):
        return Cons(x.tail.head, Eval(Cons("EveryThird", x.tail.tail.tail.tail)))
    else:
        assert False

def SkipEveryThird(x):
    if isNil(x.tail):
        return Nil
    elif isCons(x.tail) and isCons(x.tail.tail) and isCons(x.tail.tail.tail):
        return Cons(x.tail.tail.head, Cons(x.tail.tail.tail.head, Eval(Cons("SkipEveryThird", x.tail.tail.tail.tail))))
    else:
        assert False

def Apply(x):
    if isinstance(x.tail, Cons) and isinstance(x.tail.tail, Cons) and isNil(x.tail.tail.tail):
        s = x.tail.head
        t = x.tail.tail.head
        return Eval(Cons(s, Eval(t)))
    else:
        assert False

def Eval(x):
    if x in numbers:
        return numbers[x]
    if x in lits:
        return lits[x]
    if isinstance(x, int):
        return x
    if isinstance(x, str) and x.startswith("Flag"):
        return Flag[int(x[4:])]
    if isinstance(x, z3.ExprRef):
        return x
    assert isinstance(x, Cons)
    return Eval(x.head)(x)

numbers = {
        "Zero": 0,
        "One": 1,
        "Two": 2,
        "Three": 3,
        "Four": 4,
        "Five": 5,
        "Six": 6,
        "Seven": 7,
        "Eight": 8,
        "Nine": 9,
        "Ten": 10,
        "Hundred": 100,
        }
Nil = object()
lits = {x: eval(x) for x in "Sum Prod EvalBothAndSub ApplyAll WTF1 AssertAllEqual AssertNotEqual Map WeirdEquals WeirdNotEquals EveryThird SkipEveryThird Apply Nil".split()}

def parse(v):
    pExpr = P.forward_declaration()

    @P.generate
    def pCons():
        yield P.string("Cons<")
        head = yield pExpr
        yield P.string(",")
        tail = yield pExpr
        yield P.string(">")
        return Cons(head, tail)

    @P.generate
    def pOper():
        yield P.string("<")
        lhs = yield pExpr
        yield P.string("as")
        op = yield P.string("Add") | P.string("Mult") | P.string("SubAndAssertPositive") | P.string("NotEqual")
        yield P.string("<")
        rhs = yield pExpr
        yield P.string(">>::Result")
        return Oper(op, lhs, rhs)


    literals = [P.string(x) for x in numbers.keys()] + [
                P.string(f"Flag{i}") for i in range(26)
            ][::-1] + [
                P.string(x) for x in lits.keys()
            ]
    pLit = literals[0]
    for n in literals[1:]: pLit |= n

    pExpr.become(pCons | pOper | pLit)
        
    v = v.replace(" ", "").replace("\n", "").replace("\t", "")
    return pExpr.parse(v)

checkVal = "Cons < Cons < Sum , Cons < Flag11 , Cons < Flag13 , Cons < < < Ten as Mult < Two > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag1 , Cons < Flag9 , Cons < < < Ten as Mult < Two > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag4 , Cons < < < Ten as Mult < One > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag0 , Cons < Flag5 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag3 , Cons < Flag16 , Cons < < < Ten as Mult < Two > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag12 , Cons < Flag11 , Cons < < < Ten as Mult < Two > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag18 , Cons < Flag17 , Cons < Zero , Nil > > > > , Cons < Cons < Prod , Cons < Flag20 , Cons < Flag11 , Cons < Zero , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag5 , Cons < Flag9 , Cons < Five , Nil > > > > , Cons < Cons < Prod , Cons < Flag2 , Cons < Flag4 , Cons < Five , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag0 , Cons < Flag15 , Cons < < < Ten as Mult < One > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag8 , Cons < Flag24 , Cons < < < Ten as Mult < One > > :: Result as Add < Five > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag11 , Cons < Flag7 , Cons < < < Ten as Mult < Three > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag14 , Cons < Flag21 , Cons < < < Ten as Mult < Two > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag4 , Cons < Flag16 , Cons < Zero , Nil > > > > , Cons < Cons < Prod , Cons < Flag21 , Cons < Flag3 , Cons < < < Ten as Mult < Four > > :: Result as Add < Nine > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag24 , Cons < Flag16 , Cons < Four , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag3 , Cons < Flag0 , Cons < Four , Nil > > > > , Cons < Cons < Sum , Cons < Flag11 , Cons < Flag10 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag7 , Cons < Flag15 , Cons < < < Ten as Mult < Two > > :: Result as Add < One > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag18 , Cons < Flag5 , Cons < < < Ten as Mult < Three > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag18 , Cons < Flag11 , Cons < Five , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag7 , Cons < Flag21 , Cons < < < Ten as Mult < Two > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag13 , Cons < Flag18 , Cons < < < Hundred as Mult < Three > > :: Result as Add < < < Ten as Mult < Four > > :: Result as Add < One > > :: Result > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag15 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag19 , Cons < Flag23 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag14 , Cons < Flag20 , Cons < < < Ten as Mult < Four > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag21 , Cons < Flag4 , Cons < < < Ten as Mult < One > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag10 , Cons < Flag2 , Cons < < < Ten as Mult < Three > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag10 , Cons < < < Ten as Mult < One > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag17 , Cons < Flag0 , Cons < < < Hundred as Mult < Two > > :: Result as Add < < < Ten as Mult < One > > :: Result as Add < Nine > > :: Result > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag22 , Cons < Flag23 , Cons < < < Ten as Mult < Two > > :: Result as Add < One > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag15 , Cons < Flag18 , Cons < < < Ten as Mult < Eight > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag12 , Cons < Flag6 , Cons < < < Ten as Mult < Four > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag22 , Cons < Flag24 , Cons < < < Ten as Mult < Nine > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag0 , Cons < Flag23 , Cons < < < Ten as Mult < Six > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag0 , Cons < Flag5 , Cons < < < Hundred as Mult < Four > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag8 , Cons < Flag11 , Cons < < < Ten as Mult < One > > :: Result as Add < Nine > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag19 , Cons < Flag13 , Cons < < < Ten as Mult < Four > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag7 , Cons < Flag12 , Cons < < < Ten as Mult < One > > :: Result as Add < One > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag17 , Cons < Flag22 , Cons < < < Hundred as Mult < Two > > :: Result as Add < < < Ten as Mult < Four > > :: Result as Add < Zero > > :: Result > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag16 , Cons < Flag14 , Cons < < < Ten as Mult < Two > > :: Result as Add < Nine > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag24 , Cons < Flag18 , Cons < < < Ten as Mult < One > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag19 , Cons < Flag4 , Cons < < < Ten as Mult < One > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag24 , Cons < Flag3 , Cons < < < Ten as Mult < Three > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag0 , Cons < Flag16 , Cons < < < Ten as Mult < One > > :: Result as Add < Two > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag10 , Cons < Flag5 , Cons < < < Ten as Mult < Seven > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag19 , Cons < Two , Nil > > > > , Cons < Cons < Prod , Cons < Flag12 , Cons < Flag16 , Cons < Five , Nil > > > > , Cons < Cons < Prod , Cons < Flag24 , Cons < Flag12 , Cons < < < Hundred as Mult < One > > :: Result as Add < < < Ten as Mult < One > > :: Result as Add < Two > > :: Result > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag24 , Cons < Flag16 , Cons < Four , Nil > > > > , Cons < Cons < Sum , Cons < Flag12 , Cons < Flag15 , Cons < < < Ten as Mult < Four > > :: Result as Add < Five > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag1 , Cons < Flag20 , Cons < < < Ten as Mult < Two > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag1 , Cons < Flag17 , Cons < < < Ten as Mult < Two > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag5 , Cons < Flag11 , Cons < < < Ten as Mult < Two > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag5 , Cons < Flag18 , Cons < Eight , Nil > > > > , Cons < Cons < Sum , Cons < Flag16 , Cons < Flag22 , Cons < < < Ten as Mult < Two > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag14 , Cons < Flag3 , Cons < < < Hundred as Mult < Seven > > :: Result as Add < < < Ten as Mult < Four > > :: Result as Add < Seven > > :: Result > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag6 , Cons < Flag21 , Cons < < < Ten as Mult < Four > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag6 , Cons < Flag22 , Cons < < < Ten as Mult < Four > > :: Result as Add < Eight > > :: Result , Nil > > > > , Nil > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > "

solv = z3.Solver()
Flag = [z3.Int(f"Flag{i}") for i in range(26)]
for f in Flag:
    solv.add(f >= 0)
    solv.add(f <= 36)

cond3 = "Cons< Apply, Cons< Map, Cons<Cons<ApplyAll, Cons<WeirdNotEquals, Cons<Cons<EveryThird, weirdVal>, Nil>>>, Nil> > >".replace("weirdVal", checkVal)
cond2 = "Cons< Apply, Cons< Map, Cons<Cons<ApplyAll, Cons<WeirdEquals, Cons<Cons<SkipEveryThird, weirdVal>, Nil>>>, Nil> > >".replace("weirdVal", checkVal)
cond1 = parse("Cons< WTF1, Cons< Cons<Apply, Cons<WTF1, Cons<Cond3, Nil>>>, Cons<Cons<Apply, Cons<WTF1, Cons<Cond2, Nil>>>, Nil> > >".replace("Cond3", cond3).replace("Cond2", cond2))
print(Eval(cond1))
print(solv.check())
print(solv.model())
