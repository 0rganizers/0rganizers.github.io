#![recursion_limit = "10000"]
use std::marker::PhantomData;
struct Succ<T>(PhantomData<T>);
struct Zero;

type One = Succ<Zero>;
type Two = Succ<One>;
type Three = Succ<Two>;
type Four = Succ<Three>;
type Five = Succ<Four>;
type Six = Succ<Five>;
type Seven = Succ<Six>;
type Eight = Succ<Seven>;
type Nine = Succ<Eight>;
type Ten = Succ<Nine>;

trait Add<V> {
    type Result;
}

impl<T> Add<Zero> for T {
    type Result = T;
}

impl<T, U> Add<Succ<U>> for T
where
    T: Add<U>,
{
    type Result = Succ<<T as Add<U>>::Result>;
}


trait Mult<V> {
    type Result;
}

impl<T> Mult<Zero> for T {
    type Result = Zero;
}

impl<T, U> Mult<Succ<U>> for T
where
    T: Mult<U>,
    T: Add<<T as Mult<U>>::Result>,
{
    type Result = <T as Add<<T as Mult<U>>::Result>>::Result;
}


trait SubAndAssertPositive<V> {
    type Result;
}

impl<T> SubAndAssertPositive<Zero> for T {
    type Result = T;
}

impl<T, U> SubAndAssertPositive<Succ<U>> for Succ<T>
where
    T: SubAndAssertPositive<U>,
{
    type Result = <T as SubAndAssertPositive<U>>::Result;
}


trait NotEqual<V> {
    type Result;
}

impl NotEqual<Zero> for Zero {
    type Result = Zero;
}

impl<T> NotEqual<Zero> for Succ<T> {
    type Result = One;
}

impl<T> NotEqual<Succ<T>> for Zero {
    type Result = One;
}

impl<T, U> NotEqual<Succ<U>> for Succ<T>
where
    T: NotEqual<U>,
{
    type Result = <T as NotEqual<U>>::Result;
}


struct Nil;
struct Cons<W, T>(PhantomData<W>, PhantomData<T>);


trait Eval {
    type Result;
}

struct Sum;
impl Eval for Sum {
    type Result = Sum;
}

struct Prod;
impl Eval for Prod {
    type Result = Prod;
}

struct EvalBothAndSub;
impl Eval for EvalBothAndSub {
    type Result = EvalBothAndSub;
}

struct ApplyAll;
impl Eval for ApplyAll {
    type Result = ApplyAll;
}

struct WTF1;
impl Eval for WTF1 {
    type Result = WTF1;
}

struct AssertAllEqual;
impl Eval for AssertAllEqual {
    type Result = AssertAllEqual;
}

struct AssertNotEqual;
impl Eval for AssertNotEqual {
    type Result = AssertNotEqual;
}

struct Map;
impl Eval for Map {
    type Result = Map;
}

struct WeirdEquals;
impl Eval for WeirdEquals {
    type Result = WeirdEquals;
}

struct WeirdNotEquals;
impl Eval for WeirdNotEquals {
    type Result = WeirdNotEquals;
}

struct EveryThird;
impl Eval for EveryThird {
    type Result = EveryThird;
}

struct SkipEveryThird;
impl Eval for SkipEveryThird {
    type Result = SkipEveryThird;
}

struct Apply;
impl Eval for Apply {
    type Result = Apply;
}


impl Eval for Zero {
    type Result = Zero;
}
impl<T> Eval for Succ<T> {
    type Result = Succ<T>;
}


impl<X, Y> Eval for Cons<EvalBothAndSub, Cons<X, Cons<Y, Nil>>>
where
    X: Eval,
    Y: Eval,
    <X as Eval>::Result: SubAndAssertPositive<<Y as Eval>::Result>,
{
    type Result = <<X as Eval>::Result as SubAndAssertPositive<<Y as Eval>::Result>>::Result;
}


impl<T> Eval for Cons<WTF1, Cons<T, Nil>>
where
    T: Eval,
{
    type Result = <T as Eval>::Result;
}
impl<T, U, Z> Eval for Cons<WTF1, Cons<T, Cons<U, Z>>>
where
    Cons<WTF1, Cons<U, Z>>: Eval,
    T: Eval,
{
    type Result = <Cons<WTF1, Cons<U, Z>> as Eval>::Result;
}


impl<T> Eval for Cons<AssertAllEqual, Cons<T, Nil>> {
    type Result = Zero;
}
impl<T, U, Z> Eval for Cons<AssertAllEqual, Cons<T, Cons<U, Z>>>
where
    T: Eval,
    U: Eval,
    <T as Eval>::Result: SubAndAssertPositive<<U as Eval>::Result>,
    <U as Eval>::Result: SubAndAssertPositive<<T as Eval>::Result>,
    Cons<AssertAllEqual, Cons<U, Z>>: Eval,
{
    type Result = <Cons<AssertAllEqual, Cons<U, Z>> as Eval>::Result;
}


impl<T, U> Eval for Cons<AssertNotEqual, Cons<T, Cons<U, Nil>>>
where
    T: Eval,
    U: Eval,
    <T as Eval>::Result: NotEqual<<U as Eval>::Result>,
    <<T as Eval>::Result as NotEqual<<U as Eval>::Result>>::Result: SubAndAssertPositive<One>,
{
    type Result = Zero;
}


impl<S> Eval for Cons<Map, Cons<S, Nil>> {
    type Result = Nil;
}
impl<S, W, T> Eval for Cons<Map, Cons<S, Cons<W, T>>>
where
    Cons<S, Cons<W, Nil>>: Eval,
    Cons<Map, Cons<S, T>>: Eval,
{
    type Result =
        Cons<<Cons<S, Cons<W, Nil>> as Eval>::Result, <Cons<Map, Cons<S, T>> as Eval>::Result>;
}


impl<S, X, Y, T> Eval for Cons<WeirdEquals, Cons<Cons<S, Cons<X, Cons<Y, Cons<T, Nil>>>>, Nil>> {
    type Result = Cons<AssertAllEqual, Cons<Cons<S, Cons<X, Cons<Y, Nil>>>, Cons<T, Nil>>>;
}

impl<S, X, Y, T> Eval for Cons<WeirdNotEquals, Cons<Cons<S, Cons<X, Cons<Y, Cons<T, Nil>>>>, Nil>> {
    type Result = Cons<AssertNotEqual, Cons<Cons<S, Cons<X, Cons<Y, Nil>>>, Cons<T, Nil>>>;
}


impl Eval for Cons<EveryThird, Nil> {
    type Result = Nil;
}

impl<X, Y, R, T> Eval for Cons<EveryThird, Cons<X, Cons<Y, Cons<R, T>>>>
where
    Cons<EveryThird, T>: Eval,
{
    type Result = Cons<X, <Cons<EveryThird, T> as Eval>::Result>;
}


impl Eval for Cons<SkipEveryThird, Nil> {
    type Result = Nil;
}
impl<X, Y, R, T> Eval for Cons<SkipEveryThird, Cons<X, Cons<Y, Cons<R, T>>>>
where
    Cons<SkipEveryThird, T>: Eval,
{
    type Result = Cons<Y, Cons<R, <Cons<SkipEveryThird, T> as Eval>::Result>>;
}

impl<S, T> Eval for Cons<Apply, Cons<S, Cons<T, Nil>>>
where
    T: Eval,
    Cons<S, <T as Eval>::Result>: Eval,
{
    type Result = <Cons<S, <T as Eval>::Result> as Eval>::Result;
}


impl<T> Eval for Cons<ApplyAll, Cons<T, Nil>>
where
    T: Eval,
{
    type Result = <T as Eval>::Result;
}
impl<W, T> Eval for Cons<ApplyAll, Cons<W, T>>
where
    Cons<ApplyAll, T>: Eval,
{
    type Result = Cons<W, <Cons<ApplyAll, T> as Eval>::Result>;
}


impl Eval for Cons<Sum, Nil> {
    type Result = Zero;
}
impl<T> Eval for Cons<Sum, Cons<T, Nil>>
where
    T: Eval,
{
    type Result = T;
}
impl<P, Q, T> Eval for Cons<Sum, Cons<P, Cons<Q, T>>>
where
    Q: Eval,
    P: Add<<Q as Eval>::Result>,
    Cons<Sum, Cons<<P as Add<<Q as Eval>::Result>>::Result, T>>: Eval,
{
    type Result =
        <Cons<Sum, Cons<<P as Add<<Q as Eval>::Result>>::Result, T>> as Eval>::Result;
}


impl Eval for Cons<Prod, Nil> {
    type Result = One;
}
impl<T> Eval for Cons<Prod, Cons<T, Nil>>
where
    T: Eval,
{
    type Result = T;
}
impl<P, Q, T> Eval for Cons<Prod, Cons<P, Cons<Q, T>>>
where
    Q: Eval,
    P: Mult<<Q as Eval>::Result>,
    Cons<Prod, Cons<<P as Mult<<Q as Eval>::Result>>::Result, T>>: Eval,
{
    type Result =
        <Cons<Prod, Cons<<P as Mult<<Q as Eval>::Result>>::Result, T>> as Eval>::Result;
}


type Hundred = <Ten as Mult<Ten>>::Result;
trait DiceSkipEveryThird {
    const CHAR: char;
}
type Char_ = Zero;
impl DiceSkipEveryThird for Char_ {
    const CHAR: char = '_';
}
type Char0 = One;
impl DiceSkipEveryThird for Char0 {
    const CHAR: char = '0';
}
type Char1 = Two;
impl DiceSkipEveryThird for Char1 {
    const CHAR: char = '1';
}
type Char2 = Three;
impl DiceSkipEveryThird for Char2 {
    const CHAR: char = '2';
}
type Char3 = Four;
impl DiceSkipEveryThird for Char3 {
    const CHAR: char = '3';
}
type Char4 = Five;
impl DiceSkipEveryThird for Char4 {
    const CHAR: char = '4';
}
type Char5 = Six;
impl DiceSkipEveryThird for Char5 {
    const CHAR: char = '5';
}
type Char6 = Seven;
impl DiceSkipEveryThird for Char6 {
    const CHAR: char = '6';
}
type Char7 = Eight;
impl DiceSkipEveryThird for Char7 {
    const CHAR: char = '7';
}
type Char8 = Nine;
impl DiceSkipEveryThird for Char8 {
    const CHAR: char = '8';
}
type Char9 = <<Ten as Mult<One>>::Result as Add<Zero>>::Result;
impl DiceSkipEveryThird for Char9 {
    const CHAR: char = '9';
}
type CharA = <<Ten as Mult<One>>::Result as Add<One>>::Result;
impl DiceSkipEveryThird for CharA {
    const CHAR: char = 'a';
}
type CharB = <<Ten as Mult<One>>::Result as Add<Two>>::Result;
impl DiceSkipEveryThird for CharB {
    const CHAR: char = 'b';
}
type CharC = <<Ten as Mult<One>>::Result as Add<Three>>::Result;
impl DiceSkipEveryThird for CharC {
    const CHAR: char = 'c';
}
type CharD = <<Ten as Mult<One>>::Result as Add<Four>>::Result;
impl DiceSkipEveryThird for CharD {
    const CHAR: char = 'd';
}
type CharE = <<Ten as Mult<One>>::Result as Add<Five>>::Result;
impl DiceSkipEveryThird for CharE {
    const CHAR: char = 'e';
}
type CharF = <<Ten as Mult<One>>::Result as Add<Six>>::Result;
impl DiceSkipEveryThird for CharF {
    const CHAR: char = 'f';
}
type CharG = <<Ten as Mult<One>>::Result as Add<Seven>>::Result;
impl DiceSkipEveryThird for CharG {
    const CHAR: char = 'g';
}
type CharH = <<Ten as Mult<One>>::Result as Add<Eight>>::Result;
impl DiceSkipEveryThird for CharH {
    const CHAR: char = 'h';
}
type CharI = <<Ten as Mult<One>>::Result as Add<Nine>>::Result;
impl DiceSkipEveryThird for CharI {
    const CHAR: char = 'i';
}
type CharJ = <<Ten as Mult<Two>>::Result as Add<Zero>>::Result;
impl DiceSkipEveryThird for CharJ {
    const CHAR: char = 'j';
}
type CharK = <<Ten as Mult<Two>>::Result as Add<One>>::Result;
impl DiceSkipEveryThird for CharK {
    const CHAR: char = 'k';
}
type CharL = <<Ten as Mult<Two>>::Result as Add<Two>>::Result;
impl DiceSkipEveryThird for CharL {
    const CHAR: char = 'l';
}
type CharM = <<Ten as Mult<Two>>::Result as Add<Three>>::Result;
impl DiceSkipEveryThird for CharM {
    const CHAR: char = 'm';
}
type CharN = <<Ten as Mult<Two>>::Result as Add<Four>>::Result;
impl DiceSkipEveryThird for CharN {
    const CHAR: char = 'n';
}
type CharO = <<Ten as Mult<Two>>::Result as Add<Five>>::Result;
impl DiceSkipEveryThird for CharO {
    const CHAR: char = 'o';
}
type CharP = <<Ten as Mult<Two>>::Result as Add<Six>>::Result;
impl DiceSkipEveryThird for CharP {
    const CHAR: char = 'p';
}
type CharQ = <<Ten as Mult<Two>>::Result as Add<Seven>>::Result;
impl DiceSkipEveryThird for CharQ {
    const CHAR: char = 'q';
}
type CharR = <<Ten as Mult<Two>>::Result as Add<Eight>>::Result;
impl DiceSkipEveryThird for CharR {
    const CHAR: char = 'r';
}
type CharS = <<Ten as Mult<Two>>::Result as Add<Nine>>::Result;
impl DiceSkipEveryThird for CharS {
    const CHAR: char = 's';
}
type CharT = <<Ten as Mult<Three>>::Result as Add<Zero>>::Result;
impl DiceSkipEveryThird for CharT {
    const CHAR: char = 't';
}
type CharU = <<Ten as Mult<Three>>::Result as Add<One>>::Result;
impl DiceSkipEveryThird for CharU {
    const CHAR: char = 'u';
}
type CharV = <<Ten as Mult<Three>>::Result as Add<Two>>::Result;
impl DiceSkipEveryThird for CharV {
    const CHAR: char = 'v';
}
type CharW = <<Ten as Mult<Three>>::Result as Add<Three>>::Result;
impl DiceSkipEveryThird for CharW {
    const CHAR: char = 'w';
}
type CharX = <<Ten as Mult<Three>>::Result as Add<Four>>::Result;
impl DiceSkipEveryThird for CharX {
    const CHAR: char = 'x';
}
type CharY = <<Ten as Mult<Three>>::Result as Add<Five>>::Result;
impl DiceSkipEveryThird for CharY {
    const CHAR: char = 'y';
}
type CharZ = <<Ten as Mult<Three>>::Result as Add<Six>>::Result;
impl DiceSkipEveryThird for CharZ {
    const CHAR: char = 'z';
}
type Flag0 = CharL;
type Flag1 = Char1;
type Flag2 = CharS;
type Flag3 = CharP;
type Flag4 = Char_;
type Flag5 = CharI;
type Flag6 = CharN;
type Flag7 = CharS;
type Flag8 = CharI;
type Flag9 = CharD;
type Flag10 = Char3;
type Flag11 = Char_;
type Flag12 = CharR;
type Flag13 = CharU;
type Flag14 = CharS;
type Flag15 = Char7;
type Flag16 = Char_;
type Flag17 = Char9;
type Flag18 = CharA;
type Flag19 = CharF;
type Flag20 = CharH;
type Flag21 = Char1;
type Flag22 = CharN;
type Flag23 = Char2;
type Flag24 = Char3;
type weirdVal = Cons < Cons < Sum , Cons < Flag11 , Cons < Flag13 , Cons < < < Ten as Mult < Two > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag1 , Cons < Flag9 , Cons < < < Ten as Mult < Two > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag4 , Cons < < < Ten as Mult < One > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag0 , Cons < Flag5 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag3 , Cons < Flag16 , Cons < < < Ten as Mult < Two > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag12 , Cons < Flag11 , Cons < < < Ten as Mult < Two > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag18 , Cons < Flag17 , Cons < Zero , Nil > > > > , Cons < Cons < Prod , Cons < Flag20 , Cons < Flag11 , Cons < Zero , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag5 , Cons < Flag9 , Cons < Five , Nil > > > > , Cons < Cons < Prod , Cons < Flag2 , Cons < Flag4 , Cons < Five , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag0 , Cons < Flag15 , Cons < < < Ten as Mult < One > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag8 , Cons < Flag24 , Cons < < < Ten as Mult < One > > :: Result as Add < Five > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag11 , Cons < Flag7 , Cons < < < Ten as Mult < Three > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag14 , Cons < Flag21 , Cons < < < Ten as Mult < Two > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag4 , Cons < Flag16 , Cons < Zero , Nil > > > > , Cons < Cons < Prod , Cons < Flag21 , Cons < Flag3 , Cons < < < Ten as Mult < Four > > :: Result as Add < Nine > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag24 , Cons < Flag16 , Cons < Four , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag3 , Cons < Flag0 , Cons < Four , Nil > > > > , Cons < Cons < Sum , Cons < Flag11 , Cons < Flag10 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag7 , Cons < Flag15 , Cons < < < Ten as Mult < Two > > :: Result as Add < One > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag18 , Cons < Flag5 , Cons < < < Ten as Mult < Three > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag18 , Cons < Flag11 , Cons < Five , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag7 , Cons < Flag21 , Cons < < < Ten as Mult < Two > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag13 , Cons < Flag18 , Cons < < < Hundred as Mult < Three > > :: Result as Add < < < Ten as Mult < Four > > :: Result as Add < One > > :: Result > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag15 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag19 , Cons < Flag23 , Cons < < < Ten as Mult < One > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag14 , Cons < Flag20 , Cons < < < Ten as Mult < Four > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag21 , Cons < Flag4 , Cons < < < Ten as Mult < One > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag10 , Cons < Flag2 , Cons < < < Ten as Mult < Three > > :: Result as Add < Three > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag10 , Cons < < < Ten as Mult < One > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag17 , Cons < Flag0 , Cons < < < Hundred as Mult < Two > > :: Result as Add < < < Ten as Mult < One > > :: Result as Add < Nine > > :: Result > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag22 , Cons < Flag23 , Cons < < < Ten as Mult < Two > > :: Result as Add < One > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag15 , Cons < Flag18 , Cons < < < Ten as Mult < Eight > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag12 , Cons < Flag6 , Cons < < < Ten as Mult < Four > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag22 , Cons < Flag24 , Cons < < < Ten as Mult < Nine > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag0 , Cons < Flag23 , Cons < < < Ten as Mult < Six > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag0 , Cons < Flag5 , Cons < < < Hundred as Mult < Four > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag8 , Cons < Flag11 , Cons < < < Ten as Mult < One > > :: Result as Add < Nine > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag19 , Cons < Flag13 , Cons < < < Ten as Mult < Four > > :: Result as Add < Seven > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag7 , Cons < Flag12 , Cons < < < Ten as Mult < One > > :: Result as Add < One > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag17 , Cons < Flag22 , Cons < < < Hundred as Mult < Two > > :: Result as Add < < < Ten as Mult < Four > > :: Result as Add < Zero > > :: Result > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag16 , Cons < Flag14 , Cons < < < Ten as Mult < Two > > :: Result as Add < Nine > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag24 , Cons < Flag18 , Cons < < < Ten as Mult < One > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag19 , Cons < Flag4 , Cons < < < Ten as Mult < One > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag24 , Cons < Flag3 , Cons < < < Ten as Mult < Three > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag0 , Cons < Flag16 , Cons < < < Ten as Mult < One > > :: Result as Add < Two > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag10 , Cons < Flag5 , Cons < < < Ten as Mult < Seven > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag20 , Cons < Flag19 , Cons < Two , Nil > > > > , Cons < Cons < Prod , Cons < Flag12 , Cons < Flag16 , Cons < Five , Nil > > > > , Cons < Cons < Prod , Cons < Flag24 , Cons < Flag12 , Cons < < < Hundred as Mult < One > > :: Result as Add < < < Ten as Mult < One > > :: Result as Add < Two > > :: Result > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag24 , Cons < Flag16 , Cons < Four , Nil > > > > , Cons < Cons < Sum , Cons < Flag12 , Cons < Flag15 , Cons < < < Ten as Mult < Four > > :: Result as Add < Five > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag1 , Cons < Flag20 , Cons < < < Ten as Mult < Two > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag1 , Cons < Flag17 , Cons < < < Ten as Mult < Two > > :: Result as Add < Zero > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag5 , Cons < Flag11 , Cons < < < Ten as Mult < Two > > :: Result as Add < Six > > :: Result , Nil > > > > , Cons < Cons < EvalBothAndSub , Cons < Flag5 , Cons < Flag18 , Cons < Eight , Nil > > > > , Cons < Cons < Sum , Cons < Flag16 , Cons < Flag22 , Cons < < < Ten as Mult < Two > > :: Result as Add < Four > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag14 , Cons < Flag3 , Cons < < < Hundred as Mult < Seven > > :: Result as Add < < < Ten as Mult < Four > > :: Result as Add < Seven > > :: Result > > :: Result , Nil > > > > , Cons < Cons < Prod , Cons < Flag6 , Cons < Flag21 , Cons < < < Ten as Mult < Four > > :: Result as Add < Eight > > :: Result , Nil > > > > , Cons < Cons < Sum , Cons < Flag6 , Cons < Flag22 , Cons < < < Ten as Mult < Four > > :: Result as Add < Eight > > :: Result , Nil > > > > , Nil > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > > ;

fn print_flag() { println!("dice{{{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}}}", Flag0::CHAR, Flag1::CHAR, Flag2::CHAR, Flag3::CHAR, Flag4::CHAR, Flag5::CHAR, Flag6::CHAR, Flag7::CHAR, Flag8::CHAR, Flag9::CHAR, Flag10::CHAR, Flag11::CHAR, Flag12::CHAR, Flag13::CHAR, Flag14::CHAR, Flag15::CHAR, Flag16::CHAR, Flag17::CHAR, Flag18::CHAR, Flag19::CHAR, Flag20::CHAR, Flag21::CHAR, Flag22::CHAR, Flag23::CHAR, Flag24::CHAR); }

type Cond3 = Cons< Apply, Cons< Map, Cons<Cons<ApplyAll, Cons<WeirdNotEquals, Cons<Cons<EveryThird, weirdVal>, Nil>>>, Nil> > >;
type Cond2 = Cons< Apply, Cons< Map, Cons<Cons<ApplyAll, Cons<WeirdEquals, Cons<Cons<SkipEveryThird, weirdVal>, Nil>>>, Nil> > >;
type Cond1 = Cons< WTF1, Cons< Cons<Apply, Cons<WTF1, Cons<Cond3, Nil>>>, Cons<Cons<Apply, Cons<WTF1, Cons<Cond2, Nil>>>, Nil> > >;
type AssertFlagValid = <Cond1 as Eval>::Result;
fn main() {
    print_flag();
    let _: AssertFlagValid = panic!();
}

