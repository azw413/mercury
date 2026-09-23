function show(tag, result) {
  print(tag, result.value, result.done);
}

function* counter(seed) {
  var local = seed;
  function read() {
    return local;
  }
  try {
    var bump = yield read();
    local = local + bump;
    yield read();
    return local + 1;
  } finally {
    print("finally", local);
  }
}

function* caught() {
  try {
    yield "ready";
  } catch (error) {
    yield "caught:" + error;
  }
  return "finished";
}

function* inner() {
  try {
    yield 1;
    yield 2;
  } catch (error) {
    yield "delegated-catch:" + error;
  } finally {
    print("inner-finally");
  }
  return 7;
}

function* outer() {
  var result = yield* inner();
  return "outer:" + result;
}

var first = counter(4);
var second = counter(10);
show("first-1", first.next(99));
show("second-1", second.next());
show("first-2", first.next(3));
show("first-3", first.next());
show("first-4", first.next());
show("second-return", second.return(44));
show("second-after", second.next());
print("iterator", first[Symbol.iterator]() === first);

var thrown = caught();
show("throw-1", thrown.next());
show("throw-2", thrown.throw("boom"));
show("throw-3", thrown.next());

var delegatedThrow = outer();
show("delegate-1", delegatedThrow.next());
show("delegate-2", delegatedThrow.throw("x"));
show("delegate-3", delegatedThrow.next());
show("delegate-4", delegatedThrow.next());

var delegatedReturn = outer();
show("return-1", delegatedReturn.next());
show("return-2", delegatedReturn.return(9));
show("return-3", delegatedReturn.next());

var neverStarted = counter(20);
show("before-start-return", neverStarted.return(5));
try {
  counter(30).throw("before-start-throw");
} catch (error) {
  print("before-start-catch", error);
}
