var events = [];

function iterable(values, label) {
  return {
    [Symbol.iterator]: function () {
      var index = 0;
      return {
        next: function () {
          events.push(label + index);
          if (index === values.length) return { done: true };
          return { value: values[index++], done: false };
        }
      };
    }
  };
}

var array = [0, , ...iterable([1, 2], "array"), 3, ..."ab", ,];
print("array", array.length, 1 in array, array.join("|"));

var symbol = Symbol("symbol");
var source = {};
Object.defineProperty(source, "value", {
  enumerable: true,
  get: function () { events.push("get"); return 4; }
});
source[symbol] = 5;
var object = { before: 1, ...null, ...source, value: 6 };
print("object", object.before, object.value, object[symbol]);

var receiver = { base: 10 };
Object.defineProperty(receiver, "add", {
  get: function () {
    events.push("callee");
    return function (a, b, c) { return this.base + a + b + c; };
  }
});
print("call", receiver.add(1, ...iterable([2], "call"), 3));

function Constructed(a, b, c) {
  this.total = a + b + c;
}
var made = new Constructed(1, ...iterable([2], "new"), 3);
print("new", made.total, made instanceof Constructed);
print("events", events.join(","));
