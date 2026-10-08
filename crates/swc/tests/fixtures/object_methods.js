var events = [];
function key(name) {
  events.push("key:" + name);
  return name;
}

var parent = { inherited: 7 };
var object = {
  before: (events.push("before"), 1),
  [key("method")](value) {
    events.push("method");
    return this.inherited + value;
  },
  get [key("value")]() {
    events.push("get");
    return this._value || 3;
  },
  set [key("value")](value) {
    events.push("set:" + value);
    this._value = value;
  },
  __proto__: (events.push("proto"), parent),
  after: (events.push("after"), 2),
  get fixed() { return 11; },
  set fixed(value) { this.written = value; },
  __proto__() { return "method"; }
};

object.value = 9;
object.fixed = 4;
var fixed = Object.getOwnPropertyDescriptor(object, "fixed");
print(
  "values",
  object.method(5),
  object.value,
  object.fixed,
  object.written,
  parent.isPrototypeOf(object),
  object.inherited,
  object.__proto__()
);
print(
  "descriptors",
  fixed.enumerable,
  fixed.configurable,
  fixed.get.name,
  fixed.set.name,
  object.__proto__.name
);

var primitive = { first: 1, __proto__: 9, second: 2 };
var bare = { __proto__: null, own: 3 };
print(
  "prototypes",
  Object.getPrototypeOf(primitive) === Object.prototype,
  primitive.hasOwnProperty("__proto__"),
  bare.toString === undefined,
  bare.own
);
print("events", events.join(","));
