function increment(value) {
  return ++value;
}

function decrement(value) {
  return --value;
}

function postfix(value) {
  var old = value++;
  return [old, value];
}

function number(value) {
  return +value;
}

function int32(value) {
  return value | 0;
}

function text(value) {
  return "" + value;
}

function removeNamed(object) {
  return delete object.fixed;
}

function removeDynamic(object, key) {
  return delete object[key];
}

function removeStrict(object) {
  "use strict";
  return delete object.fixed;
}

var item = { fixed: 3, dynamic: 4 };
var pair = postfix("7");
print(
  increment("4"),
  decrement("4"),
  pair[0],
  pair[1],
  number("3.5"),
  int32(4294967297),
  text({
    valueOf: function () {
      return 9;
    },
  }),
  removeNamed(item),
  removeDynamic(item, "dynamic"),
  item.fixed,
  item.dynamic
);

var big = BigInt("4");
var bigPair = postfix(big);
print(increment(big), decrement(big), bigPair[0], bigPair[1]);

var locked = {};
Object.defineProperty(locked, "fixed", {
  value: 1,
  configurable: false,
});
print(removeNamed(locked), locked.fixed);
try {
  removeStrict(locked);
} catch (error) {
  print("strict-delete", error instanceof TypeError, locked.fixed);
}

function inspectArguments(first) {
  print("arguments", arguments.length, arguments[1]);
  return arguments;
}

var returnedArguments = inspectArguments(2, 7, 9);
print("returned-arguments", returnedArguments[0], returnedArguments.length);

function argumentsDoNotRewriteParameter(value) {
  arguments[0] = 6;
  return value;
}

function parameterDoesNotRewriteArguments(value) {
  value = 7;
  return arguments[0];
}

print(
  "argument-aliasing",
  argumentsDoNotRewriteParameter(1),
  parameterDoesNotRewriteArguments(2)
);

var stored = 3;
var accessor = {
  get value() {
    return stored;
  },
  set value(next) {
    stored = next + 1;
  },
};
var accessorDescriptor = Object.getOwnPropertyDescriptor(accessor, "value");
print(
  "accessor",
  accessor.value,
  accessorDescriptor.enumerable,
  accessorDescriptor.configurable,
  accessorDescriptor.get.name,
  accessorDescriptor.set.name
);
accessor.value = 8;
print("set", accessor.value);
