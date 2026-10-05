var prototype = { inherited: 5, shadowed: "prototype" };
Object.defineProperty(prototype, "hidden", {
  value: 9,
  enumerable: false,
});
var object = Object.create(prototype);
object.first = 1;
object.shadowed = "own";
object.removed = 3;

var propertyNames = [];
for (var propertyName in object) {
  propertyNames[propertyNames.length] = propertyName;
  if (propertyName === "first") {
    delete object.removed;
    delete object.shadowed;
    object.added = 4;
  }
}
print("for-in", propertyNames.join(","));

var primitiveNames = [];
for (var primitiveName in "ab") {
  primitiveNames[primitiveNames.length] = primitiveName;
}
var emptyIterations = 0;
for (var nullName in null) {
  emptyIterations++;
}
for (var undefinedName in void 0) {
  emptyIterations++;
}
print("for-in-values", primitiveNames.join(","), emptyIterations);

var values = [1, , 3];
var arrayValues = [];
for (var value of values) {
  arrayValues[arrayValues.length] = String(value);
  if (value === 1) {
    values[values.length] = 4;
  }
}
print("array-iterator", arrayValues.join(","));

var closeLog = [];
var closable = {};
closable[Symbol.iterator] = function () {
  var current = 0;
  return {
    next: function () {
      closeLog[closeLog.length] = "next";
      current++;
      return { value: current, done: false };
    },
    return: function () {
      closeLog[closeLog.length] = "return";
      return {};
    },
  };
};
for (var closeValue of closable) {
  closeLog[closeLog.length] = "value:" + closeValue;
  break;
}
print("iterator-close", closeLog.join(","));

var invalid = {};
invalid[Symbol.iterator] = function () {
  return {
    next: function () {
      return 3;
    },
  };
};
try {
  for (var invalidValue of invalid) {
    print(invalidValue);
  }
} catch (error) {
  print("invalid-next", error instanceof TypeError);
}

var throwingClose = {};
throwingClose[Symbol.iterator] = function () {
  return {
    next: function () {
      return { value: 1, done: false };
    },
    return: function () {
      throw "close";
    },
  };
};
try {
  for (var breakValue of throwingClose) {
    break;
  }
} catch (error) {
  print("break-close", error);
}
try {
  for (var throwValue of throwingClose) {
    throw "body";
  }
} catch (error) {
  print("throw-close", error);
}
