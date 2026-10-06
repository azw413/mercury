var globalValue = 4;

function globalOnly() {
  var globalValue = 99;
  return eval("globalValue + 3");
}

function looseEval() {
  return eval("looseCreated = 8; looseCreated + 1");
}

function strictEval() {
  "use strict";
  try {
    return eval("strictCreated = 1");
  } catch (error) {
    return error.name;
  }
}

var token = {};
print(
  "values",
  globalOnly(),
  looseEval(),
  looseCreated,
  strictEval(),
  typeof strictCreated,
  eval(token) === token
);
try {
  eval("(");
} catch (error) {
  print("syntax", error.name);
}
delete looseCreated;
