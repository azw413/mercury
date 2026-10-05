var symbol = Symbol("symbol");
var getterHits = 0;
var prototype = { inherited: 8 };
var source = Object.create(prototype);
source.first = 1;
source[symbol] = 2;
Object.defineProperty(source, "hidden", {
  value: 3,
  enumerable: false,
});
Object.defineProperty(source, "computed", {
  enumerable: true,
  get: function () {
    getterHits++;
    return 4;
  },
});

var spread = {
  before: 0,
  ...source,
  first: 5,
  ...null,
  ...void 0,
};
var descriptor = Object.getOwnPropertyDescriptor(spread, "computed");
print(
  "spread",
  spread.before,
  spread.first,
  spread.computed,
  spread[symbol],
  spread.hidden,
  spread.inherited,
  getterHits,
  descriptor.writable,
  descriptor.enumerable,
  descriptor.configurable
);

var first;
var rest;
({ first: first, ...rest } = source);
print(
  "rest",
  first,
  rest.first,
  rest.computed,
  rest[symbol],
  rest.hidden,
  rest.inherited,
  getterHits
);

var proxyLog = [];
var proxy = new Proxy(
  { visible: 7, skipped: 9 },
  {
    ownKeys: function (target) {
      proxyLog[proxyLog.length] = "keys";
      return ["visible", "skipped"];
    },
    getOwnPropertyDescriptor: function (target, key) {
      proxyLog[proxyLog.length] = "descriptor:" + key;
      return {
        value: target[key],
        enumerable: key === "visible",
        configurable: true,
      };
    },
    get: function (target, key) {
      proxyLog[proxyLog.length] = "get:" + key;
      return target[key];
    },
  }
);
var proxySpread = { ...proxy };
print("proxy", proxySpread.visible, proxySpread.skipped, proxyLog.join(","));
