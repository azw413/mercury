function Plain(x) {
  this.x = x;
}

function Primitive(x) {
  this.x = x;
  return 9;
}

function ObjectReturn(x) {
  this.x = x;
  return { value: x + 1 };
}

function Target() {
  this.same = new.target === Target;
}

function inspectTarget() {
  return new.target === undefined;
}

function Nested() {
  this.nestedIsOrdinaryCall = inspectTarget();
}

function Parent(x) {
  this.parent = x;
}

function Child(x) {
  Parent.call(this, x + 1);
  this.child = x;
}

Child.prototype = Object.create(Parent.prototype);
Child.prototype.constructor = Child;

var plain = new Plain(3);
var primitive = new Primitive(4);
var objectReturn = new ObjectReturn(5);
var target = new Target();
var nested = new Nested();
var child = new Child(6);
var boxed = new Boolean(false);

print(
  plain.x,
  primitive.x,
  objectReturn.value,
  target.same,
  nested.nestedIsOrdinaryCall,
  child.parent,
  child.child,
  child instanceof Parent,
  child instanceof Child,
  boxed.valueOf()
);

var arrow = () => 1;
try {
  new arrow();
} catch (error) {
  print("arrow", error instanceof TypeError);
}

function proxyConstruction(label, prototype) {
  var prototypeReads = 0;
  var constructTraps = 0;
  var applyTraps = 0;

  function ExternalTarget(value) {
    this.value = value;
    return 17;
  }

  ExternalTarget.prototype = prototype;
  var Wrapped;
  Wrapped = new Proxy(ExternalTarget, {
    get: function (target, key, receiver) {
      if (key === "prototype") {
        prototypeReads = prototypeReads + 1;
      }
      return Reflect.get(target, key, receiver);
    },
    construct: function (target, args, newTarget) {
      constructTraps = constructTraps + 1;
      print("new-target", newTarget === Wrapped);
      return Reflect.construct(target, args, newTarget);
    },
    apply: function (target, receiver, args) {
      applyTraps = applyTraps + 1;
      return Reflect.apply(target, receiver, args);
    },
  });

  var value = new Wrapped(8);
  print(
    label,
    prototypeReads,
    constructTraps,
    applyTraps,
    value.value,
    Object.getPrototypeOf(value) === Object.prototype
  );
}

proxyConstruction("object-prototype", { marker: 11 });
proxyConstruction("primitive-prototype", 9);

var failedPrototypeReads = 0;
var notConstructor = new Proxy(
  {},
  {
    get: function (target, key, receiver) {
      if (key === "prototype") {
        failedPrototypeReads = failedPrototypeReads + 1;
      }
      return Reflect.get(target, key, receiver);
    },
  }
);
try {
  new notConstructor();
} catch (error) {
  print("not-constructor", failedPrototypeReads, error instanceof TypeError);
}
