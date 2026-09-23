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
