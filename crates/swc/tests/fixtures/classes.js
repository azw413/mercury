class Base {
  constructor(value) {
    this.base = value;
  }

  method() {
    return this.base;
  }
}

class Derived extends Base {
  constructor(value) {
    super(value + 1);
    this.derived = value;
  }

  total() {
    return this.base + this.derived;
  }
}

class Features {
  constructor(value) {
    this._value = value;
  }

  get value() {
    return this._value;
  }

  set value(next) {
    this._value = next + 1;
  }

  static make(value) {
    return new Features(value);
  }
}

var instance = new Derived(6);
print(
  instance.base,
  instance.derived,
  instance.method(),
  instance.total(),
  instance instanceof Base,
  instance instanceof Derived,
  Base.prototype.method.name,
  Derived.prototype.total.name
);

var feature = Features.make(3);
print(feature.value, Features.make.name);
feature.value = 8;
print(feature.value);
