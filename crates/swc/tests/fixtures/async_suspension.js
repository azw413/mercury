async function resolved(value) {
  var local = value;
  function read() {
    return local;
  }
  local = await Promise.resolve(read() + 1);
  local = await Promise.resolve(local + 1);
  return read();
}

async function rejected() {
  try {
    await Promise.reject("no");
    return "unreachable";
  } catch (error) {
    return "caught:" + error;
  }
}

var receiver = {
  base: 10,
  run: async function(delta) {
    var base = await Promise.resolve(this.base);
    return base + delta;
  }
};

resolved(5).then(function(value) {
  print("resolved", value);
});
rejected().then(function(value) {
  print("rejected", value);
});
receiver.run(4).then(function(value) {
  print("receiver", value);
});
