function calculate(n) {
  var total = 0;
  while (n > 0) {
    if (n === 2) total = total + 10;
    else total = total + n;
    n = n - 1;
  }
  return total;
}
print(calculate(4));
