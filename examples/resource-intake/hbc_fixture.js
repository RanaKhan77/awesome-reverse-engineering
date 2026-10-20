function classify(n) {
  if (n < 0) return "negative";
  if (n === 0) return "zero";
  return n % 2 === 0 ? "even" : "odd";
}
function scaled(a, b) {
  return a * 7 + b;
}
globalThis.marker = "hbc-fixture-marker";
print(classify(4) + ":" + classify(-1) + ":" + scaled(3, 4));
