var high = "\uD800";
var low = "\uDFFF";
var pair = "\uD83D\uDE00";
var separated = "\uD800A\uDFFF";

print(
  "units",
  high.length,
  high.charCodeAt(0).toString(16),
  low.length,
  low.charCodeAt(0).toString(16),
  pair.length,
  pair.charCodeAt(0).toString(16),
  pair.charCodeAt(1).toString(16),
  separated.length,
  separated.charCodeAt(0).toString(16),
  separated.charCodeAt(1).toString(16),
  separated.charCodeAt(2).toString(16)
);

var bufferedArray = [high, "\uDFFF", pair, separated];
var bufferedObject = {
  "\uD800": "\uDFFF",
  pair: "\uD83D\uDE00",
  separated: "\uD800A\uDFFF",
};
print(
  "buffered",
  bufferedArray[1].charCodeAt(0).toString(16),
  bufferedArray[2].length,
  bufferedArray[3].length,
  bufferedObject[high].charCodeAt(0).toString(16),
  bufferedObject.pair.length,
  bufferedObject.separated.length,
  Object.keys(bufferedObject)[0].charCodeAt(0).toString(16)
);

var dynamic = {};
dynamic[high] = low;
print(
  "property",
  dynamic[high] === low,
  high in dynamic,
  delete dynamic[high],
  high in dynamic
);
