
// add base64 methods
BigInteger.prototype.toBase64 = function() {
  return hex2b64(this.toString(16));
};

BigInteger.fromBase64 = function(_str) {
  // check for urlencoded b64
  var str = _str.replace(/-/g, '+').replace(/_/g, '/');
  return new BigInteger(b64tohex(str), 16);
};
