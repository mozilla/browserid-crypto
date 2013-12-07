
// add base64 methods
BigInteger.prototype.toBase64 = function() {
  return hex2b64(this.toString(16));
};

BigInteger.fromBase64 = function(str) {
  return new BigInteger(new Buffer(str, 'base64').toString('hex'), 16);
};
