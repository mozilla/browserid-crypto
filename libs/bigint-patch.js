
var jsBigInteger = BigInteger;
var nativeBigInteger = null;

// patches to bigint to use native node code if possible
try {
  // if we can get node-bigint, we continue. If not, blarg.
  var bigint = require("bigint");
  var crypto = require("crypto");

  // trying to mimick Tom Wu's constructor
  // except we ignore the rng for now
  BigInteger = function(a, b, ignore_c) {
    if (a) {
      if (typeof a == 'number') {
        if (typeof b == 'number') {
          // random *prime* of bit size a, with certainty b
          var starting_point;
          while(true) {
            // starting_point = bigint.rand(bigint("1").shiftLeft(a));
            // strong starting point, assume even number of bytes
            starting_point = bigint(crypto.randomBytes(a/8).toString('hex'), 16);
            if (starting_point.bitLength() == a)
              break;
          }
          this._bigint = starting_point.nextPrime();
        } else {
          // random number of bit size a
          this._bigint = bigint.rand(bigint("1").shiftLeft(a));
        }
      } else {
        this._bigint = bigint(a, b);
      }
    }
  };

  // wrap
  BigInteger._from_bigint = function(bi) {
    var new_bigint = new BigInteger();
    new_bigint._bigint = bi;
    return new_bigint;
  };

  BigInteger._is_native = true;

  BigInteger.ONE = new BigInteger("1");
  BigInteger.ZERO = new BigInteger("0");

  // shim methods
  BigInteger.prototype = {
    modPow : function(e, m) {
      return BigInteger._from_bigint(this._bigint.powm(e._bigint, m._bigint));
    },
    modPowInt: function(e, m) {
      return this.modPow(BigInteger._from_bigint(bigint(e)), m);
    },
    modInverse: function(m) {
      return BigInteger._from_bigint(this._bigint.invertm(m._bigint));
    },
    equals: function(other) {
      return this._bigint.eq(other._bigint);
    },
    multiply: function(other) {
      return BigInteger._from_bigint(this._bigint.mul(other._bigint));
    },
    mod: function(m) {
      return BigInteger._from_bigint(this._bigint.mod(m._bigint));
    },
    add: function(other) {
      return BigInteger._from_bigint(this._bigint.add(other._bigint));
    },
    subtract: function(other) {
      return BigInteger._from_bigint(this._bigint.sub(other._bigint));
    },
    bitLength: function() {
      return this._bigint.bitLength();
    },
    compareTo: function(other) {
      return this._bigint.cmp(other._bigint);
    },
    toString: function(base) {
      return this._bigint.toString(base || 10);
    },
    gcd: function(other) {
      return BigInteger._from_bigint(this._bigint.gcd(other._bigint));
    },
    isProbablePrime: function(reps) {
      return this._bigint.probPrime(reps);
    },
    toBase64: function() {
      return this._bigint.toBuffer().toString('base64');
    }
  };

  BigInteger.fromBase64 = function(b64_string) {
    var bi = bigint.fromBuffer(new Buffer(b64_string, 'base64'));
    return BigInteger._from_bigint(bi);
  };

  nativeBigInteger = BigInteger;
} catch (x) {
  // oh well, we use normal JS
}

