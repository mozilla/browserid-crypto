//
// adding export statements to the all.js file
//
// FIXME: not clear this is how we want to do it
//

exports.BigInteger = BigInteger;
exports.sjcl = sjcl;
exports.hex2b64 = hex2b64;
exports.b64tohex = b64tohex;
exports.int2char = int2char;

// sha1 exports, no hmac for now
exports.hex_sha1 = hex_sha1;
exports.b64_sha1 = b64_sha1;

// this is so we can export the faked window and navigator
// objects and not write the code for base64 twice
exports.window = window;
exports.navigator = navigator;
