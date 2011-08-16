// patches to rsa-pem.js to do public key operations

function _rsapem_readPublicKeyFromPEMString(keyPEM) {
  var keyB64 = _rsapubpem_pemToBase64(keyPEM);
  var keyHex = b64tohex(keyB64) // depends base64.js

  /* expected structure is:
      0:d=0  hl=4 l= 290 cons: SEQUENCE          
    4:d=1  hl=2 l=  13 cons: SEQUENCE          
    6:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   17:d=2  hl=2 l=   0 prim: NULL              
   19:d=1  hl=4 l= 271 prim: BIT STRING        
  */
  var offsets = _asnhex_getPosArrayOfChildren_AtObj(keyHex, 0);
  var type = _asnhex_getHexOfV_AtObj(keyHex, offsets[0]);
  var key = _asnhex_getHexOfV_AtObj(keyHex, offsets[1]);

  // key is a BITSTRING; first octet is number of bits by which
  // the length of the bitstring is less than the next multiple of eight.
  // for now we assume it is zero and ignore it.
  key = key.substring(2, key.length);
  var keyOffsets = _asnhex_getPosArrayOfChildren_AtObj(key, 0);
  var n = _asnhex_getHexOfV_AtObj(key, keyOffsets[0]);
  var e = _asnhex_getHexOfV_AtObj(key, keyOffsets[1]);
  this.setPublic(n, e);
}

RSAKey.prototype.readPublicKeyFromPEMString = _rsapem_readPublicKeyFromPEMString;
