// patches to rsa-pem.js to do public key operations

function _rsapubpem_pemToBase64(sPEMPublicKey) {
  if (sPEMPublicKey.indexOf("-----BEGIN PUBLIC KEY-----") != 0) {
    throw "Malformed input to readPublicKeyFromPEMString: input does not start with '-----BEGIN PUBLIC KEY-----'";
  }
  var s = sPEMPublicKey;
  s = s.replace("-----BEGIN PUBLIC KEY-----", "");
  s = s.replace("-----END PUBLIC KEY-----", "");
  s = s.replace(/[ \n]+/g, "");
  return s;
}

function _rsapem_readPublicKeyFromPEMString(keyPEM) {
  var keyB64 = _rsapubpem_pemToBase64(keyPEM);
  var keyHex = b64tohex(keyB64); // depends base64.js

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

// Returns an ASN1-encoded RSAPrivateKey (PKCS1) data structure
function RSAPrivateKeySerializeASN1() {
  function concatBigInteger(bytes, bigInt) {
    var bigIntBytes = bigInt.toByteArray();
    bytes.push(0x02); // INTEGER
    bytes.push(bigIntBytes.length); // #BYTES
    //  bytes.push(00); // this appears in some encodings, and I don't understand why.  leading zeros?
    return bytes.concat(bigIntBytes);
  }
  var bytes=[];
  // sequence
  bytes.push(0x30);
  bytes.push(0x82);//XX breaks on 1024 bit keys?
  bytes.push(0x01);
  bytes.push(0x00);// replace with actual length (-256)...
  // version (integer 0)
  bytes.push(0x02); // INTEGER
  bytes.push(0x01); // #BYTES
  bytes.push(0x00); // value
  // modulus (n)
  bytes = concatBigInteger(bytes, this.n);
  
  // publicExponent (e)
  bytes = concatBigInteger(bytes, new BigInteger(""+this.e, 10));
  
  // privateExponent (d)
  bytes = concatBigInteger(bytes, this.d);

  // prime1 (p)
  bytes = concatBigInteger(bytes, this.p);

  // prime2 (q)
  bytes = concatBigInteger(bytes, this.q);

  // exponent1 (d mod p-1 -> dmp1)
  bytes = concatBigInteger(bytes, this.dmp1);

  // exponent2 (q mod p-1 -> dmq1)
  bytes = concatBigInteger(bytes, this.dmq1);

  // coefficient ((inverse of q) mod p -> coeff)
  bytes = concatBigInteger(bytes, this.coeff);

  var actualLength = bytes.length - 4;
  var lenBytes = new BigInteger("" + actualLength, 10).toByteArray();
  bytes[2] = lenBytes[0];
  bytes[3] = lenBytes[1];
    
  var buffer = "";
  for (var i=0;i<bytes.length;i++) { 
    buffer += int2char((bytes[i] & 0xf0) >> 4);
    buffer += int2char(bytes[i] & 0x0f);
  }
  buffer = hex2b64(buffer);
  var newlineBuffer = "";
  for (var i=0;i<buffer.length;i++) { 
    if (i>0 && (i % 64) == 0) newlineBuffer += "\n";
    newlineBuffer += buffer[i];
  }
  return "-----BEGIN RSA PRIVATE KEY-----\n" + newlineBuffer + "\n-----END RSA PRIVATE KEY-----\n";
}


// Returns an ASN1-encoded X509 Public Key data structure
function RSAPublicKeySerializeASN1() {
  
  function encodeSequence(contentObjects) {
    var len = 0;
    for (var i=0;i<contentObjects.length;i++) {
      len += contentObjects[i].length;
    }
    var out = [];
    out.push(0x30); // SEQUENCE, constructed
    if (len < 128) {
      out.push(len);
    } else {
      var lenBytes = new BigInteger("" + len, 10).toByteArray();
      out.push(0x80 | lenBytes.length);
      for (var i=0;i<lenBytes.length;i++) out.push(lenBytes[i]);
    }
    for (var i=0;i<contentObjects.length;i++) {
      out = out.concat(contentObjects[i]);
    }
    return out;
  }

  function encodeBigInteger(bigInt) {
    var bigIntBytes = bigInt.toByteArray();
    var bytes= [];
    bytes.push(0x02); // INTEGER
    bytes.push(bigIntBytes.length); // #BYTES
    return bytes.concat(bigIntBytes);
  }

  function encodeBitString(bits) {
    var bytes=[];
    bytes.push(0x03); // BIT STRING
    bytes.push(bits.length+1);  // #Bytes
    bytes.push(0);// remainder
    return bytes.concat(bits);
  }

  // construct exponent-modulus sequence:
  var neSequence = encodeSequence(
    [
      encodeBigInteger(this.n),
      encodeBigInteger(new BigInteger("" + this.e, 10))
    ]
  );
  var neBitString = encodeBitString(neSequence);

  // construct :rsaEncryption sequence:
  var rsaEncSequence = encodeSequence(
    [
      [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
      [0x05, 0x00]// NULL
    ]
  );

  // construct outer sequence
  var bytes = encodeSequence([rsaEncSequence, neBitString]);
  
  var buffer = "";
  for (var i=0;i<bytes.length;i++) { 
    buffer += int2char((bytes[i] & 0xf0) >> 4);
    buffer += int2char(bytes[i] & 0x0f);
  }
  buffer = hex2b64(buffer);
  var newlineBuffer = "";
  for (var i=0;i<buffer.length;i++) { 
    if (i>0 && (i % 64) == 0) newlineBuffer += "\n";
    newlineBuffer += buffer[i];
  }
  return "-----BEGIN PUBLIC KEY-----\n" + newlineBuffer + "\n-----END PUBLIC KEY-----\n";
}

RSAKey.prototype.readPublicKeyFromPEMString = _rsapem_readPublicKeyFromPEMString;

RSAKey.prototype.serializePrivateASN1 = RSAPrivateKeySerializeASN1;
RSAKey.prototype.serializePublicASN1 = RSAPublicKeySerializeASN1;

