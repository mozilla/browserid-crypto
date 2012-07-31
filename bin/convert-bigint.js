#!/usr/bin/env node

var BigInteger = require("../libs/minimal").BigInteger;

var args = require('optimist')
.usage('Convert BigInt\nUsage: $0')
.alias('i', 'in')
.describe('i', 'format for input, can be dec,hex')
.demand('i')
.alias('o', 'out')
.describe('o', 'format for output, can be dec,hex')
.demand('o')
.string('_');

var argv = args.argv;

if (argv.h) {
  args.showHelp();
  process.exit(1);
}

var the_bigint;

switch (argv.i) {
 case 'dec':
  the_bigint = new BigInteger(argv._[0], 10);
  break;
 case 'hex':
  the_bigint = new BigInteger(argv._[0], 16);
  break;
 case 'b64':
  the_bigint = BigInteger.fromBase64(argv._[0]);
  break;
}

var output;

switch (argv.o) {
 case 'dec':
  output = the_bigint.toString(10);
  break;
 case 'hex':
  output = the_bigint.toString(16);
  break;
 case 'b64':
  output = the_bigint.toBase64();
  break;
}

console.log(output);
