console.log('');
console.log('***Packaging External Dependencies****');
console.log('');

var fs = require('fs');
var path = require('path');

var existsSync = fs.existsSync || path.existsSync;

var LIBS_DIR = path.join(__dirname, '../libs');
var PACKAGE = path.join(LIBS_DIR, './package.txt');
var MINIMAL_PACKAGE = path.join(LIBS_DIR, './minimal_package.txt');
var OUTPUT = path.join(LIBS_DIR, './all.js');
var MINIMAL_OUTPUT = path.join(LIBS_DIR, './minimal.js');

// snagged this from nodejs 0.8
var appendFileSync = fs.appendFileSync || function(path, data) {
  var fd = fs.openSync(path, 'a');
  if (!Buffer.isBuffer(data)) {
    data = Buffer.from('' + data, 'utf8');
  }
  var written = 0;
  var position = null;
  var length = data.length;
  try {
    while (written < length) {
      written += fs.writeSync(fd, data, written, length - written, position);
      position += written;
    }
  } finally {
    fs.closeSync(fd);
  }
}

function copyFilesFromList(inFile, outFile) {
  var filenames = String(fs.readFileSync(inFile)).split(/\r?\n/);
  filenames.forEach(function(fname) {
    if (fname) {
      appendFileSync(outFile, fs.readFileSync(path.join(LIBS_DIR, fname)));
    }
  });
}

if (!existsSync(PACKAGE)) {
  throw new Error('no package.txt file, oh blarg');
}

if (existsSync(OUTPUT)) {
  fs.unlinkSync(OUTPUT);
}

copyFilesFromList(PACKAGE, OUTPUT);

if (!existsSync(MINIMAL_PACKAGE)) {
  throw new Error('no minimal package file, oh blarg');
}

if (existsSync(MINIMAL_OUTPUT)) {
  fs.unlinkSync(MINIMAL_OUTPUT);
}

copyFilesFromList(MINIMAL_PACKAGE, MINIMAL_OUTPUT);
