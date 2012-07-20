console.log('');
console.log('****Bundling VEP for Browser****');
console.log('');

var fs = require('fs');
var path = require('path');
var existsSync = fs.existsSync || path.existsSync;

var browserify = require('browserify');
var uglify = require('uglify-js');

var BUNDLE_DIR = path.join(__dirname, '../');
var INPUT = path.join(BUNDLE_DIR, './bundle.js');
var TMP = path.join(BUNDLE_DIR, './tempbundle.js');
var PRELIM = path.join(BUNDLE_DIR, './bundle-prelim.js');
var OUTPUT = path.join(BUNDLE_DIR, './bidbundle.js');
var OUTPUT_MIN = path.join(BUNDLE_DIR, './bidbundle-min.js');

// do package.js script here
require('./package');

if (existsSync(OUTPUT)) {
  fs.unlinkSync(OUTPUT);
}

var bundle = browserify({ exports: 'require' });
bundle.ignore(['crypto', 'bigint']);
bundle.addEntry(INPUT);

var bundleSource = bundle.bundle();
var bundlePrelim = fs.readFileSync(PRELIM);

var bundleOutput = bundlePrelim + '\n' + bundleSource;

fs.writeFileSync(OUTPUT, bundleOutput);

// and now make it all ugly
fs.writeFileSync(OUTPUT_MIN, uglify(bundleOutput));
