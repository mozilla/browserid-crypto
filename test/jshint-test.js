/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// jshinting (syntax checking) of the source

const vows = require("vows"),
      fs = require('fs'),
      path = require('path'),
      jshint = require('jshint').JSHINT,
      walk = require('walk'),
      util = require('util'),
      assert = require('assert');

var suite = vows.describe('jshint');

function jshintFormatter(errors) {
  return errors.map(function(e) {
    return e.error.reason + ' ' + e.file + ':' + e.error.line;
  });
}

var jshintrc = null;

suite.addBatch({
  '.jshintrc': {
    topic: function() {
      fs.readFile(path.join(__dirname, '../.jshintrc'), this.callback);
    },
    "should be readable": function(err, string) {
      assert(!err);
      assert(string);
    },
    "should parse": {
      topic: function(string) {
        this.callback(null, JSON.parse(string));
      },
      "ok": function(err, json) {
        jshintrc = json;
      }
    }
  }
});

suite.addBatch({
  'code syntax': {
    topic: function() {
      var filesToLint = [
        path.join(__dirname, '../index.js')
      ];

      var walker = walk.walkSync(path.join(__dirname, '../lib'), {});

      walker.on("file", function(root, fStat, next) {
        var f = path.join(root, fStat.name);
        if (/\.js$/.test(f)) {
          filesToLint.push(f);
        }
        next();
      });
      var self = this;
      walker.on("end", function() {
        self.callback(null, filesToLint);
      });
    },
    "for all implementation files": {
      topic: function(filesToLint) {
        var errors = [];
        var self = this;

        function checkNext() {
          if (!filesToLint.length) {
            if (errors.length) {
              var buf = util.format("%d jshint errors", errors.length);
              self.callback(buf);
            } else {
              self.callback(null);
            }
            return;
          }
          var f = filesToLint.shift();
          fs.readFile(f.toString(), function(err, data) {
            // now
            f = path.relative(process.cwd(), f);
            if (!jshint(data.toString(), jshintrc)) {
              jshint.errors.forEach(function(e) {
                if (e) {
                  var msg = util.format("%s %s:%d - %s", e.id, f, e.line, e.reason);
                  console.error(msg);
                  errors.push(msg);
                }
              });
            }
            checkNext();
          });
        }
        checkNext();
      },
      "should lint cleanly": function(err) { }
    }
  }
});

// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
