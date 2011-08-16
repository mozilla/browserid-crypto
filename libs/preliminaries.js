// faking some objects so all goes well
if (typeof(navigator) == "undefined") {
  var navigator = {
    appName: "Netscape"
  };

  var window = {
    atob: function(str) {
      return new Buffer(str, 'base64').toString('utf-8');
    },
    btoa: function(str) {
      return new Buffer(str).toString('base64');
    }
  };
}


var sha1 = {
  hex: function(){
    }
};

var sha256 = {
  hex: function(i) {return sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(i));}
};