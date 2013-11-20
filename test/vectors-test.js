/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var vows = require("vows"),
    assert = require("assert"),
    utils = require("../lib/utils"),
    jwcrypto = require("../index");

require("../lib/algs/rs");
require("../lib/algs/ds");

// all "extracted" conformance test values are encoded as hex,
// whether the key format is hex or otherwise.

var ASSERTIONS = [
  {
    assertion: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjcuMC4wLjEiLCJleHAiOjEzMzU1NjI2OTg3NjgsImlhdCI6MTMzNTU1OTA5ODc2OCwicHVibGljLWtleSI6eyJhbGdvcml0aG0iOiJEUyIsInkiOiIyN2Y2OTgzMWIzNzdlMmY1NzRiZGE5Njg1YWJmNTM5OTY1ZDAyNDI2Mjg0ZDZmYzViOWVkMjA0MzJmN2U5Yjg1YTFjMjJiMTQ2M2I0NmQwMzljMTIzOWJkZWI2NDc1ZDZjMDM0MWJlZmRiYzBjYjJmMjQ4MTUzYjRjMzFkZDMxNWFjZjFkZmY0ZWUwYmY2NGY4OTUyN2VlMTlmNTkxNTM3NWFjZTNkNTZjMWQ1NDUzY2FjNmRkMTE4NzU3NTI3MmRhYjBlZGQzMGYxYjRlOTI2Yzg3YTNlNGFjYWY2NmY5MmZlZDFhMDRhYjI3Y2NjNDkxM2FmZTI0ZGRjZjNmZTk4IiwicCI6ImZmNjAwNDgzZGI2YWJmYzViNDVlYWI3ODU5NGIzNTMzZDU1MGQ5ZjFiZjJhOTkyYTdhOGRhYTZkYzM0ZjgwNDVhZDRlNmUwYzQyOWQzMzRlZWVhYWVmZDdlMjNkNDgxMGJlMDBlNGNjMTQ5MmNiYTMyNWJhODFmZjJkNWE1YjMwNWE4ZDE3ZWIzYmY0YTA2YTM0OWQzOTJlMDBkMzI5NzQ0YTUxNzkzODAzNDRlODJhMThjNDc5MzM0MzhmODkxZTIyYWVlZjgxMmQ2OWM4Zjc1ZTMyNmNiNzBlYTAwMGMzZjc3NmRmZGJkNjA0NjM4YzJlZjcxN2ZjMjZkMDJlMTciLCJxIjoiZTIxZTA0ZjkxMWQxZWQ3OTkxMDA4ZWNhYWIzYmY3NzU5ODQzMDljMyIsImciOiJjNTJhNGEwZmYzYjdlNjFmZGYxODY3Y2U4NDEzODM2OWE2MTU0ZjRhZmE5Mjk2NmUzYzgyN2UyNWNmYTZjZjUwOGI5MGU1ZGU0MTllMTMzN2UwN2EyZTllMmEzY2Q1ZGVhNzA0ZDE3NWY4ZWJmNmFmMzk3ZDY5ZTExMGI5NmFmYjE3YzdhMDMyNTkzMjllNDgyOWIwZDAzYmJjNzg5NmIxNWI0YWRlNTNlMTMwODU4Y2MzNGQ5NjI2OWFhODkwNDFmNDA5MTM2YzcyNDJhMzg4OTVjOWQ1YmNjYWQ0ZjM4OWFmMWQ3YTRiZDEzOThiZDA3MmRmZmE4OTYyMzMzOTdhIn0sInByaW5jaXBhbCI6eyJlbWFpbCI6ImJlbkBhZGlkYS5uZXQifX0.MklRRWfQweUwYR2crhFU2EuLyUOZlpY4zJgg9LSWDF1MQIGJtNZAclB_tU4sNWfWyrHBa6ICXGfT9mMbkWwPIZC714clAkCMAQXiL2FhuzZSHlnYRO0_BFLO0LqtxIbwdGAQ0WvmaS5lPCgwHdoJbIHPVupebT1C-nUUu21pBoFI_8sPjzINwGBlE6K6WQQy0KbF2m0VDZY5EAYa4mh4o84xiABCoYZYSEeA9FIzmYRJEVrqYHjQeVucZdqkDDCTEK49nVIR4hi8Mm1EItYDn__HDydZORotzfOHuLmB9xyVgBX_tcKJ9mND7MQJVeOumhDAx9QyXtRUhPhKUTDNgA~eyJhbGciOiJEUzEyOCJ9.eyJleHAiOjEzMzU1NTk0MTU3MzMsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTAwMDEifQ.BBoFaSGq0UAYDi9vdbsoBegeJ7FHVDxzODiV8MD8pF0emOPp1i_Uzg",
    root: {"algorithm":"RS","n":"13717766671510433111303151806101127171813773557424962001210686599690717644398501153133960329815327700526221729490916021955004415636643109524427762578738613915853895591332921269523141755077814022043323454871557827878869765578483437974192481801184235473918125161566266295979176194039841474030846700306142580608077665527626562098429368267997746767380874004089196208403356658867000112308693077043530239627194850786092251128137244380236693014852428390414510793421293487373711079360003639159681004539188014924495483277607084448583613608953997565952445532663265804891482606228128383798830560843667395414521699843061983900619","e":"65537"}
  }
];

// lots of redundant stuff in here to make sure that we are doing
// parsing of keys properly.
var PUBLIC_KEYS = [
  // some older format
  {key:
   {"algorithm":"RS","n":"13717766671510433111303151806101127171813773557424962001210686599690717644398501153133960329815327700526221729490916021955004415636643109524427762578738613915853895591332921269523141755077814022043323454871557827878869765578483437974192481801184235473918125161566266295979176194039841474030846700306142580608077665527626562098429368267997746767380874004089196208403356658867000112308693077043530239627194850786092251128137244380236693014852428390414510793421293487373711079360003639159681004539188014924495483277607084448583613608953997565952445532663265804891482606228128383798830560843667395414521699843061983900619","e":"65537"},
   "algorithm": "RSA",
   "modulus": "6caa67a080c2f20e61d8395ed28914398c100e9d0dce3542dcf74013098438239873ac1376769f09f99779f21e68a529bc8d41145e27990ccd3522594844c35143884b135a1eb5ddf0944db124aa4f125a753f9e336a52c7e2dff89832509e6b2c3932dede84bc2c4d138ba956e0f00e2888365bc0f60125753eca43d4ae1ba09c74a9f70dd4b9063cae2d7857e21e12c2336e652d906aa462dd838053208bb5a5ef5bfe2d1f4a9584c95f16d6b81052c58df5fd4927d0aece42937ba25f0612d59dc92151f32fc86196f4e22a74ba410070683bf86f6cac24153185a867fbb149ea96471a0b10aabc390659b2f2db05305e58f66be80c2ff7798fa4e85673cb",
   "exponent": "10001"
  },
  {key:
   {"algorithm":"DS","y":"85340755e9ccc1396aa37482e8e078f2a5c105f5ddf0fbd67c4c878638fa0d0ab6d500282739f3913f32854d0592c89721779997918464051f3a7a17ce8410a1282dbbe5a1fc7fa0925fc0dc3928dd1d021d1d47a4566ed33391313f99b6ce514ff6d6499cb78d3ea8d374768b72140bd5060b898d5a2afba3bc1fceec4ef58e43d4b0eb5ad06f3acf1574af94327137f36ede81bc7f34e8b52c4d57ef42380829259839202c420b60ddfba6238014b21f7d368b020e69ac4991639986e14f63588a1bf774ac9b4589357a2d12f4a1540afb4ec295a8bddf75446618d9ae07d24cc8e198cfdabbaec85d92e194db82a8c8e539ab6b081e9260f041fd549dd59c","p":"d6c4e5045697756c7a312d02c2289c25d40f9954261f7b5876214b6df109c738b76226b199bb7e33f8fc7ac1dcc316e1e7c78973951bfc6ff2e00cc987cd76fcfb0b8c0096b0b460fffac960ca4136c28f4bfb580de47cf7e7934c3985e3b3d943b77f06ef2af3ac3494fc3c6fc49810a63853862a02bb1c824a01b7fc688e4028527a58ad58c9d512922660db5d505bc263af293bc93bcd6d885a157579d7f52952236dd9d06a4fc3bc2247d21f1a70f5848eb0176513537c983f5a36737f01f82b44546e8e7f0fabc457e3de1d9c5dba96965b10a2a0580b0ad0f88179e10066107fb74314a07e6745863bc797b7002ebec0b000a98eb697414709ac17b401","q":"b1e370f6472c8754ccd75e99666ec8ef1fd748b748bbbc08503d82ce8055ab3b","g":"9a8269ab2e3b733a5242179d8f8ddb17ff93297d9eab00376db211a22b19c854dfa80166df2132cbc51fb224b0904abb22da2c7b7850f782124cb575b116f41ea7c4fc75b1d77525204cd7c23a15999004c23cdeb72359ee74e886a1dde7855ae05fe847447d0a68059002c3819a75dc7dcbb30e39efac36e07e2c404b7ca98b263b25fa314ba93c0625718bd489cea6d04ba4b0b7f156eeb4c56c44b50e4fb5bce9d7ae0d55b379225feb0214a04bed72f33e0664d290e7c840df3e2abb5e48189fa4e90646f1867db289c6560476799f7be8420a6dc01d078de437f280fff2d7ddf1248d56e1a54b933a41629d6c252983c58795105802d30d7bcd819cf6ef"},
   "algorithm": "DSA",
   "y": "85340755e9ccc1396aa37482e8e078f2a5c105f5ddf0fbd67c4c878638fa0d0ab6d500282739f3913f32854d0592c89721779997918464051f3a7a17ce8410a1282dbbe5a1fc7fa0925fc0dc3928dd1d021d1d47a4566ed33391313f99b6ce514ff6d6499cb78d3ea8d374768b72140bd5060b898d5a2afba3bc1fceec4ef58e43d4b0eb5ad06f3acf1574af94327137f36ede81bc7f34e8b52c4d57ef42380829259839202c420b60ddfba6238014b21f7d368b020e69ac4991639986e14f63588a1bf774ac9b4589357a2d12f4a1540afb4ec295a8bddf75446618d9ae07d24cc8e198cfdabbaec85d92e194db82a8c8e539ab6b081e9260f041fd549dd59c",
   "p":"d6c4e5045697756c7a312d02c2289c25d40f9954261f7b5876214b6df109c738b76226b199bb7e33f8fc7ac1dcc316e1e7c78973951bfc6ff2e00cc987cd76fcfb0b8c0096b0b460fffac960ca4136c28f4bfb580de47cf7e7934c3985e3b3d943b77f06ef2af3ac3494fc3c6fc49810a63853862a02bb1c824a01b7fc688e4028527a58ad58c9d512922660db5d505bc263af293bc93bcd6d885a157579d7f52952236dd9d06a4fc3bc2247d21f1a70f5848eb0176513537c983f5a36737f01f82b44546e8e7f0fabc457e3de1d9c5dba96965b10a2a0580b0ad0f88179e10066107fb74314a07e6745863bc797b7002ebec0b000a98eb697414709ac17b401",
   "q":"b1e370f6472c8754ccd75e99666ec8ef1fd748b748bbbc08503d82ce8055ab3b",
   "g":"9a8269ab2e3b733a5242179d8f8ddb17ff93297d9eab00376db211a22b19c854dfa80166df2132cbc51fb224b0904abb22da2c7b7850f782124cb575b116f41ea7c4fc75b1d77525204cd7c23a15999004c23cdeb72359ee74e886a1dde7855ae05fe847447d0a68059002c3819a75dc7dcbb30e39efac36e07e2c404b7ca98b263b25fa314ba93c0625718bd489cea6d04ba4b0b7f156eeb4c56c44b50e4fb5bce9d7ae0d55b379225feb0214a04bed72f33e0664d290e7c840df3e2abb5e48189fa4e90646f1867db289c6560476799f7be8420a6dc01d078de437f280fff2d7ddf1248d56e1a54b933a41629d6c252983c58795105802d30d7bcd819cf6ef"   
  },
  
  // newer format stuff
  {key: {"algorithm":"RS","version":"2012.08.15","modulus":"Zx5aDEB62oTwkoTikAp4ck+HGQv4oIa8+L5KdjcANbvjR2jtXAjswepZrwvzYFhP/mwFl/Oy4YElW3OyPy9I6K0OR0xQgBsOprpEOFNEFs14Jy9LJi59yb4gA+xSUlN/SN8s0JKzQ2jYwD8ibZicZWt2C2vvyaBmWaUZm2o5V59DYH6D7ecZSPkwWi9PoD3lCeK2ZeJa7jZpD02bCvybbwyFnDPca2o9MP7/r8Fs6BWJqGAIxlDqvvLUZ+2CeKAie5a98lyBvE//kc0ANY9yjDcWp+c7IXx+lSn5AobiicM2PbiWUdqAXWOguf61ooT1yGazSAeAhZElcy+jd8VZ3Q==","exponent":"AQAB"},
   algorithm: "RSA",
   modulus: "671e5a0c407ada84f09284e2900a78724f87190bf8a086bcf8be4a76370035bbe34768ed5c08ecc1ea59af0bf360584ffe6c0597f3b2e181255b73b23f2f48e8ad0e474c50801b0ea6ba4438534416cd78272f4b262e7dc9be2003ec5252537f48df2cd092b34368d8c03f226d989c656b760b6befc9a06659a5199b6a39579f43607e83ede71948f9305a2f4fa03de509e2b665e25aee36690f4d9b0afc9b6f0c859c33dc6b6a3d30feffafc16ce81589a86008c650eabef2d467ed8278a0227b96bdf25c81bc4fff91cd00358f728c3716a7e73b217c7e9529f90286e289c3363db89651da805d63a0b9feb5a284f5c866b3480780859125732fa377c559dd",
   exponent: "10001"
  },
  {key: {"algorithm":"DS","version":"2012.08.15","y":"EgxmUUA4YD/wNDJH3mX+QTIiIwDtn2cAaCkXr0HGKFN3eTuoOqt6iCvTXEkFZCSIog9ml6wKIasJO8mcT+ZVD+40oD+CXKeRJ7LXPnpSuB5rSvgUxEtVY4/8wWra5RnhoHn8BOgb6tq/zOn9EEV6nE6h/t4rVb/dLW1QTono1Q8=","p":"/2AEg9tqv8W0Xqt4WUs1M9VQ2fG/Kpkqeo2qbcNPgEWtTm4MQp0zTu6q79fiPUgQvgDkzBSSy6MluoH/LVpbMFqNF+s79KBqNJ05LgDTKXRKUXk4A0ToKhjEeTNDj4keIq7vgS1pyPdeMmy3DqAAw/d239vWBGOMLvcX/CbQLhc=","q":"4h4E+RHR7XmRAI7Kqzv3dZhDCcM=","g":"xSpKD/O35h/fGGfOhBODaaYVT0r6kpZuPIJ+Jc+mz1CLkOXeQZ4TN+B6Lp4qPNXepwTRdfjr9q85fWnhELlq+xfHoDJZMp5IKbDQO7x4lrFbSt5T4TCFjMNNliaaqJBB9AkTbHJCo4iVydW8ytTzia8dekvROYvQct/6iWIzOXo="},
   algorithm: "DSA",
   y: "120c66514038603ff0343247de65fe4132222300ed9f6700682917af41c6285377793ba83aab7a882bd35c4905642488a20f6697ac0a21ab093bc99c4fe6550fee34a03f825ca79127b2d73e7a52b81e6b4af814c44b55638ffcc16adae519e1a079fc04e81beadabfcce9fd10457a9c4ea1fede2b55bfdd2d6d504e89e8d50f",
   p: "ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17",
   q: "e21e04f911d1ed7991008ecaab3bf775984309c3",
   g: "c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a"
  }
  
];

var SECRET_KEYS = [
  // some older format
  {key: {"algorithm":"RS","n":"20134313735633460324009287026871866843796618829620508645366930147178633379962222680717023249272820533094597858267338839317194088010291491177769775876107422860068508860247049222474149118476550449553385103674247179042986058916353175342114256161775949273688758085819167193333453685722288255237120463565853164873820456398458238032740006210438495274446844719785231515965591829050825221266535165134208095847989613986610614188375152043921071400070392986604047644804201712592855063810754615032686203014888431566402289466164948592805558518095237018685881993839526503295276463699240570317434052145766048425317464308591867033229","e":"65537","d":"19912193271912768320801042607377102668932573245998804451543589278716388359077643176037858688654784168210221181710168294726713423261654221419899755155622419476821952992478329009650113690967531941305721990776853634778706660704709014856093403708887290785737265461865564527956947482893699604420994640059160581474789494003360406077834187408037753163211562475595869258819628232479453155832681163098548915011781484585176809911841844302069549440225122202503690543386025709106303300834368406079203744646769675025699622363046762636041586213509577129540673029343027227311933661272432441022093661699434070335168027711025359541953"},
   "algorithm": "RSA",
   "modulus": "9f7e96b93b49734d9879f490b67ed1ca8c82c6f2fd0348721a1c820b3bc5cdcbeb58af3a4c161443d4bee3c62bfb778c659170fb0307187bef2f397306fa9575fd5538880464a29629f198370897c0cdc3cfa6298aec9b38cb5da4f3e2c3f706d7d5b5e30ce20c9fd98c6eee91b911d91127739e9dac96d7c775e1fed22c13a5b56e205c8cdb809d28a8496e326ec2fbef1103a14e5ac7f4c864e934e22ba5797fff05be25b95e8599932ef8bd23dc08140c7ae39d4b4f52aec9607da6e51a68b08560707e72b6dde8d5b4f92a8e263c05078597e3f5dd8390581214d9beef4baa63f36a7488049dcd3f463248f14d472d1d6e3776ed68232c0b184bcad9768d",
   "exponent": "10001",
   "secretExponent": "9dbc25f7fee83f3e2863c4393222edfbf1468cd756de5e5169fd73a70470357d4cbda25e774d06b1a6bf3aa88c6adfea5bb0a119bdfed07a112c95166b7a7b41fb4ec2dfd1e86cdb31941b43a21de2b21ccb49bba0072be3d94c3d8c6d61fcf62992d3953ef27825c6931a4a9a977b4d3fa7d2b2b5a130752a702d1744680eecaabae446478a1178235049796f4d54e9092886f6ee8ae369f262ff378b459daa3e055358e7ffbb7ebce84bb2f4fe35029617a934f4cfefdaa8c3bae18e85a83a22e3080c33388df3f979f3316affe74e62fe6a4ac4cb2604ccd243fdaa07fd332f5b9b5e203ea127c8fa81608c253c2310eee12c18fc821fb59dda5621ead6c1"
  },
  {key:
   {"algorithm":"DS","x":"c80486db596571fe799240b371b1a214b9809d45","p":"ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17","q":"e21e04f911d1ed7991008ecaab3bf775984309c3","g":"c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a"},
   "algorithm": "DSA",
   "x":"c80486db596571fe799240b371b1a214b9809d45",
   "p":"ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17","q":"e21e04f911d1ed7991008ecaab3bf775984309c3",
   "g":"c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a"
  },
  {
    key: {"algorithm":"RS","version":"2012.08.15","modulus":"Zx5aDEB62oTwkoTikAp4ck+HGQv4oIa8+L5KdjcANbvjR2jtXAjswepZrwvzYFhP/mwFl/Oy4YElW3OyPy9I6K0OR0xQgBsOprpEOFNEFs14Jy9LJi59yb4gA+xSUlN/SN8s0JKzQ2jYwD8ibZicZWt2C2vvyaBmWaUZm2o5V59DYH6D7ecZSPkwWi9PoD3lCeK2ZeJa7jZpD02bCvybbwyFnDPca2o9MP7/r8Fs6BWJqGAIxlDqvvLUZ+2CeKAie5a98lyBvE//kc0ANY9yjDcWp+c7IXx+lSn5AobiicM2PbiWUdqAXWOguf61ooT1yGazSAeAhZElcy+jd8VZ3Q==","exponent":"AQAB","secretExponent":"Kh75xVtpU21OH2tsaE3+mSLnGlILgvbGpgyEufkJeul+kyLHIfr7StKBQ8Fr7oTkWBajykffX8GzEsIVoz2bWH+n/3OqxklHGM+pIiDRBUd0tvzYg4YmF4wz46ZakgpNSeTvl1r1IqnnL9AaLg5ShBL7Kvsx/XgplqCb7yHavnFoQiVB5Fg4fEoUxrOzRrTkssxS5rverkczW5speghsOiEffszkW8tF7rh/xdIelh8xGVfCANkLVaYb9L/4vgZ/ZcCvLcC2oFOCDB1335QSO9iNvMon71r3xER8397cYAFArRExfdYcts8NKkJJ86dsJhydoqG8as72VLge3dQYAQ=="},
   algorithm: "RSA",
   modulus: "671e5a0c407ada84f09284e2900a78724f87190bf8a086bcf8be4a76370035bbe34768ed5c08ecc1ea59af0bf360584ffe6c0597f3b2e181255b73b23f2f48e8ad0e474c50801b0ea6ba4438534416cd78272f4b262e7dc9be2003ec5252537f48df2cd092b34368d8c03f226d989c656b760b6befc9a06659a5199b6a39579f43607e83ede71948f9305a2f4fa03de509e2b665e25aee36690f4d9b0afc9b6f0c859c33dc6b6a3d30feffafc16ce81589a86008c650eabef2d467ed8278a0227b96bdf25c81bc4fff91cd00358f728c3716a7e73b217c7e9529f90286e289c3363db89651da805d63a0b9feb5a284f5c866b3480780859125732fa377c559dd",
   exponent: "10001",
    secretExponent: "2a1ef9c55b69536d4e1f6b6c684dfe9922e71a520b82f6c6a60c84b9f9097ae97e9322c721fafb4ad28143c16bee84e45816a3ca47df5fc1b312c215a33d9b587fa7ff73aac6494718cfa92220d1054774b6fcd8838626178c33e3a65a920a4d49e4ef975af522a9e72fd01a2e0e528412fb2afb31fd782996a09bef21dabe7168422541e458387c4a14c6b3b346b4e4b2cc52e6bbdeae47335b9b297a086c3a211f7ecce45bcb45eeb87fc5d21e961f311957c200d90b55a61bf4bff8be067f65c0af2dc0b6a053820c1d77df94123bd88dbcca27ef5af7c4447cdfdedc600140ad11317dd61cb6cf0d2a4249f3a76c261c9da2a1bc6acef654b81eddd41801"
  },
  {
    key: {"algorithm":"DS","version":"2012.08.15","x":"rwzgsSIrU6h+BleE/2wDM7sZZtk=","p":"/2AEg9tqv8W0Xqt4WUs1M9VQ2fG/Kpkqeo2qbcNPgEWtTm4MQp0zTu6q79fiPUgQvgDkzBSSy6MluoH/LVpbMFqNF+s79KBqNJ05LgDTKXRKUXk4A0ToKhjEeTNDj4keIq7vgS1pyPdeMmy3DqAAw/d239vWBGOMLvcX/CbQLhc=","q":"4h4E+RHR7XmRAI7Kqzv3dZhDCcM=","g":"xSpKD/O35h/fGGfOhBODaaYVT0r6kpZuPIJ+Jc+mz1CLkOXeQZ4TN+B6Lp4qPNXepwTRdfjr9q85fWnhELlq+xfHoDJZMp5IKbDQO7x4lrFbSt5T4TCFjMNNliaaqJBB9AkTbHJCo4iVydW8ytTzia8dekvROYvQct/6iWIzOXo="},
    algorithm: "DSA",
    p: "ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17",
    q: "e21e04f911d1ed7991008ecaab3bf775984309c3",
    g: "c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a",
    x: "af0ce0b1222b53a87e065784ff6c0333bb1966d9"
  }
];

var CERTS = [
  {"cert": "eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWMta2V5Ijp7ImFsZ29yaXRobSI6IkRTIiwieSI6ImJlODNmMWNmNGRjMjU2OWFmODIyYjZiNWM1NDE3OTJlMzIxZDljNjE5NGVhNTY3MTQyZTk4NjllNDk1YmIyNWZiZjQ5NjkzYzZmNTc3ZWZlMTYyMDkzZWYyN2M3YzU1MGVjM2Q4MTBiZjAwNWU1MjNkM2VlNmM3NzM0NmUwNWZkY2Q5YWRmNTg0NjcwYjM2ODAwNWIxZWQyZTI2YWRjMGVlZjliMmE4NzFkN2Q1MWU1NjAxMzQ5ODIyNzEwZjMwMjhhNThiNWFmNDVmNzJiODM2NmY1MzA5MzZhOThjYTdlYWZjN2JhMzFkNmUxMzYzNjM2NWUxMTNhMGE1YjYyNmMiLCJwIjoiZmY2MDA0ODNkYjZhYmZjNWI0NWVhYjc4NTk0YjM1MzNkNTUwZDlmMWJmMmE5OTJhN2E4ZGFhNmRjMzRmODA0NWFkNGU2ZTBjNDI5ZDMzNGVlZWFhZWZkN2UyM2Q0ODEwYmUwMGU0Y2MxNDkyY2JhMzI1YmE4MWZmMmQ1YTViMzA1YThkMTdlYjNiZjRhMDZhMzQ5ZDM5MmUwMGQzMjk3NDRhNTE3OTM4MDM0NGU4MmExOGM0NzkzMzQzOGY4OTFlMjJhZWVmODEyZDY5YzhmNzVlMzI2Y2I3MGVhMDAwYzNmNzc2ZGZkYmQ2MDQ2MzhjMmVmNzE3ZmMyNmQwMmUxNyIsInEiOiJlMjFlMDRmOTExZDFlZDc5OTEwMDhlY2FhYjNiZjc3NTk4NDMwOWMzIiwiZyI6ImM1MmE0YTBmZjNiN2U2MWZkZjE4NjdjZTg0MTM4MzY5YTYxNTRmNGFmYTkyOTY2ZTNjODI3ZTI1Y2ZhNmNmNTA4YjkwZTVkZTQxOWUxMzM3ZTA3YTJlOWUyYTNjZDVkZWE3MDRkMTc1ZjhlYmY2YWYzOTdkNjllMTEwYjk2YWZiMTdjN2EwMzI1OTMyOWU0ODI5YjBkMDNiYmM3ODk2YjE1YjRhZGU1M2UxMzA4NThjYzM0ZDk2MjY5YWE4OTA0MWY0MDkxMzZjNzI0MmEzODg5NWM5ZDViY2NhZDRmMzg5YWYxZDdhNGJkMTM5OGJkMDcyZGZmYTg5NjIzMzM5N2EifSwicHJpbmNpcGFsIjp7ImVtYWlsIjoidXNlckBleGFtcGxlaWRwLmNvbSJ9LCJpYXQiOjEzNDI2MzQzNTU5MTMsImV4cCI6MTM0MjYzNDM2MTkxMywiaXNzIjoiZXhhbXBsZWlkcC5jb20ifQ.EOe_edjbSfgeyYZZgD1KaCax2ZBCi2_spd8ngvejRUaZZPsrSvNrmc3BZreTYSQAp895zmgSBbC7StaMBWclQzU4gBFMw9kXzSoDUOsXc3kBY1yYju0FsN1JwLf2znci_O1Tj4jEacJMHLRZSuEg0SVZJLQNgp7c4uHd4RSRR42sik8hB_fYAyzM57kZQCPV7Bx3ag_9aIDB1yiylAaMBHkxpOmDgJPEk-UMBMSgw4Mi7Daf7LpfdF7UExRr5hyrO_KUxCcxX2tU3WaH6lreFluPQYV5p_rr863WTg_iTu7OQBLiS2RR89VtKEVcf-b_mXF-dzU2n4T-ikK8GLCXkw",
   "issued_at":1342634355913,"expires_at":1342634361913,"issuer":"exampleidp.com",
   "email": "user@exampleidp.com",
   "certifierPublicKey": {"algorithm":"RS","n":"14992830413702950214310095212044491259620359262383741324696388958190897089691526259734048412721912364240221301689826865084526414386073707804839978986676709963946069225361038897793675105866773424177081334731736862288361853661697790251045350661007112837048725805572051406892322870828536513516637815563734426985085169776230353505099335068959396036415837272499551706990150656379682592552383284722119011793645821942132094135988926383389368449569136547237729302181561293580509148227224997417221099523657138090327493805636962561720869470208329064396135474786068129369609669835010448697628273776942729022409017231229381035477","e":"65537"},
   "containedPublicKey": {"algorithm":"DS","y":"be83f1cf4dc2569af822b6b5c541792e321d9c6194ea567142e9869e495bb25fbf49693c6f577efe162093ef27c7c550ec3d810bf005e523d3ee6c77346e05fdcd9adf584670b368005b1ed2e26adc0eef9b2a871d7d51e5601349822710f3028a58b5af45f72b8366f530936a98ca7eafc7ba31d6e13636365e113a0a5b626c","p":"ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17","q":"e21e04f911d1ed7991008ecaab3bf775984309c3","g":"c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a"}
  },
  {
    cert: "eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWNLZXkiOnsiYWxnb3JpdGhtIjoiRFMiLCJ2ZXJzaW9uIjoiMjAxMi4wOC4xNSIsInkiOiJFZ3htVVVBNFlEL3dOREpIM21YK1FUSWlJd0R0bjJjQWFDa1hyMEhHS0ZOM2VUdW9PcXQ2aUN2VFhFa0ZaQ1NJb2c5bWw2d0tJYXNKTzhtY1QrWlZEKzQwb0QrQ1hLZVJKN0xYUG5wU3VCNXJTdmdVeEV0Vlk0Lzh3V3JhNVJuaG9IbjhCT2diNnRxL3pPbjlFRVY2bkU2aC90NHJWYi9kTFcxUVRvbm8xUTg9IiwicCI6Ii8yQUVnOXRxdjhXMFhxdDRXVXMxTTlWUTJmRy9LcGtxZW8ycWJjTlBnRVd0VG00TVFwMHpUdTZxNzlmaVBVZ1F2Z0RrekJTU3k2TWx1b0gvTFZwYk1GcU5GK3M3OUtCcU5KMDVMZ0RUS1hSS1VYazRBMFRvS2hqRWVUTkRqNGtlSXE3dmdTMXB5UGRlTW15M0RxQUF3L2QyMzl2V0JHT01MdmNYL0NiUUxoYz0iLCJxIjoiNGg0RStSSFI3WG1SQUk3S3F6djNkWmhEQ2NNPSIsImciOiJ4U3BLRC9PMzVoL2ZHR2ZPaEJPRGFhWVZUMHI2a3BadVBJSitKYyttejFDTGtPWGVRWjRUTitCNkxwNHFQTlhlcHdUUmRmanI5cTg1ZlduaEVMbHEreGZIb0RKWk1wNUlLYkRRTzd4NGxyRmJTdDVUNFRDRmpNTk5saWFhcUpCQjlBa1RiSEpDbzRpVnlkVzh5dFR6aWE4ZGVrdlJPWXZRY3QvNmlXSXpPWG89In0sInByaW5jaXBhbCI6eyJlbWFpbCI6InVzZXJAZXhhbXBsZWlkcC5jb20ifSwidmVyc2lvbiI6IjIwMTIuMDguMTUiLCJpYXQiOjEzNDI4MDE2OTA1NzAsImV4cCI6MTM0MjgwMTY5NjU3MCwiaXNzIjoiZXhhbXBsZWlkcC5jb20ifQ.IP1owFXMabG0FtLJmp9owqy5KdaY1qMERNpaCgvBZxccofC4cGRqJGsvNbPMMWlxRYUt_jR6F2M_hSEXHDJQrAhthZGaZYEDTRZIkBVQO_ufA7_6VeeY5Z-cvUBaXEtJD0HsYJhSDRsUS3WdTyCJasv7csA6_4ovuNm69rmY3QxlQs0wux4tAN_5P5xM6Y4rZwZaBpdLRmwxGcObEsQ_OS6c8OER5TSXrbKaFPL5iThL5xI_mdi7mCqcwPnPtLwcV2ARQ3qFqd8Xf30RP5cAetC-0pwr4o4xuby81ZRjf-ulp5lIbLE_uZVTgSZbIR3aP6edqrdJ-wZYf_oDQnNQbA",
    "issued_at":1342801690570,"expires_at":1342801696570,"issuer":"exampleidp.com",
    "email":"user@exampleidp.com",
    certifierPublicKey: {"algorithm":"RS","version":"2012.08.15","modulus":"Zx5aDEB62oTwkoTikAp4ck+HGQv4oIa8+L5KdjcANbvjR2jtXAjswepZrwvzYFhP/mwFl/Oy4YElW3OyPy9I6K0OR0xQgBsOprpEOFNEFs14Jy9LJi59yb4gA+xSUlN/SN8s0JKzQ2jYwD8ibZicZWt2C2vvyaBmWaUZm2o5V59DYH6D7ecZSPkwWi9PoD3lCeK2ZeJa7jZpD02bCvybbwyFnDPca2o9MP7/r8Fs6BWJqGAIxlDqvvLUZ+2CeKAie5a98lyBvE//kc0ANY9yjDcWp+c7IXx+lSn5AobiicM2PbiWUdqAXWOguf61ooT1yGazSAeAhZElcy+jd8VZ3Q==","exponent":"AQAB"},
    containedPublicKey: {"algorithm":"DS","version":"2012.08.15","y":"EgxmUUA4YD/wNDJH3mX+QTIiIwDtn2cAaCkXr0HGKFN3eTuoOqt6iCvTXEkFZCSIog9ml6wKIasJO8mcT+ZVD+40oD+CXKeRJ7LXPnpSuB5rSvgUxEtVY4/8wWra5RnhoHn8BOgb6tq/zOn9EEV6nE6h/t4rVb/dLW1QTono1Q8=","p":"/2AEg9tqv8W0Xqt4WUs1M9VQ2fG/Kpkqeo2qbcNPgEWtTm4MQp0zTu6q79fiPUgQvgDkzBSSy6MluoH/LVpbMFqNF+s79KBqNJ05LgDTKXRKUXk4A0ToKhjEeTNDj4keIq7vgS1pyPdeMmy3DqAAw/d239vWBGOMLvcX/CbQLhc=","q":"4h4E+RHR7XmRAI7Kqzv3dZhDCcM=","g":"xSpKD/O35h/fGGfOhBODaaYVT0r6kpZuPIJ+Jc+mz1CLkOXeQZ4TN+B6Lp4qPNXepwTRdfjr9q85fWnhELlq+xfHoDJZMp5IKbDQO7x4lrFbSt5T4TCFjMNNliaaqJBB9AkTbHJCo4iVydW8ytTzia8dekvROYvQct/6iWIzOXo="}
  }
];

var BACKED_ASSERTIONS = [
  {"assertion": "eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWMta2V5Ijp7ImFsZ29yaXRobSI6IkRTIiwieSI6IjczNzAxMTViMzAzNDllMzg5NzgwMzRlMTBjYjRkMzExYmFmNGVhYzkyZmM1M2IzNWMyYTc5ODBkZmEwZDVmZGY1NDYwOWQyYzU2YTNhNTc3NGRhYjg0YjAxZWVjN2E2Nzc2OTRjYWY1MDFlZGZhNGUzMDg1YWYzMjk3ZGZlNTg0NTkwZmFkN2Y1YjgzMzI3NDE5Njk0NWE5OTg1ODc4NGI1OGJmYzBiNjZhNjk3NGVjYjcwMjdkMzkwODliMDI2MjYzNTJhYjFjODZhYjliMmVlYmMwZmZiZGQwOWFkZDNkNDBlZDI0MjAyMzg4YjQ1ODg2ZGI3MTQyMzQ4NWRmNGUiLCJwIjoiZmY2MDA0ODNkYjZhYmZjNWI0NWVhYjc4NTk0YjM1MzNkNTUwZDlmMWJmMmE5OTJhN2E4ZGFhNmRjMzRmODA0NWFkNGU2ZTBjNDI5ZDMzNGVlZWFhZWZkN2UyM2Q0ODEwYmUwMGU0Y2MxNDkyY2JhMzI1YmE4MWZmMmQ1YTViMzA1YThkMTdlYjNiZjRhMDZhMzQ5ZDM5MmUwMGQzMjk3NDRhNTE3OTM4MDM0NGU4MmExOGM0NzkzMzQzOGY4OTFlMjJhZWVmODEyZDY5YzhmNzVlMzI2Y2I3MGVhMDAwYzNmNzc2ZGZkYmQ2MDQ2MzhjMmVmNzE3ZmMyNmQwMmUxNyIsInEiOiJlMjFlMDRmOTExZDFlZDc5OTEwMDhlY2FhYjNiZjc3NTk4NDMwOWMzIiwiZyI6ImM1MmE0YTBmZjNiN2U2MWZkZjE4NjdjZTg0MTM4MzY5YTYxNTRmNGFmYTkyOTY2ZTNjODI3ZTI1Y2ZhNmNmNTA4YjkwZTVkZTQxOWUxMzM3ZTA3YTJlOWUyYTNjZDVkZWE3MDRkMTc1ZjhlYmY2YWYzOTdkNjllMTEwYjk2YWZiMTdjN2EwMzI1OTMyOWU0ODI5YjBkMDNiYmM3ODk2YjE1YjRhZGU1M2UxMzA4NThjYzM0ZDk2MjY5YWE4OTA0MWY0MDkxMzZjNzI0MmEzODg5NWM5ZDViY2NhZDRmMzg5YWYxZDdhNGJkMTM5OGJkMDcyZGZmYTg5NjIzMzM5N2EifSwicHJpbmNpcGFsIjp7ImVtYWlsIjoidXNlckBleGFtcGxlaWRwLmNvbSJ9LCJpYXQiOjEzNDI2MzU5NTEwMjcsImV4cCI6MTM0MjYzNTk1NzAyNywiaXNzIjoiZXhhbXBsZWlkcC5jb20ifQ.ivdVg3r2kjU26PqicsHrCDKPK_9LNWMbZ7OjAdpXOsi4sGNdSolHM609eT-xoRUdhVz67sq9wnSmtUv1BMOupeSi7i4DCNSwUWHPBH4DOAswG0nCficHjvgrqaOCBOQ95Dk8dLLd9kcf1P_gLmkVVFAaKlPkOawWCoHaF8FBlBIgU9tWYJ5jbSCT6dCwKbBeESTzKzDHV53O6g1Fr-uMZ8-EXnMHhakkxXoF94Tpu-_cuwy3BNVMxWOLpuwb8S9PnF98DCRR9X_6e3UYMNlejOGjSEIalkhFb0dMlj93oIYqUjyrpZxwUPXDrhpxvQFW-tN2PXUAtlID6vjp_n52bg~eyJhbGciOiJEUzEyOCJ9.eyJpYXQiOjEzNDI2MzU5NTEwMjcsImV4cCI6MTM0MjYzNTk1NzAyNywiYXVkIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9.VVg3pg9wwe_g5Kg2GwgdnGtZftxPpGLqd-LHjucpiw9sgkDGHs-I5A",
   "certifyingKey": {"algorithm":"RS","n":"22065728673523995313275840949283186147733361077125922117151884405727929358603197277862449100403401708874580160739851743372607390289312514176219745745061161080731994997513081977238890869729018736569475296178956470173744597843997030482898117646152273158717073309419015545324220626878746740658868160778804057923124408381754223997324049665565313870157861356938746339320398255353426803343525261847622455643513993816581672201295385001276849331760685387802142681675064994849190179959904536701035730762770114494100415667933501396487866806200962527123706046621867087261935508571250402047499424810996126895397600099821060652017","e":"65537"},
   "issued_at":1342635951027,"expires_at":1342635957027,"audience":"https://example.com",
   "email": 'user@exampleidp.com'
  },
  {
    assertion: "eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWNLZXkiOnsiYWxnb3JpdGhtIjoiRFMiLCJ2ZXJzaW9uIjoiMjAxMi4wOC4xNSIsInkiOiJFZ3htVVVBNFlEL3dOREpIM21YK1FUSWlJd0R0bjJjQWFDa1hyMEhHS0ZOM2VUdW9PcXQ2aUN2VFhFa0ZaQ1NJb2c5bWw2d0tJYXNKTzhtY1QrWlZEKzQwb0QrQ1hLZVJKN0xYUG5wU3VCNXJTdmdVeEV0Vlk0Lzh3V3JhNVJuaG9IbjhCT2diNnRxL3pPbjlFRVY2bkU2aC90NHJWYi9kTFcxUVRvbm8xUTg9IiwicCI6Ii8yQUVnOXRxdjhXMFhxdDRXVXMxTTlWUTJmRy9LcGtxZW8ycWJjTlBnRVd0VG00TVFwMHpUdTZxNzlmaVBVZ1F2Z0RrekJTU3k2TWx1b0gvTFZwYk1GcU5GK3M3OUtCcU5KMDVMZ0RUS1hSS1VYazRBMFRvS2hqRWVUTkRqNGtlSXE3dmdTMXB5UGRlTW15M0RxQUF3L2QyMzl2V0JHT01MdmNYL0NiUUxoYz0iLCJxIjoiNGg0RStSSFI3WG1SQUk3S3F6djNkWmhEQ2NNPSIsImciOiJ4U3BLRC9PMzVoL2ZHR2ZPaEJPRGFhWVZUMHI2a3BadVBJSitKYyttejFDTGtPWGVRWjRUTitCNkxwNHFQTlhlcHdUUmRmanI5cTg1ZlduaEVMbHEreGZIb0RKWk1wNUlLYkRRTzd4NGxyRmJTdDVUNFRDRmpNTk5saWFhcUpCQjlBa1RiSEpDbzRpVnlkVzh5dFR6aWE4ZGVrdlJPWXZRY3QvNmlXSXpPWG89In0sInByaW5jaXBhbCI6eyJlbWFpbCI6InVzZXJAZXhhbXBsZWlkcC5jb20ifSwidmVyc2lvbiI6IjIwMTIuMDguMTUiLCJpYXQiOjEzNDI4MDE2OTA1NzAsImV4cCI6MTM0MjgwMTY5NjU3MCwiaXNzIjoiZXhhbXBsZWlkcC5jb20ifQ.IP1owFXMabG0FtLJmp9owqy5KdaY1qMERNpaCgvBZxccofC4cGRqJGsvNbPMMWlxRYUt_jR6F2M_hSEXHDJQrAhthZGaZYEDTRZIkBVQO_ufA7_6VeeY5Z-cvUBaXEtJD0HsYJhSDRsUS3WdTyCJasv7csA6_4ovuNm69rmY3QxlQs0wux4tAN_5P5xM6Y4rZwZaBpdLRmwxGcObEsQ_OS6c8OER5TSXrbKaFPL5iThL5xI_mdi7mCqcwPnPtLwcV2ARQ3qFqd8Xf30RP5cAetC-0pwr4o4xuby81ZRjf-ulp5lIbLE_uZVTgSZbIR3aP6edqrdJ-wZYf_oDQnNQbA~eyJhbGciOiJEUzEyOCJ9.eyJpYXQiOjEzNDI4MDE2OTA1NzAsImV4cCI6MTM0MjgwMTY5NjU3MCwiYXVkIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInZlcnNpb24iOiIyMDEyLjA4LjE1In0.ytUhc5Zt71ZtUmYnf7jaRfC10Y4zbzQweNXIMRO-bC0z8wrBuM42gA",
    "issued_at":1342801690570,"expires_at":1342801696570,
    "audience":"https://example.com",
    "email": 'user@exampleidp.com',
    certifyingKey: {"algorithm":"RS","version":"2012.08.15","modulus":"Zx5aDEB62oTwkoTikAp4ck+HGQv4oIa8+L5KdjcANbvjR2jtXAjswepZrwvzYFhP/mwFl/Oy4YElW3OyPy9I6K0OR0xQgBsOprpEOFNEFs14Jy9LJi59yb4gA+xSUlN/SN8s0JKzQ2jYwD8ibZicZWt2C2vvyaBmWaUZm2o5V59DYH6D7ecZSPkwWi9PoD3lCeK2ZeJa7jZpD02bCvybbwyFnDPca2o9MP7/r8Fs6BWJqGAIxlDqvvLUZ+2CeKAie5a98lyBvE//kc0ANY9yjDcWp+c7IXx+lSn5AobiicM2PbiWUdqAXWOguf61ooT1yGazSAeAhZElcy+jd8VZ3Q==","exponent":"AQAB"}
  }
];

var assertion = ASSERTIONS[0].assertion;
var pk = jwcrypto.loadPublicKeyFromObject(ASSERTIONS[0].root);
var now = new Date();

// times
var timeOfCert = 1335562698768;
var timeOfAssertion = 1335559415733;

// a bit before both cert and assertion
var timeThatShouldWork = new Date(Math.min(timeOfCert, timeOfAssertion) - 1000);

var suite = vows.describe('vectors');

suite.addBatch(
  {
    "verifying a test-vector assertion that is expired" : {
      topic: function() {
        jwcrypto.cert.verifyBundle(
          assertion, now, function(issuer, next) {
            next(null, pk);
          },
          this.callback);
      },
      "fails appropriately": function(err, certParamsArray, payload, assertionParams) {
        assert.equal(err, "certificate expired");
      }
    }
})

suite.addBatch(
  {
    "verifying a test-vector assertion with appropriate verif time" : {
      topic: function() {
        jwcrypto.cert.verifyBundle(
          assertion, timeThatShouldWork, function(issuer, next) {
            next(null, pk);
          },
          this.callback);
      },
      "succeed": function(err, certParamsArray, payload, assertionParams) {
        assert.isNull(err);
      },
      "contains the right fields": function(err, certParamsArray, payload, assertionParams) {
        assert.isNotNull(assertionParams.expiresAt);
        assert.isNotNull(assertionParams.expiresAt.getFullYear);        
        assert.isString(assertionParams.audience);

        assert.isUndefined(assertionParams.aud);
        assert.isUndefined(assertionParams.exp);        
        assert.isUndefined(payload.aud);
        assert.isUndefined(payload.exp);        
      }
    }    
});

// check the public keys
var addPublicKeyBatch = function(pkObject) {
  suite.addBatch({
    "loading a public key": {
      topic: function() {
        return jwcrypto.loadPublicKey(JSON.stringify(pkObject.key));
      },
      "succeeds": function(pk) {
        assert.ok(pk);
      },
      "has the right fields": function(pk) {
        if (pkObject.algorithm == "RSA") {
          assert.ok(pk.rsa.n);
          assert.ok(pk.rsa.e);
        }

        if (pkObject.algorithm == "DSA") {
          assert.ok(pk.y);
          assert.ok(pk.g);
          assert.ok(pk.q);
          assert.ok(pk.p);          
        }
      },
      "has fields with correct values": function(pk) {
        if (pkObject.algorithm == "RSA") {
          assert.equal(pk.rsa.n.toString(16), pkObject.modulus);
          assert.equal(pk.rsa.e.toString(16), pkObject.exponent);
        }

        if (pkObject.algorithm == "DSA") {
          assert.equal(pk.y.toString(16), pkObject.y);
          assert.equal(pk.g.toString(16), pkObject.g);
          assert.equal(pk.q.toString(16), pkObject.q);
          assert.equal(pk.p.toString(16), pkObject.p);          
        }
      },
      "two reserializations equals the same thing": function(pk) {
        assert.equal(jwcrypto.loadPublicKey(pk.serialize()).serialize(), pk.serialize());
      }
    }
  });
};


PUBLIC_KEYS.forEach(function(pkObject) {
  addPublicKeyBatch(pkObject);
});

// check the secret keys
var addSecretKeyBatch = function(skObject) {
  suite.addBatch({
    "loading a secret key": {
      topic: function() {
        return jwcrypto.loadSecretKey(JSON.stringify(skObject.key));
      },
      "succeeds": function(sk) {
        assert.ok(sk);
      },
      "has the right fields": function(sk) {
        if (skObject.algorithm == "RSA") {
          assert.ok(sk.rsa.n);
          assert.ok(sk.rsa.d);
          assert.ok(sk.rsa.e);          
        }

        if (skObject.algorithm == "DSA") {
          assert.ok(sk.x);
          assert.ok(sk.g);
          assert.ok(sk.q);
          assert.ok(sk.p);        
        }
      },
      "has fields with correct values": function(sk) {
        if (skObject.algorithm == "RSA") {
          assert.equal(sk.rsa.n.toString(16), skObject.modulus);
          assert.equal(sk.rsa.e.toString(16), skObject.exponent);
          assert.equal(sk.rsa.d.toString(16), skObject.secretExponent);
        }

        if (skObject.algorithm == "DSA") {
          assert.equal(sk.x.toString(16), skObject.x);
          assert.equal(sk.g.toString(16), skObject.g);
          assert.equal(sk.q.toString(16), skObject.q);
          assert.equal(sk.p.toString(16), skObject.p);          
        }
      },
      "two reserializations equals the same thing": function(sk) {
        assert.equal(jwcrypto.loadSecretKey(sk.serialize()).serialize(), sk.serialize());
      }
    }
  });
};


SECRET_KEYS.forEach(function(skObject) {
  addSecretKeyBatch(skObject);
});


// check the certs
var addCertBatch = function(certObject) {
  suite.addBatch({
    "verifying a cert": {
      topic: function() {
        var certifierPublicKey = jwcrypto.loadPublicKeyFromObject(certObject.certifierPublicKey);
        jwcrypto.cert.verify(
          certObject.cert, certifierPublicKey,
          new Date(certObject.issued_at),
          this.callback);
      },
      "succeeds": function(err, payload, assertionParams, certParams) {
        assert.isNull(err);
      },
      "contains the right parameters": function(err, payload, assertionParams, certParams) {
        assert.equal(assertionParams.issuedAt.valueOf(), certObject.issued_at);
        assert.equal(assertionParams.expiresAt.valueOf(), certObject.expires_at);
        assert.equal(assertionParams.issuer, certObject.issuer);
      },
      "contains the right public key": function(err, payload, assertionParams, certParams) {
        assert.isDefined(certParams.publicKey, "public key not present under .publicKey parameter");
        assert.ok(certParams.publicKey.equals(jwcrypto.loadPublicKeyFromObject(certObject.containedPublicKey)));
      },
      "contains the right email": function(err, payload, assertionParams, certParams) {
        assert.equal(certParams.principal.email, certObject.email);
      }
      
    }
  });
};


CERTS.forEach(function(certObject) {
  addCertBatch(certObject);
});

// check the backed assertions
var addBackedAssertionBatch = function(backedAssertionObject) {
  suite.addBatch({
    "verifying a backed assertion": {
      topic: function() {
        var certifyingKey = jwcrypto.loadPublicKeyFromObject(backedAssertionObject.certifyingKey);
        jwcrypto.cert.verifyBundle(
          backedAssertionObject.assertion, new Date(backedAssertionObject.issued_at),
          function(issuer, next) {
            // ignore issuer
            next(null, certifyingKey);
          },
          this.callback);
      },
      "succeeds": function(err, certParamsArray, payload, assertionParams) {
        assert.isNull(err);
      },
      "contains the right parameters": function(err, certParamsArray, payload, assertionParams) {
        assert.equal(assertionParams.issuedAt.valueOf(), backedAssertionObject.issued_at);
        assert.equal(assertionParams.expiresAt.valueOf(), backedAssertionObject.expires_at);
      },
      "certifies the right user": function(err, certParamsArray, payload, assertionParams) {
        assert.equal(certParamsArray[0].certParams.principal.email, backedAssertionObject.email);
      },
      "contains the right audience": function(err, certParamsArray, payload, assertionParams) {
        assert.equal(assertionParams.audience, backedAssertionObject.audience);
      }      
    }
  });
};

BACKED_ASSERTIONS.forEach(function(backedAssertionObject) {
  addBackedAssertionBatch(backedAssertionObject);
});

suite.export(module);
