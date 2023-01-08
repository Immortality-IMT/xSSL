

aSSL = {
	
//
// aSSL - Ajax Secure Service Layer - version 1.2beta3
// Copyright (c) 2006, 2007 Francesco Sullo, www.sullof.com
//
// aSSL is freely distributable under the terms of the following MIT license:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy 
// of this software and associated documentation files (the "Software"), to 
// deal in the Software without restriction, including without limitation the 
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
// sell copies of the Software, and to permit persons to whom the Software is 
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
// IN THE SOFTWARE.
//
// For more information about aSSL look at: http://assl.sullof.com
//	

	vername: 'aSSL', version: '1.2beta3', verdate: '2006-01-08',
	
// if you put this to false before Session brokes aSSL negotiate a new exchange key:
	onlyMantainSession: true,

	connections: [],

	_init: function (conn) {
		aSSL._current = conn ? conn : '0';
		var a = aSSL._current, b = aSSL.connections;
		if (!b[a]) b[a] = [];
		return b[a];
	},

// 128-bit = 16 chars
	keySize: 16,

	_randomKeyGenerator: function (nn) {
		var v, n = !nn || isNaN(nn) ? this.keySize : nn, ret = [];
		for (var x=0; x<n; x++) {
			v = Math.floor(Math.random() * 257);
			if (v == 0 || v == 257) { x--; continue; }
			ret[ret.length] = v;
		}
		var s = '';
  		for (var i=0; i<ret.length; i++) s += ret[i].toString(16);
		return s;
	},

	_getStringFromHex: function (str) {
		var h = '';
		for (var j=0;j<32;j=j+2)
			h += String.fromCharCode(parseInt(str.substring(j,j+2),16));
		return h;
	},
	
	encrypt: function (txt,conn) {
		var key0 = this._getStringFromHex(this._init(conn).key);
		return this.encode(AES.encrypt(txt,key0));
	},
	
	decrypt: function (txt,conn) {
		var key0 = this._getStringFromHex(this._init(conn).key);
		return AES.decrypt(this.decode(txt),key0);
	},

	connect: function (url,callback,conn) {
		var currc = this._init(conn);
		var now = new Date();
		currc._startedAt = now.getTime()
		currc.connUrl = url;
		currc.response = callback;
		aSSL._request(url,{aSSLConnName: this._current, aSSLOMS: currc.sessionTimeout && this.onlyMantainSession ? 1 : ''},this._connect2);
	},

	_connect2: function (res) {
		var currc = aSSL.connections[aSSL._current];
		if (currc.sessionTimeout && aSSL.onlyMantainSession) aSSL._afterConn();
		else {
			currc.key = aSSL._randomKeyGenerator();
			var rsa = new JSBN.RSA.RSAKey();
			var response = res.responseText.split("|");
			rsa.setPublic(response[0],response[1]);
			var res = rsa.encrypt(currc.key);
			var cryptedkey = JSBN.RSA.linebrk(res, 256);
			aSSL._request(currc.connUrl,{aSSLConnName:aSSL._current,aSSLCKey:cryptedkey},aSSL._afterConn);
		}
	},

	_afterConn: function (response) {
		var sto, currc = aSSL.connections[aSSL._current];
		if (response) sto = parseInt(response.responseText,10);
		if (sto) currc.sessionTimeout = sto;
		if (currc.sessionTimeout) currc.timeId = setTimeout("aSSL._autoConnect('"+aSSL._current+"')",1000*(currc.sessionTimeout-30));
		var now = new Date();
		currc.timeElapsed = now.getTime() - currc._startedAt;
		if (currc.response) currc.response(response);
	},
	
	_autoConnect: function (cc) {
		var currc = aSSL.connections[cc];
		clearTimeout(currc.timeId);
		aSSL.connect(currc.connUrl);
	},
	
	debug: function () {},

	_transport: function () {
		if (typeof XMLHttpRequest != 'undefined') return new XMLHttpRequest();
		else try { return new ActiveXObject("Microsoft.XMLHTTP"); } catch (e) {}
		return aSSL.debug("XMLHttpRequest not supported");
	},

	_request: function (url,parameters,callback) {
		if (!url) return aSSL.debug("Url missing.");
		var par = parameters || {};
		url = this._setUrl(url) + aSSL.toQuerystr(par);

//		prompt("",url);

		var cb = callback || function(){};
   		var tr = aSSL._transport();
		aSSL.pendings++;
		tr.onreadystatechange = function() {
			aSSL.pendings--;
			if (tr.readyState == 4) cb(tr);
    	};
		tr.open('GET',url,true);
		tr.send(null);
	},

	_setUrl: function (url) {
		return url.split('#')[0]+(/(\?|&)$/.test(url)?'':(/&/.test(url)||/\?[^\?]+/.test(url))?'&':'?');
	},

	toQuerystr: function (h) {
		var p = '';
		for (var j in h) { if (h[j]) { p += (p?'&':'') + j + "=" + h[j] } else { break }}
		return p;
	},

	querystr: function (x) {
		var qs = [];
		var xx = x ? x : location.search.replace(/^\?/,"");
		qs[0] = xx;
		var couple = xx.split("&");
		for (var j=0;j<couple.length;j++) {
			var kx = couple[j].split("=");
			qs[kx[0]] = kx[1];
		}
		return qs;
	},
	
	encode: function (txt) {
		var v = this._strToLongs(txt);
		var ret = "";
		for (var j=0;j<v.length;j++) { ret += (ret?"x":"")+v[j] }
		return ret;
	},
	
	decode: function (txt) {
		var vv = txt.split("x");
		v = [];
		str = "";
		for (var j=0;j<vv.length;j++) {
			v[j] = parseInt(vv[j],10);
			str += vv[j]+"\n";
		}
		return this._longsToStr(v).replace(/\0+$/,'');
	},
	
// Thanks to Chris Veness // www.movable-type.co.uk
// for the following two methods	

	_strToLongs: function (s) {
		var ll = Math.ceil(s.length/4);
		var l = new Array(ll);
		for (var i=0; i<ll; i++) {
			l[i] = s.charCodeAt(i*4)
				+ (s.charCodeAt(i*4+1)<<8)
				+ (s.charCodeAt(i*4+2)<<16)
				+ (s.charCodeAt(i*4+3)<<24);
		}
		return l;
	},

	_longsToStr: function (l) {
		var a = new Array(l.length);
		for (var i=0; i<l.length; i++) {
			a[i] = String.fromCharCode(
				l[i] & 0xFF,
				l[i]>>>8 & 0xFF,
				l[i]>>>16 & 0xFF,
				l[i]>>>24 & 0xFF
			);
		}
		return a.join('');
	}
};
