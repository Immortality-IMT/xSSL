<%

aSSL = {

//
// aSSL for ASP version 1.2beta3 - 8 january 2007
// Copyright (c) 2006, 2007 Francesco Sullo <sullof@sullof.com>
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

	vername: 'aSSL',
	language: 'ASP/JScript',
	version: '1.2beta3',
	verdate: '2007-01-08'
	,

	init: new function () {
		if (!Session("aSSL")) Session("aSSL") = {};
		if (!Session("aSSL").aSSLconn) Session("aSSL").aSSLconn = {}
	}
	,
	
	getStringFromHex: function (str) {
		var h = ''
		for (var j=0;j<32;j=j+2) {
			h += String.fromCharCode(parseInt(str.substring(j,j+2),16))
		}
		return h
	}
	,
	
	encrypt: function (txt,conn) {
		var cn = conn ? conn : '0';
		var key0 = this.getStringFromHex(Session("aSSL").aSSLconn[cn].key)
		return this.encode(AES.encrypt(txt,key0))
	}
	,
	
	decrypt: function (txt,key,conn) {
		var cn = conn ? conn : '0';
		var key0 = this.getStringFromHex(Session("aSSL").aSSLconn[cn].key)
		return AES.decrypt(this.decode(txt),key0)
	}
	,


	write: function (str) {
		Response.Clear();
		Response.Write(str?str:'');
		Response.End()
	}
	,

	response: function (sk) {
		var QS = this.querystr();
		var cn = QS.aSSLConnName;
		if (QS.aSSLOMS) this.write(1)
		else if (QS.aSSLCKey) {
			var rsa = new JSBN.RSA.RSAKey();
			rsa.setPrivateEx(sk[0],sk[1],sk[2],sk[3],sk[4],sk[5],sk[6],sk[7]);
			var res = rsa.decrypt(QS.aSSLCKey);
			if (res == null) this.write('error')
			else {
				Session("aSSL").aSSLconn[cn].key = res;
				this.write(Session.Timeout*60)
			}		
		}
		else {
			Session("aSSL").aSSLconn[cn] = []
			this.write(sk[0]+"|"+sk[1])
		}
	}
	,

	send: function (txt,conn) {
		var QS = this.querystr();
		this.write(this.encrypt(txt,null,conn?conn:QS.aSSLConnName))
	}
	,

	querystr: function (x) {
		var qs = [];
		var xx = x ? x : Request.QueryString().Item;
		qs[0] = xx;
		var couple = xx.split("&");
		for (var j=0;j<couple.length;j++) {
			var kx = couple[j].split("=");
			qs[kx[0]] = x ? kx[1] : Request.QueryString(kx[0]).Item //kx[1]
		}
		return qs
	}	
	,
	
	encode: function (txt) {
		var v = BlockTEA4aSSL.strToLongs(txt)
		var ret = "";
		for (var j=0;j<v.length;j++) { ret += (ret?"x":"")+v[j] }
		return ret
	}
	,
	
	decode: function (txt) {
		var vv = txt.split("x");
		v = [];
		str = ""
		for (var j=0;j<vv.length;j++) {
			v[j] = parseInt(vv[j],10)
			str += vv[j]+"\n"
		}
		return this.longsToStr(v).replace(/\0+$/,'')	
	}
	,
	
// Thanks to Chris Veness // www.movable-type.co.uk
// for the following two methods	
	
	strToLongs: function (s) {
		var ll = Math.ceil(s.length/4);
		var l = new Array(ll);
		for (var i=0; i<ll; i++) {
			l[i] = s.charCodeAt(i*4)
				+ (s.charCodeAt(i*4+1)<<8)
				+ (s.charCodeAt(i*4+2)<<16)
				+ (s.charCodeAt(i*4+3)<<24);
		}
		return l;
	}
	,

	longsToStr: function (l) {
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
}



		
%>

