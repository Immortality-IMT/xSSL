<%


BlockTEA = {

//
// 'Block' Tiny Encryption Algorithm xxtea
// (c) 2002-2006 Chris Veness <scripts@movable-type.co.uk>
//
// Algorithm: David Wheeler & Roger Needham, Cambridge University Computer Lab
//            http://www.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html (1994)
//            http://www.cl.cam.ac.uk/ftp/users/djw3/xtea.ps (1997)
//            http://www.cl.cam.ac.uk/ftp/users/djw3/xxtea.ps (1998)
//
// JavaScript implementation: Chris Veness, Movable Type Ltd: www.movable-type.co.uk
// http://www.movable-type.co.uk/scripts/TEAblock.html
//
// You are welcome to re-use these scripts [without any warranty express or implied]
// provided you retain my copyright notice and when possible a link to my website.
// If you have any queries or find any problems, please contact Chris Veness.
//
//
// Original script adapted for aSSL by Francesco Sullo <sullof@sullof.com>
//

	vername: 'BlockTEA',
	language: 'ASP/JScript',
	version: '1.0',
	verdate: '2006-10-23'
	,

	
// to obtain a standard ciphertext put notNumeric = true
	
	teaencrypt: function (plaintext, key, notNumeric) {
		if (plaintext.length == 0) return('');
		var v = this.strToLongs(plaintext);
		if (v.length <= 1) v[1] = 0;
		var k = this.strToLongs(key.slice(0,16));
		var n = v.length;
		var z = v[n-1], y = v[0], delta = 0x9E3779B9;
		var mx, e, q = Math.floor(6 + 52/n), sum = 0;
		while (q-- > 0) {
			sum += delta;
			e = sum>>>2 & 3;
			for (var p = 0; p < n; p++) {
				y = v[(p+1) % n];
				mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
				z = v[p] += mx;
			}
		}
		if (notNumeric) {
    		return this.longsToStr(v);
		}
		var ret = "";
		for (var j=0;j<v.length;j++) { ret += (ret?"x":"")+v[j] }
		return ret
	}
	,


// to decrypt starting from a standard ciphertext put notNumeric = true

	teadecrypt: function (ciphertext, key, notNumeric) {
		if (ciphertext.length == 0) return('');
		var v, n
		k = this.strToLongs(key.slice(0,16)); 
		if (notNumeric) {
			v = this.strToLongs(ciphertext);
			n = v.length;
		}
		else {
			var vv = ciphertext.split("x");
			n = vv.length;
			v = [];
			for (var j=0;j<n;j++) {
				v[j] = parseInt(vv[j],10)
			}
		}
		var z = v[n-1], y = v[0], delta = 0x9E3779B9;
		var mx, e, q = Math.floor(6 + 52/n), sum = q*delta;
		while (sum != 0) {
			e = sum>>>2 & 3;
			for (var p = n-1; p >= 0; p--) {
				z = v[p>0 ? p-1 : n-1];
				mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
				y = v[p] -= mx;
			}
			sum -= delta
		}
		return this.longsToStr(v).replace(/\0+$/,'')
	}
	,

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

