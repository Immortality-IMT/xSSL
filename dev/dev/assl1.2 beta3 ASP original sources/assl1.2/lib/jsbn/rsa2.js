// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.
// Incapsulated by Francesco Sullo (www.sullof.com), december 2006


// Depends on rsa.js and jsbn2.js


// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext

if (typeof JSBN != 'undefined') {

	JSBN.RSA.pkcs1unpad2 = function (d,n) {
	  var b = d.toByteArray();
	  var i = 0;
	  while(i < b.length && b[i] == 0) ++i;
	  if(b.length-i != n-1 || b[i] != 2)
		return null;
	  ++i;
	  while(b[i] != 0)
		if(++i >= b.length) return null;
	  var ret = "";
	  while(++i < b.length)
		ret += String.fromCharCode(b[i]);
	  return ret;
	};
	
	
	// Set the private key fields N, e, and d from hex strings
	JSBN.RSA.RSAKey.prototype.setPrivate = function (N,E,D) {
	  if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = JSBN.RSA.parseBigInt(N,16);
		this.e = parseInt(E,16);
		this.d = JSBN.RSA.parseBigInt(D,16);
	  }
	  else
		alert("Invalid RSA private key");
	};
	
	
	// Set the private key fields N, e, d and CRT params from hex strings
	JSBN.RSA.RSAKey.prototype.setPrivateEx = function (N,E,D,P,Q,DP,DQ,C) {
	  if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = JSBN.RSA.parseBigInt(N,16);
		this.e = parseInt(E,16);
		this.d = JSBN.RSA.parseBigInt(D,16);
		this.p = JSBN.RSA.parseBigInt(P,16);
		this.q = JSBN.RSA.parseBigInt(Q,16);
		this.dmp1 = JSBN.RSA.parseBigInt(DP,16);
		this.dmq1 = JSBN.RSA.parseBigInt(DQ,16);
		this.coeff = JSBN.RSA.parseBigInt(C,16);
	  }
	  else alert("Invalid RSA private key");
	};
	
	
	// Generate a new random private key B bits long, using public expt E
	JSBN.RSA.RSAKey.prototype.generate = function (B,E) {
	  var rng = new JSBN.RNG.SecureRandom();
	  var qs = B>>1;
	  this.e = parseInt(E,16);
	  var ee = new JSBN.BigInteger(E,16);
	  for(;;) {
		for(;;) {
		  this.p = new JSBN.BigInteger(B-qs,1,rng);
		  if(this.p.subtract(JSBN.BigInteger.ONE).gcd(ee).compareTo(JSBN.BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
		}
		for(;;) {
		  this.q = new JSBN.BigInteger(qs,1,rng);
		  if(this.q.subtract(JSBN.BigInteger.ONE).gcd(ee).compareTo(JSBN.BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
		}
		if(this.p.compareTo(this.q) <= 0) {
		  var t = this.p;
		  this.p = this.q;
		  this.q = t;
		}
		var p1 = this.p.subtract(JSBN.BigInteger.ONE);
		var q1 = this.q.subtract(JSBN.BigInteger.ONE);
		var phi = p1.multiply(q1);
		if(phi.gcd(ee).compareTo(JSBN.BigInteger.ONE) == 0) {
		  this.n = this.p.multiply(this.q);
		  this.d = ee.modInverse(phi);
		  this.dmp1 = this.d.mod(p1);
		  this.dmq1 = this.d.mod(q1);
		  this.coeff = this.q.modInverse(this.p);
		  break;
		}
	  }
	};
	
	
	// Perform raw private operation on "x": return x^d (mod n)
	JSBN.RSA.RSAKey.prototype.doPrivate = function (x) {
	  if(this.p == null || this.q == null)
		return x.modPow(this.d, this.n);
	
	  // TODO: re-calculate any missing CRT params
	  var xp = x.mod(this.p).modPow(this.dmp1, this.p);
	  var xq = x.mod(this.q).modPow(this.dmq1, this.q);
	
	  while(xp.compareTo(xq) < 0)
		xp = xp.add(this.p);
	  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
	};
	
	
	// Return the PKCS#1 RSA decryption of "ctext".
	// "ctext" is an even-length hex string and the output is a plain string.
	JSBN.RSA.RSAKey.prototype.decrypt = function (ctext) {
	  var c = JSBN.RSA.parseBigInt(ctext, 16);
	  var m = this.doPrivate(c);
	  if(m == null) return null;
	  return JSBN.RSA.pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
	};
	
	// Return the PKCS#1 RSA decryption of "ctext".
	// "ctext" is a Base64-encoded string and the output is a plain string.
	//function RSAB64Decrypt(ctext) {
	//  var h = b64tohex(ctext);
	//  if(h) return this.decrypt(h); else return null;
	//}

};