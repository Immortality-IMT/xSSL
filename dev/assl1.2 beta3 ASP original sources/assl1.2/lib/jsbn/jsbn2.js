// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.
// Incapsulated by Francesco Sullo (www.sullof.com), december 2006

// Extended JavaScript BN functions, required for RSA private ops.

if (typeof JSBN != 'undefined') {

	var BI = JSBN.BigInteger;
	
	// (public)
	BI.prototype.clone = function () { var r = JSBN.nbi(); this.copyTo(r); return r; };
	
	// (public) return value as integer
	BI.prototype.intValue = function () {
	  if(this.s < 0) {
		if(this.t == 1) return this[0]-this.DV;
		else if(this.t == 0) return -1;
	  }
	  else if(this.t == 1) return this[0];
	  else if(this.t == 0) return 0;
	  // assumes 16 < DB < 32
	  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
	};
	
	// (public) return value as byte
	BI.prototype.byteValue = function () { return (this.t==0)?this.s:(this[0]<<24)>>24; };
	
	// (public) return value as short (assumes DB>=16)
	BI.prototype.shortValue = function () { return (this.t==0)?this.s:(this[0]<<16)>>16; };
	
	// (protected) return x s.t. r^x < DV
	BI.prototype.chunkSize = function (r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); };
	
	// (public) 0 if this == 0, 1 if this > 0
	BI.prototype.signum = function () {
	  if(this.s < 0) return -1;
	  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
	  else return 1;
	};
	
	// (protected) convert to radix string
	BI.prototype.toRadix = function (b) {
	  if(b == null) b = 10;
	  if(this.signum() == 0 || b < 2 || b > 36) return "0";
	  var cs = this.chunkSize(b);
	  var a = Math.pow(b,cs);
	  var d = JSBN.nbv(a), y = JSBN.nbi(), z = JSBN.nbi(), r = "";
	  this.divRemTo(d,y,z);
	  while(y.signum() > 0) {
		r = (a+z.intValue()).toString(b).substr(1) + r;
		y.divRemTo(d,y,z);
	  }
	  return z.intValue().toString(b) + r;
	};
	
	// (protected) convert from radix string
	BI.prototype.fromRadix = function (s,b) {
	  this.fromInt(0);
	  if(b == null) b = 10;
	  var cs = this.chunkSize(b);
	  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
	  for(var i = 0; i < s.length; ++i) {
		var x = JSBN.intAt(s,i);
		if(x < 0) {
		  if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
		  continue;
		}
		w = b*w+x;
		if(++j >= cs) {
		  this.dMultiply(d);
		  this.dAddOffset(w,0);
		  j = 0;
		  w = 0;
		}
	  }
	  if(j > 0) {
		this.dMultiply(Math.pow(b,j));
		this.dAddOffset(w,0);
	  }
	  if(mi) JSBN.BigInteger.ZERO.subTo(this,this);
	};
	
	// (protected) alternate constructor
	BI.prototype.fromNumber = function (a,b,c) {
	  if("number" == typeof b) {
		// new JSBN.BigInteger(int,int,RNG)
		if(a < 2) this.fromInt(1);
		else {
		  this.fromNumber(a,c);
		  if(!this.testBit(a-1))	// force MSB set
			this.bitwiseTo(JSBN.BigInteger.ONE.shiftLeft(a-1),JSBN.op_or,this);
		  if(this.isEven()) this.dAddOffset(1,0); // force odd
		  while(!this.isProbablePrime(b)) {
			this.dAddOffset(2,0);
			if(this.bitLength() > a) this.subTo(JSBN.BigInteger.ONE.shiftLeft(a-1),this);
		  }
		}
	  }
	  else {
		// new JSBN.BigInteger(int,RNG)
		var x = new Array(), t = a&7;
		x.length = (a>>3)+1;
		b.nextBytes(x);
		if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
		this.fromString(x,256);
	  }
	};
	
	// (public) convert to bigendian byte array
	BI.prototype.toByteArray = function () {
	  var i = this.t, r = new Array();
	  r[0] = this.s;
	  var p = this.DB-(i*this.DB)%8, d, k = 0;
	  if(i-- > 0) {
		if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
		  r[k++] = d|(this.s<<(this.DB-p));
		while(i >= 0) {
		  if(p < 8) {
			d = (this[i]&((1<<p)-1))<<(8-p);
			d |= this[--i]>>(p+=this.DB-8);
		  }
		  else {
			d = (this[i]>>(p-=8))&0xff;
			if(p <= 0) { p += this.DB; --i; }
		  }
		  if((d&0x80) != 0) d |= -256;
		  if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
		  if(k > 0 || d != this.s) r[k++] = d;
		}
	  }
	  return r;
	};
	
	BI.prototype.equals = function (a) { return(this.compareTo(a)==0); };
	BI.prototype.min = function (a) { return(this.compareTo(a)<0)?this:a; };
	BI.prototype.max = function (a) { return(this.compareTo(a)>0)?this:a; };
	
	// (protected) r = this op a (bitwise)
	BI.prototype.bitwiseTo = function (a,op,r) {
	  var i, f, m = Math.min(a.t,this.t);
	  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
	  if(a.t < this.t) {
		f = a.s&this.DM;
		for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
		r.t = this.t;
	  }
	  else {
		f = this.s&this.DM;
		for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
		r.t = a.t;
	  }
	  r.s = op(this.s,a.s);
	  r.clamp();
	};
	
	// (public) this & a
	JSBN.op_and = function (x,y) { return x&y; };
	BI.prototype.and = function (a) { var r = JSBN.nbi(); this.bitwiseTo(a,JSBN.op_and,r); return r; };
	
	// (public) this | a
	JSBN.op_or = function (x,y) { return x|y; };
	BI.prototype.or = function (a) { var r = JSBN.nbi(); this.bitwiseTo(a,JSBN.op_or,r); return r; };
	
	// (public) this ^ a
	JSBN.op_xor = function (x,y) { return x^y; };
	BI.prototype.xor = function (a) { var r = JSBN.nbi(); this.bitwiseTo(a,JSBN.op_xor,r); return r; };
	
	// (public) this & ~a
	JSBN.op_andnot = function (x,y) { return x&~y; };
	BI.prototype.andNot = function (a) { var r = JSBN.nbi(); this.bitwiseTo(a,JSBN.op_andnot,r); return r; };
	
	// (public) ~this
	BI.prototype.not = function () {
	  var r = JSBN.nbi();
	  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
	  r.t = this.t;
	  r.s = ~this.s;
	  return r;
	};
	
	// (public) this << n
	BI.prototype.shiftLeft = function (n) {
	  var r = JSBN.nbi();
	  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
	  return r;
	};
	
	// (public) this >> n
	BI.prototype.shiftRight = function (n) {
	  var r = JSBN.nbi();
	  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
	  return r;
	};
	
	// return index of lowest 1-bit in x, x < 2^31
	JSBN.lbit = function (x) {
	  if(x == 0) return -1;
	  var r = 0;
	  if((x&0xffff) == 0) { x >>= 16; r += 16; }
	  if((x&0xff) == 0) { x >>= 8; r += 8; }
	  if((x&0xf) == 0) { x >>= 4; r += 4; }
	  if((x&3) == 0) { x >>= 2; r += 2; }
	  if((x&1) == 0) ++r;
	  return r;
	};
	
	// (public) returns index of lowest 1-bit (or -1 if none)
	BI.prototype.getLowestSetBit = function () {
	  for(var i = 0; i < this.t; ++i)
		if(this[i] != 0) return i*this.DB+JSBN.lbit(this[i]);
	  if(this.s < 0) return this.t*this.DB;
	  return -1;
	};
	
	// return number of 1 bits in x
	JSBN.cbit = function (x) {
	  var r = 0;
	  while(x != 0) { x &= x-1; ++r; }
	  return r;
	};
	
	// (public) return number of set bits
	BI.prototype.bitCount = function () {
	  var r = 0, x = this.s&this.DM;
	  for(var i = 0; i < this.t; ++i) r += JSBN.cbit(this[i]^x);
	  return r;
	};
	
	// (public) true iff nth bit is set
	BI.prototype.testBit = function (n) {
	  var j = Math.floor(n/this.DB);
	  if(j >= this.t) return(this.s!=0);
	  return((this[j]&(1<<(n%this.DB)))!=0);
	};
	
	// (protected) this op (1<<n)
	BI.prototype.changeBit = function (n,op) {
	  var r = JSBN.BigInteger.ONE.shiftLeft(n);
	  this.bitwiseTo(r,op,r);
	  return r;
	};
	
	// (public) this | (1<<n)
	BI.prototype.setBit = function (n) { return this.changeBit(n,op_or); };
	
	// (public) this & ~(1<<n)
	BI.prototype.clearBit = function (n) { return this.changeBit(n,op_andnot); };
	
	// (public) this ^ (1<<n)
	BI.prototype.flipBit = function (n) { return this.changeBit(n,op_xor); };
	
	// (protected) r = this + a
	BI.prototype.addTo = function (a,r) {
	  var i = 0, c = 0, m = Math.min(a.t,this.t);
	  while(i < m) {
		c += this[i]+a[i];
		r[i++] = c&this.DM;
		c >>= this.DB;
	  }
	  if(a.t < this.t) {
		c += a.s;
		while(i < this.t) {
		  c += this[i];
		  r[i++] = c&this.DM;
		  c >>= this.DB;
		}
		c += this.s;
	  }
	  else {
		c += this.s;
		while(i < a.t) {
		  c += a[i];
		  r[i++] = c&this.DM;
		  c >>= this.DB;
		}
		c += a.s;
	  }
	  r.s = (c<0)?-1:0;
	  if(c > 0) r[i++] = c;
	  else if(c < -1) r[i++] = this.DV+c;
	  r.t = i;
	  r.clamp();
	};
	
	// (public) this + a
	BI.prototype.add = function (a) { var r = JSBN.nbi(); this.addTo(a,r); return r; };
	
	// (public) this - a
	BI.prototype.subtract = function (a) { var r = JSBN.nbi(); this.subTo(a,r); return r; };
	
	// (public) this * a
	BI.prototype.multiply = function (a) { var r = JSBN.nbi(); this.multiplyTo(a,r); return r; };
	
	// (public) this / a
	BI.prototype.divide = function (a) { var r = JSBN.nbi(); this.divRemTo(a,r,null); return r; };
	
	// (public) this % a
	BI.prototype.remainder = function (a) { var r = JSBN.nbi(); this.divRemTo(a,null,r); return r; };
	
	// (public) [this/a,this%a]
	BI.prototype.divideAndRemainder = function (a) {
	  var q = JSBN.nbi(), r = JSBN.nbi();
	  this.divRemTo(a,q,r);
	  return new Array(q,r);
	};
	
	// (protected) this *= n, this >= 0, 1 < n < DV
	BI.prototype.dMultiply = function (n) {
	  this[this.t] = this.am(0,n-1,this,0,0,this.t);
	  ++this.t;
	  this.clamp();
	};
	
	// (protected) this += n << w words, this >= 0
	BI.prototype.dAddOffset = function (n,w) {
	  while(this.t <= w) this[this.t++] = 0;
	  this[w] += n;
	  while(this[w] >= this.DV) {
		this[w] -= this.DV;
		if(++w >= this.t) this[this.t++] = 0;
		++this[w];
	  }
	};
	
	// A "null" reducer 
	JSBN.NullExp = function () {
		this.convert = function (x) { return x; };
		this.revert = function (x) { return x; };
		this.mulTo = function (x,y,r) { x.multiplyTo(y,r); };
		this.sqrTo = function (x,r) { x.squareTo(r); };
	};
	
	// (public) this^e
	BI.prototype.pow = function (e) { return this.exp(e,new JSBN.NullExp()); };
	
	// (protected) r = lower n words of "this * a", a.t <= n
	// "this" should be the larger one if appropriate.
	BI.prototype.multiplyLowerTo = function (a,n,r) {
	  var i = Math.min(this.t+a.t,n);
	  r.s = 0; // assumes a,this >= 0
	  r.t = i;
	  while(i > 0) r[--i] = 0;
	  var j;
	  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
	  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
	  r.clamp();
	};
	
	// (protected) r = "this * a" without lower n words, n > 0
	// "this" should be the larger one if appropriate.
	BI.prototype.multiplyUpperTo = function (a,n,r) {
	  --n;
	  var i = r.t = this.t+a.t-n;
	  r.s = 0; // assumes a,this >= 0
	  while(--i >= 0) r[i] = 0;
	  for(i = Math.max(n-this.t,0); i < a.t; ++i)
		r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
	  r.clamp();
	  r.drShiftTo(1,r);
	};
	
	// Barrett modular reduction
	JSBN.Barrett = function (m) {
	  // setup Barrett
	  this.r2 = JSBN.nbi();
	  this.q3 = JSBN.nbi();
	  JSBN.BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
	  this.mu = this.r2.divide(m);
	  this.m = m;
	
		this.concert = function (x) {
		  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
		  else if(x.compareTo(this.m) < 0) return x;
		  else { var r = JSBN.nbi(); x.copyTo(r); this.reduce(r); return r; }
		};
		
		this.revert = function (x) { return x; };
		
		// x = x mod m (HAC 14.42)
		this.reduce = function (x) {
		  x.drShiftTo(this.m.t-1,this.r2);
		  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
		  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
		  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
		  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
		  x.subTo(this.r2,x);
		  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
		};
		
		// r = x^2 mod m; x != r
		this.sqrTo = function (x,r) { x.squareTo(r); this.reduce(r); };
		
		// r = x*y mod m; x,y != r
		this.mulTo = function (x,y,r) { x.multiplyTo(y,r); this.reduce(r); };
	};
	
	// (public) this^e % m (HAC 14.85)
	BI.prototype.modPow = function (e,m) {
	  var i = e.bitLength(), k, r = JSBN.nbv(1), z;
	  if(i <= 0) return r;
	  else if(i < 18) k = 1;
	  else if(i < 48) k = 3;
	  else if(i < 144) k = 4;
	  else if(i < 768) k = 5;
	  else k = 6;
	  if(i < 8)
		z = new Classic(m);
	  else if(m.isEven())
		z = new JSBN.Barrett(m);
	  else
		z = new JSBN.Montgomery(m);
	
	  // precomputation
	  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
	  g[1] = z.convert(this);
	  if(k > 1) {
		var g2 = JSBN.nbi();
		z.sqrTo(g[1],g2);
		while(n <= km) {
		  g[n] = JSBN.nbi();
		  z.mulTo(g2,g[n-2],g[n]);
		  n += 2;
		}
	  }
	
	  var j = e.t-1, w, is1 = true, r2 = JSBN.nbi(), t;
	  i = JSBN.nbits(e[j])-1;
	  while(j >= 0) {
		if(i >= k1) w = (e[j]>>(i-k1))&km;
		else {
		  w = (e[j]&((1<<(i+1))-1))<<(k1-i);
		  if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
		}
	
		n = k;
		while((w&1) == 0) { w >>= 1; --n; }
		if((i -= n) < 0) { i += this.DB; --j; }
		if(is1) {	// ret == 1, don't bother squaring or multiplying it
		  g[w].copyTo(r);
		  is1 = false;
		}
		else {
		  while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
		  if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
		  z.mulTo(r2,g[w],r);
		}
	
		while(j >= 0 && (e[j]&(1<<i)) == 0) {
		  z.sqrTo(r,r2); t = r; r = r2; r2 = t;
		  if(--i < 0) { i = this.DB-1; --j; }
		}
	  }
	  return z.revert(r);
	};
	
	// (public) gcd(this,a) (HAC 14.54)
	BI.prototype.gcd = function (a) {
	  var x = (this.s<0)?this.negate():this.clone();
	  var y = (a.s<0)?a.negate():a.clone();
	  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
	  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
	  if(g < 0) return x;
	  if(i < g) g = i;
	  if(g > 0) {
		x.rShiftTo(g,x);
		y.rShiftTo(g,y);
	  }
	  while(x.signum() > 0) {
		if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
		if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
		if(x.compareTo(y) >= 0) {
		  x.subTo(y,x);
		  x.rShiftTo(1,x);
		}
		else {
		  y.subTo(x,y);
		  y.rShiftTo(1,y);
		}
	  }
	  if(g > 0) y.lShiftTo(g,y);
	  return y;
	};
	
	// (protected) this % n, n < 2^26
	BI.prototype.modInt = function (n) {
	  if(n <= 0) return 0;
	  var d = this.DV%n, r = (this.s<0)?n-1:0;
	  if(this.t > 0)
		if(d == 0) r = this[0]%n;
		else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
	  return r;
	};
	
	// (public) 1/this % m (HAC 14.61)
	BI.prototype.modInverse = function (m) {
	  var ac = m.isEven();
	  if((this.isEven() && ac) || m.signum() == 0) return JSBN.BigInteger.ZERO;
	  var u = m.clone(), v = this.clone();
	  var a = JSBN.nbv(1), b = JSBN.nbv(0), c = JSBN.nbv(0), d = JSBN.nbv(1);
	  while(u.signum() != 0) {
		while(u.isEven()) {
		  u.rShiftTo(1,u);
		  if(ac) {
			if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
			a.rShiftTo(1,a);
		  }
		  else if(!b.isEven()) b.subTo(m,b);
		  b.rShiftTo(1,b);
		}
		while(v.isEven()) {
		  v.rShiftTo(1,v);
		  if(ac) {
			if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
			c.rShiftTo(1,c);
		  }
		  else if(!d.isEven()) d.subTo(m,d);
		  d.rShiftTo(1,d);
		}
		if(u.compareTo(v) >= 0) {
		  u.subTo(v,u);
		  if(ac) a.subTo(c,a);
		  b.subTo(d,b);
		}
		else {
		  v.subTo(u,v);
		  if(ac) c.subTo(a,c);
		  d.subTo(b,d);
		}
	  }
	  if(v.compareTo(JSBN.BigInteger.ONE) != 0) return JSBN.BigInteger.ZERO;
	  if(d.compareTo(m) >= 0) return d.subtract(m);
	  if(d.signum() < 0) d.addTo(m,d); else return d;
	  if(d.signum() < 0) return d.add(m); else return d;
	};
	
	JSBN.lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509];
	JSBN.lplim = (1<<26)/JSBN.lowprimes[JSBN.lowprimes.length-1];
	
	// (public) test primality with certainty >= 1-.5^t
	BI.prototype.isProbablePrime = function (t) {
	  var i, x = this.abs();
	  if(x.t == 1 && x[0] <= JSBN.lowprimes[JSBN.lowprimes.length-1]) {
		for(i = 0; i < JSBN.lowprimes.length; ++i)
		  if(x[0] == JSBN.lowprimes[i]) return true;
		return false;
	  }
	  if(x.isEven()) return false;
	  i = 1;
	  while(i < JSBN.lowprimes.length) {
		var m = JSBN.lowprimes[i], j = i+1;
		while(j < JSBN.lowprimes.length && m < JSBN.lplim) m *= JSBN.lowprimes[j++];
		m = x.modInt(m);
		while(i < j) if(m%JSBN.lowprimes[i++] == 0) return false;
	  }
	  return x.millerRabin(t);
	};
	
	// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
	BI.prototype.millerRabin = function (t) {
	  var n1 = this.subtract(JSBN.BigInteger.ONE);
	  var k = n1.getLowestSetBit();
	  if(k <= 0) return false;
	  var r = n1.shiftRight(k);
	  t = (t+1)>>1;
	  if(t > JSBN.lowprimes.length) t = JSBN.lowprimes.length;
	  var a = JSBN.nbi();
	  for(var i = 0; i < t; ++i) {
		a.fromInt(JSBN.lowprimes[i]);
		var y = a.modPow(r,this);
		if(y.compareTo(JSBN.BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
		  var j = 1;
		  while(j++ < k && y.compareTo(n1) != 0) {
			y = y.modPowInt(2,this);
			if(y.compareTo(JSBN.BigInteger.ONE) == 0) return false;
		  }
		  if(y.compareTo(n1) != 0) return false;
		}
	  }
	  return true;
	};
	
	// BigInteger interfaces not implemented in jsbn:
	
	// BigInteger(int signum, byte[] magnitude)
	// double doubleValue()
	// float floatValue()
	// int hashCode()
	// long longValue()
	// static BigInteger valueOf(long val)

};