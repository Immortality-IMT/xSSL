# aSSL Ajax SSL - end to end encryption between client side JavaScript & server side PHP

aSSL originally created by Francesco Sullo - Rome, Italy (https://web.archive.org/web/20170216003527/http://assl.sullof.com/assl/), the project was orphaned some years ago now.

Minimal update to work with PHP8.2

Simply throw it in web directory and load index.php. PHP Version requires php-gmp so **apt-get install php-gmp** and then you may need to enable PHP FPM in Apache2 by a2enmod proxy_fcgi setenvif and a2enconf php-fpm and reload apache as per the instructions provided by the installation of php-gmp.

aSSL is now called xSSL. xSSL implements technology similar to SSL over http. Embeddable in any http website application and provide end to end encryption without third party issuer. xSSL is in development and not for production, the files are a working demo. The goal of the project is to make the end to end encryption more secure, possibly even ID the server to the client without a certificate issuer.

Upload, copy / paste to server and run index.php. xSSL is composed of two parts: a client-side component and a server-side component. The first is a client side scripting language, pure Javascript files are used, the second is server side language and depends on specific languages (Javascript, PHP, Java, Ruby, etc.), only a PHP version is available. xSSL encrypts the $_POST or $_GET to the server and encrypts back again from the server to the client.

**How xSSL works**

1. On page load the (Javascript) connection routine is called aSSL.connect(url,showConn) and the PHP connection routine is called aSSL::response() conn.php. Each side doesn't have their own public and private keys, exchanging and signing messages. Instead it works more like regular SSL.

2. Only the server side has the RSA key pair and sends its RSA modulus and the public exponent to the client, (its pubic key).

3. The client generates a random 128-bit key, encrypts it using the server public key and passes the encrypted exchange key to the server.

4. The server receives the encrypted 128-bit key, decrypts it with its private key and, if the result is ok, sets a session duration time. Javascript has no sessions so when the page is reloaded the process begins anew, this constant key renewal might add a challenge to a hacker. The system depends on Ajax, jQuery to keep the key in memory on the client side for just long enough to send and receive encrypted data.

All subsequent client-server exchanges are encrypted and decrypted using AES algorithm. AES is a symmetric algorithm which uses the same 128, 192, or 256 bit key for both encryption and decryption.  With a 128-bit key, the task of cracking AES by checking each of the 2128 possible key values (a “brute force” attack) is so computationally intensive that even the fastest supercomputer would require, on average, more than 100 trillion years to do it. AES has never been cracked, and based on current technological trends, is expected to remain secure for years to come.

aSSL allows multiple secure connections to be established with one or more servers.

6. The key only remains alive if AJAX is used, when the browser is reloaded the key generation happens anew.

7. The data is encrypted and encoded then sent, decoded with base 64 because unicode characters cause transmission equipment to change the chars.

8. The AES 128bit key is also encoded in hex and decoded using getStringFromHex() function before encrypt/decrypt function calls.

**aSSL reference**

aSSL.connect(uri,callBackFunction[,connectionName])

Client-side method. It starts the process to establish the connection.

uri is the uri of the server-side application.

callBackFunction is the function that is automatically called after connection is established

connectionName is the name of the connection. If it is not present aSSL opens the '0' connection as default.

aSSL.encrypt(clearText)

Client and server-side method. It encrypts the clearText string using the previously negotiated secret 128-bit key.

aSSL.decrypt(cipherText)

Client and server-side method. It decrypts the cipherText using the previously negotiated secret 128-bit key.

aSSL.response(myKey)

Server-side method. It using the myKey parameter (see above), establishes the connection.

aSSL.connections[connectionName].sessionTimeout

Client-side property. It is the session duration time of the specific connection. If you use the default connection you must specify it as '0'.

aSSL.connections[connectionName].elapsedTime

Client-side property. It is the time elapsed to establish the connection.

aSSL.keySize

Client-side property. As default aSSL generates a 128-bit key (e.g. a key of 16 characters). This is expressed in number of characters. If you want to generate a different key for some mysterous reason you can set this property. For example:

aSSL.keySize = 12

aSSL.onlyMantainSession

Client-side property. By default, once the connection has been established and the secret key has been exchanged with the server, aSSL merely mantains the session. If you prefer that aSSL continually re-negotiates a new key instead of just keeping the session open, set this property to false.

Is aSSL secure as SSL?

Mostly, *SSL* is secure because it is implemented at browser level so when a HTTPS connection has been established, the browser checks the SSL Certificate before continuing.

Suppose a man-in-the-middle (MiTM) attack. With an SSL connection, the attack would be successful only should the user clicked Ok when the browser alerts him saying that the certificate doesn't correspond to the connected server (the alert may also appear if some file is transferred over HTTP instead of HTTPS because in this file a hacker could inject malicious code).

If a hacker were to attack with a MiTM attack during an aSSL connection, he could be successful.

Password sniffing is much more diffuse because it is much easier. In fact, there are specific softwares that sniff the traffic, recognizes userid and passwords, and register them. aSSL protects against these sniffers. When a server exchanges account information in clear HTTP, a sniffer can simply intercept all the data, but if the server exchanges the data via aSSL it is not possible to decode the passed data and so the level of security of the site is notably better.

The goal of aSSL development is remedy these issues, such as trace route monitoring or server to client authentication. 

aSSL is composed of javascript files and server side files. The major functions are located in the files assl_.js and assl_.php. Along with connection, encryption and decryption there are string manipulation functions. aSSL utilizes Ajax to connect, send and receive. aSSL used to use negotiation algorithm RC4 but has updated to RSA. The directory structure.

See the index.php and run it in a browser, simple. It is an example login using aSSL.

   / - this is where you do your web project that utilizes aSSL in any langauge as long as you can call PHP and JavaScript functions.
   jassl - the js files, encryption libs and the main file assl.js 
   phpassl - the php files, encryptions libs and the main file assl.js
   testbench - ping.php and pong.php to test the various function to make sure they are working correctly
   dev - the original versions of the project. These source are no longer supported or being developed.
 
   assl_.       contains all the functions of aSSL - this is the main file
   assl.        just an includes file (ignore unless you want to include)

The source code are mirror images of eachother. So any changes must be identical to the server side and the client side, any porting should mirror the existing file structure functions so that any updates to one code can be applied and so the protocol speaks the same language. The files are identically named irrespective of langauge and even the source code is identical line by line. One set of files are client side and one set of files are server side, they both reside on the server but the processing is client side or server side. Javascript is a client side language, the interpretor is in the browser and is not pre-processing while PHP is a server side language, the data is sent to the server for processing and returned.

aSSL uses an encryption lib that PHP no longer supports. https://github.com/pear/Crypt_RSA - implementation of RSA in php version,  https://pear.php.net/package/Crypt_RSA - message reads This package is not maintained anymore and has been superseded. Package has moved to channel phpseclib.sourceforge.net, package Crypt_RSA. The package has fixes and still functions.

Credits go to... Tom Wu for its BigIntegers and RSA in JavaScript, Chriss Veness for its AES Javascript implementation, Ryan Perry for the PHP aSSL porting 
 
30-12-2009, Fixed a bug in the aSSL PHP version. Thanks to Thomas Krapp.
19-11-2009, Fixed a bug in the aSSL PHP version. Thanks to Mark Brekelmans.

Tony remembered the project, downloaded it from the wayback machine, fixed it and posted it on github.

The myKey.asp is a file that contains the RSA server key. Look at the following example with a 512-bit key:

<pre>
<*
var myKey = [
   '91305d87dd6de2944fd6a62ceaa5aae1'+
   '608798c73037747e55ac553b357c4b17'+
   '47848d671df1772fc755c7fdcbb81be1'+
   '3d854794622c29832d189aa1382d8617',
   '10001',
   '223e3701115f965e068a88bcf546c78b'+
   'ca7990b6021042407db25c93cf64964c'+
   'f752072a08c70489ef4a1b8e95d7a948'+
   'de312e46638cd0fcaa03d654b586ef71',
   'c4e3ec8bc8753e7ffb78ce2bda372ae2'+
   '266e3cf309d0940f5f1118c1d2a2bfdf',
   'bcc6e96e460c6c1461737e9a742ca369'+
   '320d60cb15a0310b8be7bc4b6ab720c9',
   '2c315488d387ad6da08e2f089cc44135'+
   'dd9664cbd06a26b1848f1bd57567de55',
   '668c23683cf3288f15b518b42ca1c70f'+
   '311a65574ce31d616959b446bfacc549',
   '9b6eb5314afaffd51cda024facc091f3'+
   '8c2f4554076d638844faa9b0f6e5a8c4'
]
*>
</pre>

**This key should be changed.**

To generate your RSA key you can use the Simple RSA key generator for aSSL.

RSA Key Generator

http://www-cs-students.stanford.edu/~tjw/jsbn/rsa2.html

Parts of the RSA key used in aSSL. mykey.php

<pre>
Modulus (hex):
BC86E3DC782C446EE756B874ACECF2A115E613021EAF1ED5EF295BEC2BED899D
26FE2EC896BF9DE84FE381AF67A7B7CBB48D85235E72AB595ABF8FE840D5F8DB
</pre>

Public exponent (hex, F4=0x10001): 3, four hex digits also public

above is the public key

below is the private key

<pre>
Private exponent (hex):
7daf4292fac82d9f44e47af87348a1c0b9440cac1474bf394a1b929d729e5bbc
f402f29a9300e11b478c091f7e5dacd3f8edae2effe3164d7e0eeada87ee817b
</pre>
<pre>
P (hex):
ef3fc61e21867a900e01ee4b1ba69f5403274ed27656da03ed88d7902cce693f
</pre>
<pre>
Q (hex):
c9b9fcc298b7d1af568f85b50e749539bc01b10a68472fe1302058104821cd65
</pre>
<pre>
D mod (P-1) (hex):
9f7fd9696baefc6009569edcbd19bf8d576f89e1a439e6ad4905e50ac8899b7f
</pre>
<pre>
D mod (Q-1) (hex):
867bfdd7107a8bca39b503ce09a30e267d567606f02f7540cac03ab5856bde43
</pre>
<pre>
1/Q mod P (hex):
</pre>

Bye.
Tony
