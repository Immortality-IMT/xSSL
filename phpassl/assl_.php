<?php
/**
 * aSSL - PHP version
 * This class should be used as static - the same as done in ASP version.
 */
class aSSL
{
	private static $vername = 'aSSL';
	private static $language = 'PHP';
	private static $version = '1.2beta3';
	private static $verdate = '2007-01-08';
	
	/**
	 * gets string from HEX
	 *
	 * @param string $str hex string
	 * @return string
	 */
	private static function getStringFromHex($str) 
	{
		$h = '';
		for ($j = 0; $j < 32; $j = $j + 2) 
		{
			$h .= chr(intval(substr($str, $j, 2), 16));
		}
		return $h;
	}
	
	/**
	 * AES data encryption.
	 *
	 * @param string $txt
	 * @param int $conn - connection number/name which key should be used for encryption
	 * @return string encrypted data
	 */
	public static function encrypt($txt, $conn = 0) 
	{
		$conn = $QS['aSSLConnName'];		

        $encodedkey = $_SESSION['aSSL']['aSSLconn']['key']; //hex encoded password
    	
    	$key0 = self::getStringFromHex($encodedkey); //hex decoded password

        $ecryptedtxt = AES::encrypt($txt, $key0); //encrypt
    
        $ret = self::encode($ecryptedtxt); //encode encrypted text to base 64

		return $ret; //return decrypted text
	}
	

	/**
	 * AES data decryption
	 *
	 * @param string $txt encrypted data
	 * @param int $conn - connection number/name which key should be used to decrypt data
	 * @return string
	 */
	public static function decrypt($txt, $conn = 0) 
	{
        $encodedkey = $_SESSION['aSSL']['aSSLconn']['key']; //hex encoded password
    
		$key0 = self::getStringFromHex($encodedkey); //hex decoded password

        $decodedtxt = self::decode($txt); //decode text from base 64

        $ret = AES::decrypt($decodedtxt, $key0); //decrypt

		return $ret; //return decrypted text
	}
	
	
	/**
	 * Outputs data.
	 * 
	 * Data is just echoed. Implemented for compatibility with ASP aSSL version.
	 *
	 * @param string $str
	 */
	public static function write($str) 
	{
       // error_log($str,0);
		echo $str ? $str : '';
	}
	
    function myErrorHandler($error) 
    {
      error_log($error->getMessage());
      error_log($error->getCode());
    }
	
	/**
	 * Used to connect to server from JS and store AES key in the session
	 *
	 * @param array $sk - RSA $key
	 */
	public static function response($sk) 
	{
		$QS = self::querystr();
		$cn = $QS['aSSLConnName'];
		
		if (isset($QS['aSSLOMS'])) self::write(1);
		elseif (isset($QS['aSSLCKey'])) 
		{
			set_time_limit(0);
			
            $key = new Crypt_RSA_Key($sk[0], $sk[2], 'private', 'GMP', 'myErrorHandler');
			//$key = new Crypt_RSA_Key($sk[0], $sk[2], 'private');
			
            $rsa = new Crypt_RSA(null, 'GMP', 'myErrorHandler');
			//$rsa = new Crypt_RSA();
			$res = $rsa->decryptHex($QS['aSSLCKey'], $key);
			
			if (!$res) self::write('error');
			else 
			{
				$_SESSION['aSSL']['aSSLconn']['key'] = $res;
				self::write(ini_get('session.gc_maxlifetime'));
			}
		}
		else 
		{
			self::write($sk[0] . '|' . $sk[1]);
		}
	}
	
	/**
	 * Encrypts data and sends it to client.
	 *
	 * @param string $txt - plain text
	 * @param int $conn - connection number/name which key should be used for encryption.
	 */
	public static function send($txt, $conn = 0) 
	{
		$QS = self::querystr();

        $encrypted_reply = self::encrypt($txt, null, $conn ? $conn : $QS['aSSLConnName']);        
   
		self::write($encrypted_reply);
	}
	
	
	/**
	 * Turns request of post data into array
	 * 
	 * @param string $x
	 * @return array
     * e.g
     * from decrypted string, nickname=admin&password=easy to
     * array\n(\n    [nickname] => admin\n    [password] => easy\n)\n',   
	 */

	public static function querystr($x = null) 
	{
		if (isset($x))
		{
			$qs = array();
			$couple = explode("&", $x);
			for ($j = 0; $j < count($couple); $j++) 
			{
				$kx = explode("=", $couple[$j]);
				$qs[$kx[0]] = $kx[1];
			}
			return $qs;
		}
		else
			return $_REQUEST;
	}
	
	
	/**
	 * Encode string to base 64 so transmission equipment does not replace unknown characters with ? or other chars
	 * Url-encode base64 as strings contain the "+", "=" and "/" chars which transmission equipment could change
     * encodeURI() will not encode: ~!@#$&*()=:/,;?+'
     *
     * Both functions are from the PHP helper functions - PHP lib
	 * @param string $txt
	 * @return string
	 */

	private static function encode( $txt ) 
	{

        $b64encoded = base64_encode( $txt ); //php lib

        $enc_plus = strtr($b64encoded, '+', '_'); //base64 chars not web safe replaced
        $enc_slash = strtr($enc_plus, '/', '.'); //base64 chars not web safe replaced
        $ret = strtr($enc_slash, '=', '-'); //base64 chars not web safe replaced

        return $ret;
	}
	
	
	/**
     * Decode string to base 64 so transmission equipment does not replace unknown characters with ? or other chars
	 * Url-encode base64 as strings contain the "+", "=" and "/" chars which transmission equipment could change
     * encodeURI() will not encode: ~!@#$&*()=:/,;?+'
     *
     * Both functions are from the PHP helper functions - PHP lib
	 * @param string $txt
	 * @return string
	 */

	private static function decode( $b64encoded ) 
	{

        $enc_plus = strtr($b64encoded, '_', '+'); //base64 chars not web safe replaced
        $enc_slash = strtr($enc_plus, '.', '/'); //base64 chars not web safe replaced
        $enc_equals = strtr($enc_slash, '-', '='); //base64 chars not web safe replaced

        $ret = base64_decode( $enc_equals );

        return $ret;
	}

} //end class aSSL

