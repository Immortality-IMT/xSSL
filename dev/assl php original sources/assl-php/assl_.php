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
		$key0 = self::getStringFromHex($_SESSION['aSSL']['aSSLconn'][$conn]['key']);
		return self::encode(AES::encrypt($txt, $key0));
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
		$key0 = self::getStringFromHex($_SESSION['aSSL']['aSSLconn'][$conn]['key']);
		return AES::decrypt(self::decode($txt), $key0);
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
		echo $str ? $str : '';
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
			
			$key = new Crypt_RSA_Key($sk[0], $sk[2], 'private');
			
			$rsa = new Crypt_RSA();
			$res = $rsa->decryptHex($QS['aSSLCKey'], $key);
			
			if (!$res) self::write('error');
			else 
			{
				$_SESSION['aSSL']['aSSLconn'][$cn]['key'] = $res;
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
		self::write(self::encrypt($txt, null, $conn ? $conn : $QS['aSSLConnName']));
	}
	
	
	/**
	 * Returns associative array by query string
	 *
	 * @param string $x
	 * @return array
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
	 * Encodes string to format supported by client library.
	 *
	 * @param string $txt
	 * @return string
	 */
	private static function encode($txt) 
	{
		$v = self::strToLongs($txt);
		$ret = '';
		for ($j = 0; $j < count($v); $j++) { $ret .= ($ret ? "x" : "").$v[$j]; }
		return $ret;
	}
	
	
	/**
	 * Decodes string
	 *
	 * @param string $txt
	 * @return string
	 */
	private static function decode($txt) 
	{
		$vv = explode("x", $txt);
		$v = array();
		$str = '';
		for ($j = 0; $j < count($vv); $j++) 
		{
			$v[$j] = intval($vv[$j]);
			$str .= $vv[$j] . "\n";
		}
		return preg_replace('/\0+$/', '', self::longsToStr($v));	
	}
	
	
	/**
	 * Converts string to array of longs
	 *
	 * @param string $s
	 * @return array()
	 */
	private static function strToLongs($s) 
	{
		$ll = ceil(strlen($s)/4);
		$l = array();
		for ($i = 0; $i < $ll; $i++) 
		{
			$l[$i] = ord($s[$i * 4]) 
				+ (ord($s[$i * 4 + 1]) << 8) 
				+ (ord($s[$i * 4 + 2]) << 16)
				+ (ord($s[$i * 4 + 3]) << 24);
		}
		return $l;
	}
	
	/**
	 * Converts array of longs to string
	 *
	 * @param array $l
	 * @return string
	 */
	private static function longsToStr($l) 
	{
		$a = array();
		for ($i = 0; $i < count($l); $i++) 
		{
			$a[$i] = chr($l[$i] & 0xFF) 
				. chr($l[$i] >> 8 & 0xFF)
				. chr($l[$i] >> 16 & 0xFF)
				. chr($l[$i] >> 24 & 0xFF);
		}
		return implode('', $a);
	}
}
?>