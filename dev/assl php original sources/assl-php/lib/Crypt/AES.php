<?php
class AES
{
	/**
	 * Cipher
	 *
	 * @param array $input
	 * @param array $key
	 * @param array $w
	 * @return array
	 */
	private static function Cipher($input, $key, $w)
	{
		$Nk = count($key) / 4;  // key length (in words)
		$Nr = $Nk + 6;       // no of rounds
		$Nb = 4;            // block size: no of columns in state (fixed at 4 for AES)
	
		$state = array();  // initialise 4xNb byte-array 'state' with input
		for ($i = 0; $i < 4 * $Nb; $i++) $state[$i % 4][floor($i / 4)] = $input[$i];
	
		$state = self::AddRoundKey($state, $w, 0, $Nb);
	
		for ($round = 1; $round < $Nr; $round++) 
		{
			$state = self::SubBytes($state, $Nb);
			$state = self::ShiftRows($state, $Nb);
			$state = self::MixColumns($state, $Nb);
			$state = self::AddRoundKey($state, $w, $round, $Nb);
		}
	
		$state = self::SubBytes($state, $Nb);
		$state = self::ShiftRows($state, $Nb);
		$state = self::AddRoundKey($state, $w, $Nr, $Nb);
		
		$output = array();  // convert to 1-d array before returning
		for ($i = 0; $i < 4 * $Nb; $i++) $output[$i] = $state[$i % 4][floor($i/4)];
		return $output;
	}
	
	/**
	 * Applies SBox to state S [§5.1.1]
	 *
	 * @param array $s
	 * @param int $Nb
	 * @return array
	 */
	private static function SubBytes($s, $Nb) 
	{
		for ($r = 0; $r < 4; $r++) 
		{
			for ($c = 0; $c < $Nb; $c++) $s[$r][$c] = self::$Sbox[$s[$r][$c]];
		}
		return $s;
	}
	
	/**
	 * Shifts row r of state S left by r bytes [§5.1.2]
	 *
	 * @param array $s
	 * @param int $Nb
	 * @return array
	 */
	private static function ShiftRows($s, $Nb) 
	{
		$t = array();
		for ($r=1; $r < 4; $r++) 
		{
			for ($c = 0; $c < 4; $c++) $t[$c] = $s[$r][($c + $r) % $Nb];  // shift into temp copy
			for ($c = 0; $c < 4; $c++) $s[$r][$c] = $t[$c];         // and copy back
		}          // note that this will work for Nb=4,5,6, but not 7,8: see
		return $s;  // fp.gladman.plus.com/cryptography_technology/rijndael/aes.spec.311.pdf 
	}
	
	/**
	 * Combines bytes of each col of state S [§5.1.3]
	 *
	 * @param array $s
	 * @param int $Nb
	 * @return array
	 */
	private static function MixColumns($s, $Nb) 
	{
		for ($c = 0; $c < 4; $c++) 
		{
			$a = array();  // 'a' is a copy of the current column from 's'
			$b = array();  // 'b' is a{02} in GF(2^8)
			for ($i = 0; $i < 4; $i++) 
			{
				$a[$i] = $s[$i][$c];
				$b[$i] = $s[$i][$c] & 0x80 ? $s[$i][$c] << 1 ^ 0x011b : $s[$i][$c] << 1;
			}
			// a[n] ^ b[n] is a{03} in GF(2^8)
			$s[0][$c] = $b[0] ^ $a[1] ^ $b[1] ^ $a[2] ^ $a[3]; // 2*a0 + 3*a1 + a2 + a3
			$s[1][$c] = $a[0] ^ $b[1] ^ $a[2] ^ $b[2] ^ $a[3]; // a0 * 2*a1 + 3*a2 + a3
			$s[2][$c] = $a[0] ^ $a[1] ^ $b[2] ^ $a[3] ^ $b[3]; // a0 + a1 + 2*a2 + 3*a3
			$s[3][$c] = $a[0] ^ $b[0] ^ $a[1] ^ $a[2] ^ $b[3]; // 3*a0 + a1 + a2 + 2*a3
		}
		return $s;
	}
	
	/**
	 * xor Round Key into state S [§5.1.4]
	 *
	 * @param array $state
	 * @param array $w
	 * @param int $rnd
	 * @param int $Nb
	 * @return array
	 */
	private static function AddRoundKey($state, $w, $rnd, $Nb) 
	{
		for ($r = 0; $r < 4; $r++) 
		{
			for ($c = 0; $c < $Nb; $c++) $state[$r][$c] ^= $w[$rnd * 4 + $c][$r];
		}
		return $state;
	}
	
	/**
	 * Generate Key Schedule (byte-array Nr+1 x Nb) from Key [§5.2]
	 *
	 * @param array $key
	 * @return array
	 */
	private static function KeyExpansion($key) 
	{
		$Nk = count($key) / 4;  // key length (in words)
		$Nr = $Nk + 6;       // no of rounds
		$Nb = 4;            // block size: no of columns in state (fixed at 4 for AES)
	
		$w = array();
		$temp = array();
	
		for ($i = 0; $i < $Nk; $i++) 
		{
			$r = array($key[4 * $i], $key[4 * $i + 1], $key[4 * $i + 2], $key[4 * $i + 3]);
			$w[$i] = $r;
		}
	
		for ($i = $Nk; $i < ($Nb * ($Nr + 1)); $i++) 
		{
			$w[$i] = array();
			for ($t = 0; $t < 4; $t++) $temp[$t] = $w[$i - 1][$t];
			if ($i % $Nk == 0) 
			{
				$temp = self::SubWord(self::RotWord($temp));
				for ($t = 0; $t < 4; $t++) $temp[$t] ^= self::$Rcon[$i / $Nk][$t];
			} 
			elseif ($Nk > 6 && $i % $Nk == 4) 
			{
				$temp = self::SubWord($temp);
			}
			for ($t = 0; $t < 4; $t++) $w[$i][$t] = $w[$i - $Nk][$t] ^ $temp[$t];
		}
	
		return $w;
	}
	
	/**
	 * Applies SBox to 4-byte word w
	 *
	 * @param array $w
	 * @return array
	 */
	private static function SubWord($w) 
	{
		for ($i = 0; $i < 4; $i++) $w[$i] = self::$Sbox[$w[$i]];
		return $w;
	}
	
	/**
	 * Rotates 4-byte word w left by one byte
	 *
	 * @param array $w
	 * @return array
	 */
	private static function RotWord($w) 
	{
		$w[4] = $w[0];
		for ($i = 0; $i < 4; $i++) $w[$i] = $w[$i + 1];
		return $w;
	}
	
	/**
	 * Sbox is pre-computed multiplicative 
	 * inverse in GF(2^8) used in SubBytes and 
	 * KeyExpansion
	 *
	 * @var array
	 */
	private static $Sbox = array(0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
		 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
		 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
		 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
		 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
		 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
		 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
		 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
		 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
		 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
		 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
		 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
		 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
		 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
		 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
		 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16);
	
	/**
	 * Rcon is Round Constant used for the Key 
	 * Expansion [1st col is 2^(r-1) in GF(2^8)]
	 *
	 * @var array
	 */
	private static $Rcon = array( array(0x00, 0x00, 0x00, 0x00),
		 array(0x01, 0x00, 0x00, 0x00),
		 array(0x02, 0x00, 0x00, 0x00),
		 array(0x04, 0x00, 0x00, 0x00),
		 array(0x08, 0x00, 0x00, 0x00),
		 array(0x10, 0x00, 0x00, 0x00),
		 array(0x20, 0x00, 0x00, 0x00),
		 array(0x40, 0x00, 0x00, 0x00),
		 array(0x80, 0x00, 0x00, 0x00),
		 array(0x1b, 0x00, 0x00, 0x00),
		 array(0x36, 0x00, 0x00, 0x00));

	/** 
	 * Use AES to encrypt 'plaintext' with 'password' using 128-bit key, in 'Counter' mode of operation
	 *                           - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
	 *   for each block
	 *   - outputblock = cipher(counter, key)
	 *   - cipherblock = plaintext xor outputblock
	 */
	public static function encrypt($plaintext, $password) 
	{
		// ensure plaintext only contains 8-bit characters: use 'escape' to convert anything outside 
		// ISO-8859-1, but keep spaces as spaces not '%20' to restrict bloat
		$plaintext = preg_replace('/%20/', ' ', urlencode($plaintext));
	
		// for this example script, generate the key by applying Cipher to 1st 16 chars of password; for 
		// real-world applications, a more secure approach would be to hash the password e.g. with SHA-1
		$pwBytes = array();
		for ($i = 0; $i < 16; $i++) $pwBytes[$i] = ord($password[$i]);
		$pwKeySchedule = self::KeyExpansion(array(0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1));
		$key = self::Cipher($pwBytes, $pwBytes, $pwKeySchedule);
	
		// initialise counter block (NIST SP800-38A §B.2)
		$counterBlock = array();
		$nonce = time();  // milliseconds since 1-Jan-1970
		for ($i = 0; $i < 8; $i++) $counterBlock[$i] = ($nonce >> ($i >= 4 ? $i - 4 : $i) * 8) & 0xFF;
		#var_dump($counterBlock);
	
		// generate key schedule - an expansion of the key into distinct Key Rounds for each round
		$keySchedule = self::KeyExpansion($key);
	
		$blockCount = ceil(strlen($plaintext) / 16);
		$ciphertext = array();  // ciphertext as array of strings
	  
		for ($b = 0; $b < $blockCount; $b++) 
		{
			for ($c = 0; $c < 8; $c++) $counterBlock[15 - $c] = ($b >> ($c >= 4 ? 4 - $c : $c) * 8) & 0xFF;  // set counter in counter block
	
			$cipherCntr = self::Cipher($counterBlock, $key, $keySchedule);  // -- encrypt counter block --
		
			// calculate length of final block:
			$blockLength = $b < $blockCount - 1 ? 16 : (strlen($plaintext) - 1) % 16 + 1;
	
			$ct = '';
			for ($i = 0; $i < $blockLength; $i++) 
			{  // -- xor plaintext with ciphered counter byte-by-byte --
				$plaintextByte = ord($plaintext[$b * 16 + $i]);
				$cipherByte = $plaintextByte ^ $cipherCntr[$i];
				$ct .= chr($cipherByte);
			}
	
			$ciphertext[$b] = self::escCtrlChars($ct);  // escape troublesome characters in ciphertext
		}
	
		// convert the nonce to a string to go on the front of the ciphertext
		$ctrTxt = '';
		for ($i = 0; $i < 4; $i++) $ctrTxt .= chr($counterBlock[$i]);
		$ctrTxt = self::escCtrlChars($ctrTxt);
	
		// use '+' to separate blocks, since encrypted blocks are of variable size after escaping ctrl chars
		// use Array.join to concatenate arrays of strings, as repeated string concatenation would be slow
		return $ctrTxt . '+' . implode('+', $ciphertext);
	}
	
	/** 
	 * Use AES to decrypt 'ciphertext' with 'password' using 128-bit key, in Counter mode of operation
	 *
	 *   for each block
	 *   - outputblock = cipher(counter, key)
	 *   - cipherblock = plaintext xor outputblock
	 */
	public static function decrypt($ciphertext, $password) 
	{
		$pwBytes = array();
		for ($i = 0; $i < 16; $i++) $pwBytes[$i] = ord($password[$i]);
		$pwKeySchedule = self::KeyExpansion(array(0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1));
		$key = self::Cipher($pwBytes, $pwBytes, $pwKeySchedule);
		
		$keySchedule = self::KeyExpansion($key);
		
		$ciphertext = explode('+', $ciphertext);  // split ciphertext into array of block-length strings 
		
		// recover nonce from 1st element of ciphertext
		$counterBlock = array();
		$ctrTxt = self::unescCtrlChars($ciphertext[0]);
		for ($i = 0; $i < 8; $i++) $counterBlock[$i] = ord($ctrTxt[$i % 4]);
		
		$plaintext = array();
		
		for ($b = 1; $b < count($ciphertext); $b++)
		{
			for ($c = 0; $c < 8; $c++) $counterBlock[15 - $c] = (($b - 1) >> ($c >= 4 ? 4 - $c : $c) * 8) & 0xff;  // set counter in counter block
	
			$cipherCntr = self::Cipher($counterBlock, $key, $keySchedule);  // encrypt counter block
	
			$ciphertext[$b] = self::unescCtrlChars($ciphertext[$b]);
			
			$pt = '';
			for ($i = 0; $i < strlen($ciphertext[$b]); $i++) 
			{
				$ciphertextByte = ord($ciphertext[$b][$i]);
				$plaintextByte = $ciphertextByte ^ $cipherCntr[$i];
				$pt .= chr($plaintextByte);
			}
	
			$plaintext[$b] = $pt;
		}
		
		return urldecode(implode('', $plaintext));
	}
	
	/**
	 * Escapes control chars which might cause problems handling ciphertext
	 * \xa0 to cater for bug in Firefox; include '+' to leave it free for use as a block marker
	 *
	 * @param string $str
	 * @return string
	 */
	private static function escCtrlChars($str) 
	{  
		return preg_replace_callback('/([\0\n\v\f\r\xa0+!])/', array('self', 'esc_callback'), $str);
	}
	
	/**
	 * escCtrlChars replace callback
	 *
	 * @param array $matches
	 * @return string
	 */
	private static function esc_callback($matches)
	{
		return '!' . strval(ord($matches[1])) . '!';
	}
	
	/**
	 * Unescapes potentially problematic control characters
	 *
	 * @param string $str
	 * @return string
	 */
	private static function unescCtrlChars($str) 
	{
		return preg_replace_callback('/!(\d\d?\d?)!/', array('self', 'unesc_callback'), $str);
	}
	
	
	/**
	 * unescCtrlChars callback replace function
	 *
	 * @param array $matches
	 * @return string
	 */
	private static function unesc_callback($matches)
	{
		return chr($matches[1]);
	}
	
	/**
	 * Converts byte array to hex
	 *
	 * @param array $b
	 * @return string
	 */
	private static function byteArrayToHexStr($b) 
	{  // convert byte array to hex string for displaying test vectors
		$s = '';
		for ($i = 0; $i < count($b); $i++) $s .= dechex($b[$i]) . ' ';
		return $s;
	}
	
}

?>