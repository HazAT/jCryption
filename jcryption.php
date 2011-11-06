<?php
/**
* jCryption
*
* PHP version 5.3
*
* LICENSE: This source file is subject to version 3.0 of the PHP license
* that is available through the world-wide-web at the following URI:
* http://www.php.net/license/3_0.txt.  If you did not receive a copy of
* the PHP License and are unable to obtain it through the web, please
* send a note to license@php.net so we can mail you a copy immediately.
*
* Many of the functions in this class are from the PEAR Crypt_RSA package ...
* So most of the credits goes to the original creator of this package Alexander Valyalkin
* you can get the package under http://pear.php.net/package/Crypt_RSA
*
* I just changed, added, removed and improved some functions to fit the needs of jCryption
*
* @author     Daniel Griesser <daniel.griesser@jcryption.org>
* @copyright  2011 Daniel Griesser
* @license    http://www.php.net/license/3_0.txt PHP License 3.0
* @version    1.2
* @link       http://jcryption.org/
*/
class jCryption {

	private $_key_len;
	private $_e;

	public function __construct($e="\x01\x00\x01") {
		$this->_e = $e;
	}

	/**
	* Generates the Keypair with the given keyLength the encryption key e ist set staticlly
	* set to 65537 for faster encryption.
	*
	* @param int $keyLength
	* @return array
	*/
	public function generateKeypair($keyLength) {
		$this->_key_len = intval($keyLength);
		if ($this->_key_len < 8) {
			$this->_key_len = 8;
		}
		// set [e] to 0x10001 (65537)
		$e = $this->_bin2int($this->_e);
		// generate [p], [q] and [n]
		$p_len = intval(($this->_key_len + 1) / 2);
		$q_len = $this->_key_len - $p_len;
		$p1 = $q1 = 0;
		do {
			// generate prime number [$p] with length [$p_len] with the following condition:
			// GCD($e, $p - 1) = 1
			do {
				$p = $this->getPrime($p_len);
				$p1 = bcsub($p, '1');
				$tmp = $this->_gcd($e, $p1);
			} while (bccomp($tmp, '1'));
			// generate prime number [$q] with length [$q_len] with the following conditions:
			// GCD($e, $q - 1) = 1
			// $q != $p
			do {
				$q = $this->getPrime($q_len);
				$q1 = bcsub($q, '1');
				$tmp = $this->_gcd($e, $q1);
			} while (bccomp($tmp, '1') && !bccomp($q, $p));

			// if (p < q), then exchange them
			if (bccomp($p, $q) < 0) {
				$tmp = $p;
				$p = $q;
				$q = $tmp;
				$tmp = $p1;
				$p1 = $q1;
				$q1 = $tmp;
			}
			// calculate n = p * q
			$n = bcmul($p, $q);

		} while ($this->_bitLen($n) != $this->_key_len);

		// calculate d = 1/e mod (p - 1) * (q - 1)
		$pq = bcmul($p1, $q1);
		$d = $this->_invmod($e, $pq);

		// store RSA keypair attributes
		return array('n' => $n, 'e' => $e, 'd' => $d, 'p' => $p, 'q' => $q);
	}

	/**
	* Finds greatest common divider (GCD) of $num1 and $num2
	*
	* @param string $num1
	* @param string $num2
	* @return string
	*/
	private function _gcd($num1, $num2) {
		do {
			$tmp = bcmod($num1, $num2);
			$num1 = $num2;
			$num2 = $tmp;
		} while (bccomp($num2, '0'));
		return $num1;
	}

	/**
	* Transforms binary representation of large integer into its native form.
	*
	* Example of transformation:
	*    $str = "\x12\x34\x56\x78\x90";
	*    $num = 0x9078563412;
	*
	* @param string $str
	* @return string
	* @access public
	*/
	private function _bin2int($str) {
		$result = '0';
		$n = strlen($str);
		do {
			$result = bcadd(bcmul($result, '256'), ord($str {--$n} ));
		} while ($n > 0);
		return $result;
	}

	/**
	* Transforms large integer into binary representation.
	*
	* Example of transformation:
	*    $num = 0x9078563412;
	*    $str = "\x12\x34\x56\x78\x90";
	*
	* @param string $num
	* @return string
	* @access public
	*/
	private function _int2bin($num) {
		$result = '';
		do {
			$result .= chr(bcmod($num, '256'));
			$num = bcdiv($num, '256');
		} while (bccomp($num, '0'));
		return $result;
	}

	/**
	* Generates prime number with length $bits_cnt
	*
	* @param int $bits_cnt
	*/
	public function getPrime($bits_cnt) {
		$bytes_n = intval($bits_cnt / 8);
		do {
			$str = '';
			$str = openssl_random_pseudo_bytes($bytes_n);
			$num = $this->_bin2int($str);
			$num = gmp_strval(gmp_nextprime($num));
		} while ($this->_bitLen($num) != $bits_cnt);
		return $num;
	}

	/**
	* Finds inverse number $inv for $num by modulus $mod, such as:
	*     $inv * $num = 1 (mod $mod)
	*
	* @param string $num
	* @param string $mod
	* @return string
	*/
	private function _invmod($num, $mod) {
		$x = '1';
		$y = '0';
		$num1 = $mod;
		do {
			$tmp = bcmod($num, $num1);
			$q = bcdiv($num, $num1);
			$num = $num1;
			$num1 = $tmp;
			$tmp = bcsub($x, bcmul($y, $q));
			$x = $y;
			$y = $tmp;
		} while (bccomp($num1, '0'));
		if (bccomp($x, '0') < 0) {
			$x = bcadd($x, $mod);
		}
		return $x;
	}

	/**
	* Returns bit length of number $num
	*
	* @param string $num
	* @return int
	*/
	private function _bitLen($num) {
		$tmp = $this->_int2bin($num);
		$bit_len = strlen($tmp) * 8;
		$tmp = ord($tmp {strlen($tmp) - 1} );
		if (!$tmp) {
			$bit_len -= 8;
		} else {
			while (!($tmp & 0x80)) {
				$bit_len--;
				$tmp <<= 1;
			}
		}
		return $bit_len;
	}

	/**
	* Converts a hex string to bigint string
	*
	* @param string $hex
	* @return string
	*/
	private function _hex2bint($hex) {
		$result = '0';
		for ($i=0; $i < strlen($hex); $i++) {
			$result = bcmul($result, '16');
			if ($hex[$i] >= '0' && $hex[$i] <= '9') {
				$result = bcadd($result, $hex[$i]);
			} else if ($hex[$i] >= 'a' && $hex[$i] <= 'f') {
				$result = bcadd($result, '1' . ('0' + (ord($hex[$i]) - ord('a'))));
			} else if ($hex[$i] >= 'A' && $hex[$i] <= 'F') {
				$result = bcadd($result, '1' . ('0' + (ord($hex[$i]) - ord('A'))));
			}
		}
		return $result;
	}

	/**
	* Converts a hex string to int
	*
	* @param string $hex
	* @return int
	* @access public
	*/
	private function _hex2int($hex) {
		$result = 0;
		for ($i=0; $i < strlen($hex); $i++) {
			$result *= 16;
			if ($hex[$i] >= '0' && $hex[$i] <= '9') {
				$result += ord($hex[$i]) - ord('0');
			} else if ($hex[$i] >= 'a' && $hex[$i] <= 'f') {
				$result += 10 + (ord($hex[$i]) - ord('a'));
			} else if ($hex[$i] >= 'A' && $hex[$i] <= 'F') {
				$result += 10 + (ord($hex[$i]) - ord('A'));
			}
		}
		return $result;
	}

	/**
	* Converts a bigint string to the ascii code
	*
	* @param string $bigint
	* @return string
	*/
	private function _bint2char($bigint) {
		$message = '';
		while (bccomp($bigint, '0') != 0) {
			$ascii = bcmod($bigint, '256');
			$bigint = bcdiv($bigint, '256', 0);
			$message .= chr($ascii);
		}
		return $message;
	}

	/**
	* Removes the redundacy in den encrypted string
	*
	* @param string $string
	* @return mixed
	*/
	private function _redundacyCheck($string) {
		$r1 = substr($string, 0, 2);
		$r2 = substr($string, 2);
		$check = $this->_hex2int($r1);
		$value = $r2;
		$sum = 0;
		for ($i=0; $i < strlen($value); $i++) {
			$sum += ord($value[$i]);
		}
		if ($check == ($sum & 0xFF)) {
			return $value;
		} else {
			return NULL;
		}
	}

	/**
	* Decrypts a given string with the $dec_key and the $enc_mod
	*
	* @param string $encrypted
	* @param int $dec_key
	* @param int $enc_mod
	* @return string
	*/
	public function decrypt($encrypted, $dec_key, $enc_mod) {
		//replaced split with explode
		$blocks = explode(' ', $encrypted);
		$result = "";
		$max = count($blocks);
		for ($i=0; $i < $max; $i++) {
			$dec = $this->_hex2bint($blocks[$i]);
			$dec = bcpowmod($dec, $dec_key, $enc_mod);
			$ascii = $this->_bint2char($dec);
			$result .= $ascii;
		}
		return $this->_redundacyCheck($result);
	}

	/**
	* Converts a given decimal string to any base between 2 and 36
	*
	* @param string $decimal
	* @param int $base
	* @return string
	*/
	public function dec2string($decimal, $base) {
		$string = null;
		$base = (int) $base;
		if ($base < 2 | $base > 36 | $base == 10) {
			echo 'BASE must be in the range 2-9 or 11-36';
			exit;
		}

		$charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$charset = substr($charset, 0, $base);

		do {
			$remainder = bcmod($decimal, $base);
			$char = substr($charset, $remainder, 1);
			$string = $char . $string;
			$decimal = bcdiv(bcsub($decimal, $remainder), $base);
		} while ($decimal > 0);

		return strtolower($string);
	}
}

