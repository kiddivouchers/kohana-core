<?php defined('SYSPATH') or die('No direct script access.');
/**
 * The Encrypt library provides two-way encryption of text and binary strings
 * using the [Sodium](https://www.php.net/manual/en/book.sodium.php) extension.

 * @package    Kohana
 * @category   Security
 * @author     Kohana Team
 * @copyright  (c) 2007-2012 Kohana Team
 * @license    http://kohanaframework.org/license
 */
class Kohana_Encrypt {
	/**
	 * @var string
	 */
	public static $default = 'default';

	/**
	 * @var array
	 */
	public static $instances = [];

	/**
	 * @var string
	 */
	private $key;

	/**
	 * Returns a singleton instance of Encrypt. An encryption key must be
	 * provided in your "encrypt" configuration file.
	 *
	 * @param string $name configuration group name
	 *
	 * @return self
	 */
	public static function instance($name = null)
	{
		if ($name === null)
		{
			$name = self::$default;
		}

		if (!isset(self::$instances[$name]))
		{
			// Load the configuration data
			$config = \Kohana::$config->load('encrypt')->$name;

			if (!isset($config['key']))
			{
				// No default encryption key is provided!
				throw new \Kohana_Exception('No encryption key is defined in the encryption configuration group: :group',
					array(':group' => $name));
			}

			// Create a new instance
			self::$instances[$name] = new self($config['key']);
		}

		return self::$instances[$name];
	}

	/**
	 * @param string $key Encryption key (hexadecimal)
	 */
	public function __construct($key)
	{
		$this->key = hex2bin($key);
	}

	/**
	 * Encrypts the data and returns it as a base 64 encoded string.
	 *
	 * @param string $data
	 *
	 * @return string
	 */
	public function encode($data)
	{
		$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$encryptedData = sodium_crypto_secretbox($data, $nonce, $this->key);

		// Base 64 encode the encrypted data.
		return base64_encode(bin2hex($nonce.$encryptedData));
	}

	/**
	 * Decrypts the encoded base 64 data to it's original value.
	 * Returns false if the decryption fails.
	 *
	 * @param string $data
	 *
	 * @return string|false
	 */
	public function decode($data)
	{
		$data = base64_decode($data, true);

		if (!$data)
		{
			return false;
		}

		// Nonce is twice the size when converted to hexadecimal.
		$nonceSize = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES * 2;

		// Extract the nonce (hexadecimal) from the data (hexadecimal).
		$nonce = substr($data, 0, $nonceSize);

		// Remove the nonce from the data.
		$data = substr($data, $nonceSize);

		$encryptedData = sodium_crypto_secretbox_open(hex2bin($data), hex2bin($nonce), $this->key);

		if (!$encryptedData)
		{
			return false;
		}

		return $encryptedData;
	}


} // End Encrypt
