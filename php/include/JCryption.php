<?php

class JCryption
{
    private $private_key_file;
    private $public_key_file;

    const SESSION_KEY = 'jCryptionKey';
    const POST_KEY = 'jCryption';

    public function __construct($public_key_file, $private_key_file)
    {
        $this->public_key_file = $public_key_file;
        $this->private_key_file = $private_key_file;

        if (!is_readable($this->private_key_file)) {
            throw new Exception('Unable to read private key');
        }
        if (!is_readable($this->public_key_file)) {
            throw new Exception('Unable to read public key');
        }

        $this->session_start();
    }

    public function getPublicKey()
    {
        Header('Content-type: application/json');
        echo json_encode(array('publickey' => file_get_contents($this->public_key_file)));
        exit();
    }

    public function handshake()
    {
        openssl_private_decrypt(base64_decode($_POST['key']), $key, file_get_contents($this->private_key_file));
        $_SESSION[self::SESSION_KEY] = $key;
        Header('Content-type: application/json');
        echo json_encode(array('challenge' =>  sqAES::crypt($key, $key)));
        exit();
    }

    public function decrypttest()
    {
        // set timezone just in case
        date_default_timezone_set('UTC');
        // Get some test data to encrypt, this is an ISO 8601 timestamp
        $toEncrypt = date('c');

        // get the key from the session
        $key = $_SESSION[self::SESSION_KEY];

        $encrypted = sqAES::crypt($key, $toEncrypt);

        header('Content-type: application/json');
        echo json_encode(
            array(
                'encrypted' => $encrypted,
                'unencrypted' => $toEncrypt,
            )
        );
        exit();
    }

    public static function decrypt()
    {
        self::session_start();
        parse_str(sqAES::decrypt($_SESSION[self::SESSION_KEY], $_POST[self::POST_KEY]), $_POST);
        //Can't unset the key here, it breaks bi-directional.
        //unset($_SESSION[self::SESSION_KEY]);
        unset($_REQUEST[self::POST_KEY]);
        $_REQUEST = array_merge($_POST, $_REQUEST);
    }

    public function go()
    {
        if (isset($_GET['getPublicKey'])) {
            $this->getPublicKey();
        }
        if (isset($_GET['handshake'])) {
            $this->handshake();
        }
        if (isset($_GET['decrypttest'])) {
            $this->decrypttest();
        }
        if (isset($_POST[self::POST_KEY])) {
            $this->decrypt();
        }
    }

    public static function session_start()
    {
        switch (session_status()) {
            case PHP_SESSION_DISABLED :
                throw new Exception('jCryption requires sessions');
                break;
            case PHP_SESSION_NONE :
                session_start();
                break;
        }
    }
}
