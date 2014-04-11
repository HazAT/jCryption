<?php
require_once('sqAES.php');
				
session_start();

if(isset($_GET['getPublicKey'])) {
	Header('Content-type: application/json');
	echo json_encode(array('publickey' => file_get_contents('rsa_1024_pub.pem')));
	exit();
}

if (isset($_GET['handshake'])) {
	// Decrypt the client's request
	openssl_private_decrypt(base64_decode($_POST['key']), $key, file_get_contents('rsa_1024_priv.pem'));
	$_SESSION['key'] = $key;
	// JSON encode the challenge
	Header('Content-type: application/json');
	echo json_encode(array('challenge' =>  sqAES::crypt($key, $key)));
	exit();
}

if (isset($_GET['decrypttest'])) {
	// set timezone just in case
	date_default_timezone_set('UTC');
	// Get some test data to encrypt, this is an ISO 8601 timestamp
	$toEncrypt = date('c');

	// get the key from the session
	$key = $_SESSION['key'];

	$encrypted = sqAES::crypt($key, $toEncrypt);
	
	Header('Content-type: application/json');
	echo json_encode( 
		array(
			'encrypted' => $encrypted,
			'unencrypted' => $toEncrypt
		)
	);
	exit();
}

if(isset($_POST['jCryption'])) {
	// Decrypt the client's request and stick it in the _POST & _REQUEST globals.
	parse_str(sqAES::decrypt($_SESSION['key'], $_POST['jCryption']), $_POST);
	unset($_SESSION['key']);
	unset($_REQUEST['jCryption']);
	$_REQUEST = array_merge($_POST, $_REQUEST);
}

Header('Content-type: text/plain');
print_r($_POST);

?>
