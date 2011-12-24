<?php
	// Start the session so we can use sessions
	session_start();
	// Include the jCryption PHP library
	require_once("../../jcryption.php");
	// Set the RSA key length
	$keyLength = 1024;
	// Create a new jCryption object
	$jCryption = new jCryption();

	// If the GET parameter "generateKeypair" is set
	if(isset($_GET["generateKeypair"])) {
		// Include some RSA keys
		require_once("../../100_1024_keys.inc.php");
		// Pick a random key from the array
		$keys = $arrKeys[mt_rand(0, 100)];
		// Save the RSA key into session
		$_SESSION["e"] = array("int" => $keys["e"], "hex" => $jCryption->dec2string($keys["e"], 16));
		$_SESSION["d"] = array("int" => $keys["d"], "hex" => $jCryption->dec2string($keys["d"], 16));
		$_SESSION["n"] = array("int" => $keys["n"], "hex" => $jCryption->dec2string($keys["n"], 16));
		// Generate reponse
		$arrOutput = array(
			"e" => $_SESSION["e"]["hex"],
			"n" => $_SESSION["n"]["hex"],
			"maxdigits" => intval($keyLength*2/16+3)
		);
		// Convert the response to JSON, and send it to the client
		echo json_encode($arrOutput);
	// Else if the GET parameter "decrypttest" is set
	} elseif (isset($_GET["decrypttest"])) {
		// Get some test data to encrypt, this is an ISO 8601 timestamp
		$toEncrypt = date("c");
		// JSON encode the timestamp, both encrypted and unencrypted
		echo json_encode( 
			array(
				"encrypted" => AesCtr::encrypt($toEncrypt, $_SESSION["key"], 256),
				"unencrypted" => $toEncrypt
			)
		);
	// Else if the GET parameter "handshake" is set
	} elseif (isset($_GET["handshake"])) {
		// Decrypt the client's request
		$key = $jCryption->decrypt($_POST['key'], $_SESSION["d"]["int"], $_SESSION["n"]["int"]);
		// Remove the RSA key from the session
		unset($_SESSION["e"]);
		unset($_SESSION["d"]);
		unset($_SESSION["n"]);
		// Save the AES key into the session
		$_SESSION["key"] = $key;
		// JSON encode the challenge
		echo json_encode(array("challenge" => AesCtr::encrypt($key, $key, 256)));
	} else {
		// Decrypt the client's request and send it to the clients(uncrypted)
		echo json_encode(array("data" => AesCtr::decrypt($_POST['jCryption'], $_SESSION["key"], 256)));
	}
?>