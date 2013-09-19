<?php
	// Start the session so we can use sessions
	session_start();
	
	// If the GET parameter "generateKeypair" is set
	if(isset($_GET["generateKeypair"])) {
		$_SESSION["publickey"] = file_get_contents("rsa_4096_pub.pem");
		
		// Generate reponse
		$arrOutput = array(
			"publickey" => $_SESSION["publickey"]
		);
		// Convert the response to JSON, and send it to the client
		echo json_encode($arrOutput);
	// Else if the GET parameter "decrypttest" is set
	} elseif (isset($_GET["decrypttest"])) {
		date_default_timezone_set('UTC');
		// Get some test data to encrypt, this is an ISO 8601 timestamp
		$toEncrypt = date("c");
		// JSON encode the timestamp, both encrypted and unencrypted
		file_put_contents("message", $toEncrypt);

		$key = $_SESSION["key"];
		// Decrypt the client's request and send it to the clients(uncrypted)

		$encrypted = shell_exec("openssl enc -aes-256-cbc -in message -pass pass:'$key' -a -e");

		echo json_encode( 
			array(
				"encrypted" => $encrypted,
				"unencrypted" => $toEncrypt
			)
		);
	// Else if the GET parameter "handshake" is set
	} elseif (isset($_GET["handshake"])) {
		// Decrypt the client's request
		file_put_contents("message", base64_decode($_POST['key']));

		$key = shell_exec("openssl rsautl -decrypt -inkey rsa_4096_priv.pem -in message");
		file_put_contents("message", $key);
		// Save the AES key into the session
		$_SESSION["key"] = $key;
		
		// JSON encode the challenge
		$challenge = shell_exec("openssl enc -aes-256-cbc -in message -pass pass:'$key' -a -e");

		echo json_encode(array("challenge" => trim(str_replace("\n", "", $challenge))));
		// echo json_encode(array("challenge" => AesCtr::encrypt($key, $key, 256)));
	} else {
		file_put_contents("message", base64_decode($_POST['jCryption']));
		$key = $_SESSION["key"];
		// Decrypt the client's request and send it to the clients(uncrypted)
		$data = trim(str_replace("\n", "", shell_exec("openssl enc -aes-256-cbc -in message -pass pass:'$key' -d")));
		echo json_encode(array("data" => $data));
	}
?>