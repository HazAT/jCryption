<?php
	session_start();
	require_once("../../jcryption.php");

	$keyLength = 1024;
	$jCryption = new jCryption();

	if(isset($_GET["generateKeypair"])) {
		require_once("../../100_1024_keys.inc.php");
		$keys = $arrKeys[mt_rand(0, 100)];
		$_SESSION["e"] = array("int" => $keys["e"], "hex" => $jCryption->dec2string($keys["e"], 16));
		$_SESSION["d"] = array("int" => $keys["d"], "hex" => $jCryption->dec2string($keys["d"], 16));
		$_SESSION["n"] = array("int" => $keys["n"], "hex" => $jCryption->dec2string($keys["n"], 16));
		$arrOutput = array(
			"e" => $_SESSION["e"]["hex"],
			"n" => $_SESSION["n"]["hex"],
			"maxdigits" => intval($keyLength*2/16+3)
		);
		echo json_encode($arrOutput);
	} elseif (isset($_GET["decrypttest"])) {
		$toEncrypt = date("c");
		echo json_encode( 
			array(
				"encrypted" => AesCtr::encrypt($toEncrypt, $_SESSION["key"], 256),
				"unencrypted" => $toEncrypt
			)
		);
	} elseif (isset($_GET["handshake"])) {
		$key = $jCryption->decrypt($_POST['key'], $_SESSION["d"]["int"], $_SESSION["n"]["int"]);
		unset($_SESSION["e"]);
		unset($_SESSION["d"]);
		unset($_SESSION["n"]);
		$_SESSION["key"] = $key;
		echo json_encode(array("challenge" => AesCtr::encrypt($key, $key, 256)));
	} else {
		echo json_encode(array("data" => AesCtr::decrypt($_POST['jCryption'], $_SESSION["key"], 256)));
	}
?>