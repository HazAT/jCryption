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
} elseif (isset($_GET["handshake"])) {
	// Decrypt the response and get the AES key
	$key = $jCryption->decrypt($_POST['key'], $_SESSION["d"]["int"], $_SESSION["n"]["int"]);
	// Remove the RSA key from the session
	unset($_SESSION["e"]);
	unset($_SESSION["d"]);
	unset($_SESSION["n"]);
	// Save the AES key into the session
	$_SESSION["key"] = $key;
	// Echo the challenge
	echo json_encode(array("challenge" => AesCtr::encrypt($key, $key, 256)));
} else {
	// Send the HTML page to the user
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Result</title>
<style type="text/css">
html,body {
	margin:0;
	padding:0;
	font-family:Tahoma;
	font-size:12px;
}
</style>
</head>
<body>

<p><strong>orignial POST:</strong> <br/><?php print_r($_POST); ?></p>
<?php
$var = AesCtr::decrypt($_POST['jCryption'], $_SESSION["key"], 256);
parse_str($var, $result);
?>

<p><strong>decrypted POST:</strong> <br/><?php print_r($result); ?></p>

</body>
</html>

<?php
}
?>
