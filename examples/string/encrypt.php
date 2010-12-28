<?php
	session_start();
	require_once("../../jCryption-1.1.php");
	$keyLength = 256;
	$jCryption = new jCryption();
	if(isset($_GET["generateKeypair"])) {
		$keys = $jCryption->generateKeypair($keyLength);
		$_SESSION["e"] = array("int" => $keys["e"], "hex" => $jCryption->dec2string($keys["e"],16));
		$_SESSION["d"] = array("int" => $keys["d"], "hex" => $jCryption->dec2string($keys["d"],16));
		$_SESSION["n"] = array("int" => $keys["n"], "hex" => $jCryption->dec2string($keys["n"],16));

		echo '{"e":"'.$_SESSION["e"]["hex"].'","n":"'.$_SESSION["n"]["hex"].'","maxdigits":"'.intval($keyLength*2/16+3).'"}';
	} else {
		$var = $jCryption->decrypt($_POST['jCryption'], $_SESSION["d"]["int"], $_SESSION["n"]["int"]);
		echo $var;
	}
?>