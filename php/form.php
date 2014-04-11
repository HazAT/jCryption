<?php

require_once('include/sqAES.php');
require_once('include/jcryption.php');

jcryption::decrypt();

Header('Content-type: text/plain');
echo "jCryption example form\n======================\n";
print_r($_POST);

?>