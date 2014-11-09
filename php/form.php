<?php

require_once 'include/sqAES.php';
require_once 'include/JCryption.php';

$postBefore = print_r($_POST, true);

JCryption::decrypt();

header('Content-type: text/plain');
echo "Original POST\n======================\n";
print_r($postBefore);
echo "jCryption example form\n======================\n";
print_r($_POST);
