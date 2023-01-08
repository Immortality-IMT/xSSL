<?php
//start session as AES key is stored in $_SESSION
session_start();
//require file with key(s)
require_once 'mykey.php';

// the aSSL library
require_once 'assl-php/assl.php';

// To establish the aSSL connection it is sufficient the following line:
aSSL::response(isset($_GET['size']) && $_GET['size'] == 1024 ? $myKey1024 : $myKey);
?>