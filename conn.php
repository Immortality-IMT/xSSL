<?php
// the aSSL library
require_once "phpassl/lib/Crypt/RSA.php";
require_once "phpassl/lib/Crypt/AES.php";
require_once "phpassl/assl_.php";
//must be include in every file

//required only on connect RSA key pair
require_once "phpassl/mykey.php";

//AES key is stored in $_SESSION
session_start();

// To establish an aSSL connection use the following line
aSSL::response(isset($_GET['size']) && $_GET['size'] == 1024 ? $myKey1024 : $myKey);
?>
