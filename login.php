<?php
/*
the aSSL system includes required in every file
if the file is not displayed to the user then the 
js includes are not required / 3 files
*/
require_once "phpassl/lib/Crypt/RSA.php";
require_once "phpassl/lib/Crypt/AES.php";
require_once "phpassl/assl_.php";

//start session as RSA key is stored in $_SESSION
session_start();

//decrypt server request
$decrypted = aSSL::decrypt($_POST['data']);

//turn POST data into array format rather than string
$res = aSSL::querystr($decrypted);

//now the server can compare for valid users
$users = array('guru' => 'jolly', 'admin' => 'easy');

$result = ($users[$res['nickname']] && $users[$res['nickname']] == $res['password']) ? 1 : 0;
//Returns 1 or 0 to allow access.

//aSSL::write($result); //only data sent is encrypted, data return to server is not encrypted

aSSL::send($result); //must use send - both send and receive are encrypted
?>
