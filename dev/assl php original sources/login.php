<?php
//start session as AES key is stored in $_SESSION
session_start();
//require needed files
require_once 'assl-php/assl.php';
//decrypt server request
$decrypted = aSSL::decrypt($_POST['data']);
//get associative array from encrypted data
$res = aSSL::querystr($decrypted);

//valid users
$users = array('guru' => 'jolly', 'admin' => 'crazy');

$result = ($users[$res['nickname']] && $users[$res['nickname']] == $res['password']) ? 1 : 0;
//output result. It can be done with aSSL::send($result) if data returned to server should be encrypted.
aSSL::write($result);
?>