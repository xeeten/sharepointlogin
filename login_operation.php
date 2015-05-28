<?php
session_start();
//require_once 'SPOClient.php';
require_once 'GetAuthentication.php';
$username = 'username@domain.net';
$password = 'yourpassword';
$url = "https://yourdomain.sharepoint.com";

$login = new GetAuthentication($username,$password,$url);
$login->SignIn();


$_SESSION['FedAuth'] = $login->FedAuth;
$_SESSION['FormDigestValue'] = $login->FormDigestValue;
$_SESSION['rtFa'] = $login->rtFa;

var_dump($_SESSION);
?>