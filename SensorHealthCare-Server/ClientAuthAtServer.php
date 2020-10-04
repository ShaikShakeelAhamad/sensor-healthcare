<?php
//this code recive client AES(SignClentPri(ServerPublic))

// if you are doing ajax with application-json headers
if (empty($_POST)) {
    $_POST = json_decode(file_get_contents("php://input"), true) ? : [];
}

$iv = str_replace("\n", "", $_POST['iv']);
$ensign = str_replace("\n", "", $_POST['clientENSign']);

$filedata = file_get_contents('serverkeys.txt');

$keysdata = trim($filedata);

/*output contain following
Server Public Key
Server Private Key
Server AES Key
Client Public Key
Ciphertext of AES(ECSign(Client Public Key))
AES IV
*/

$keysarray = (explode("-------",$keysdata));
$serveraeskey = $keysarray[2];
$clientpubkey = $keysarray[3];
$serverpubkey = $keysarray[0];


$input = $serveraeskey." ".$iv." ".$ensign." ".$clientpubkey." ".$serverpubkey;

file_put_contents("temp.txt",$input);

$cmd = "java -jar ClientAuthAtServer.jar ".$input;

$output = shell_exec($cmd); 

if(trim($output) == "valid"){
	echo "Client Verified Successfully at Server side, Client Authenticated";
}
else{
	echo "Client Verification failed at Server side, Client Authentication Failed";
}

?>