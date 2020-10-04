<?php
// if you are doing ajax with application-json headers
if (empty($_POST)) {
    $_POST = json_decode(file_get_contents("php://input"), true) ? : [];
}

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

$input = $serveraeskey." ".str_replace("\n", "", $_POST['iv'])." ".str_replace("\n", "", $_POST['encryptedTransaction'])." ".$clientpubkey." ".str_replace("\n", "", $_POST['signature']);

file_put_contents("temp3.txt",$input);

$cmd = "java -jar MobilePayDigiSignServerCode.jar ".$input;

$output = shell_exec($cmd); 

if(trim($output) == "valid"){
	echo "Transaction Sign Verification Successfully at Server side, Transaction Completed";
}
else{
	echo "Transaction Sign Verification failed at Server side, Transaction Cancelled";
}



?>