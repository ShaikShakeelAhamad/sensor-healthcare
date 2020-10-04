<?php
//this code recive client AES(SignClentPri(ServerPublic))

// if you are doing ajax with application-json headers
if (empty($_POST)) {
    $_POST = json_decode(file_get_contents("php://input"), true) ? : [];
}

$iv = str_replace("\n", "", $_POST['iv']);
$endata = str_replace("\n", "", $_POST['clientENPdata']);
$csign  = str_replace("\n", "", $_POST['clientSignature']);

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


$input = $serveraeskey." ".$iv." ".$endata." ".$clientpubkey." ".$csign;

file_put_contents("temp2.txt",$input);

$cmd = "java -jar ConfirmHealthCareContact.jar ".$input;

$output = shell_exec($cmd); 

if(trim($output) == "valid"){
	echo "Patient Sensor Readings Verified at Health Care Server Successfully, Readings stored and Readings sent to Doctor.";
}
else{
	echo "Patient Sensor Readings Verification failed at Health Care Server, Please close the App and try again";
}

?>