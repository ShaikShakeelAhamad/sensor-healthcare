<?php
//this server code recive clientPublicKeyEC
//then server send PublicKeyEC and AESShared(SignServerPrivateEC(ClientPublicKey))
// if you are doing ajax with application-json headers
try {
	
	if (empty($_POST)) {
		$_POST = json_decode(file_get_contents("php://input"), true) ? : [];
	}
	$input = str_replace("\n", "", $_POST['clientPublicKeyEC']);

	$cmd = "java -jar ServerAuthAtClient.jar ".$input;

	$output = shell_exec($cmd); 
	$keysdata = trim($output);

	/*output contain following
	Server Public Key
	Server Private Key
	Server AES Key
	Client Public Key
	Ciphertext of AES(ECSign(Client Public Key))
	AES IV
	*/

	file_put_contents("serverkeys.txt",$keysdata);

	$keysarray = (explode("-------",$keysdata));
	$spubkey = $keysarray[0];
	$ensign = $keysarray[4];
	$iv = $keysarray[5];
	
	$result = $spubkey."-------".$ensign."-------".$iv;
	echo $result;
}

//catch exception
catch(Exception $e) {
  echo 'Error: ' .$e->getMessage();
}



?>