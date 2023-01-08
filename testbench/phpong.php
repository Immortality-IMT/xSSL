<?php
/*****************************************************
 This tests the AES encrypt and decrypt PHP functions
 are working properly
*****************************************************/

include "../phpassl/lib/Crypt/AES.php";


$testdata  = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
$testdata .= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

$key = "\x19\x91\x9d\x94~'*\x971K\xd5]LV"; //must be 16 bytes

        //call encrypt and display result
		error_log('sends result to server log'.$key,0);

        echo "<h2>TESTDATA</h2>".$testdata."<hr>";

		$enc = AES::encrypt($testdata, $key);

        echo "<h2>ENCRYPTED TESTDATA</h2>".$enc."<hr>";

		$dec = "<h2>DECRYPTED TESTDATA (should be cleartext testdata)</h2>".AES::decrypt($enc, $key);
        
        echo $dec."<hr>";

//test the base 64 encode decode

//************************************************************
// To send encrypted data over network you need to encode it
// first because of its unicode form breaks along tranmisson
//***********************************************************/

        //base64 encode

            $enc_enc =  base64_encode($testdata);
            $dec_dec =  base64_decode($enc_enc);

        echo "<h2>Encoded Testdata</h2>".$enc_enc."<hr>";
        echo "<h2>Decoded Testdata - should be clear text testdata</h2>".$dec_dec."<hr>";

//posted from js

$encfromjs = $_POST['w3review'];

echo "<h2>Encrypted Encoded Posted From Javascript</h2><hr>".$encfromjs;

         //decode base 64
         $decfromjs = base64_decode($encfromjs);

 		 $plainfromjs = AES::decrypt($decfromjs, $key);

                
echo "<h2>Decoded Decrypted Posted From Javascript - should be clear text testdata</h2><hr>";
        
        echo $plainfromjs."<hr>";

///Let's post back
echo "<h2>Encrypted Post To JS</h2><hr>";

		$enc_sendback = AES::encrypt($testdata, $key);

            echo $enc_sendback;

echo "<h2>Encrypted Encoded Post To Javascript</h2><hr>";

        //encode base 64
         $sendback = base64_encode($enc_sendback);

        echo $sendback;

echo "<h2>Encrypted and Encoded Ready 2B Sent To JS:</h2><hr>";

?>

<form action="jsping.php" method="post">
<label for="w3review">Encrypted and Encoded Ready 2b sent to js:</label><br />
<textarea id="w3review" name="w3review" rows="20" cols="80"><?php echo $sendback; ?></textarea>
  <br><br>
  <input type="submit" value="Submit">
</form>
