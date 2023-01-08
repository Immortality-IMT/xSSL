<html>
<head>
<meta charset="utf-8"/>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8" />

<script type="text/javascript" src="../jsassl/lib/aes.js"></script>
<script type="text/javascript" src="../jsassl/assl_.js"></script>

</head>
<body>

<p id="d1"></p>
<p id="d2"></p>
<p id="d3"></p>
<p id="d4"></p>
<p id="d5"></p>
<p id="d6"></p>
<p id="d7"></p>
<p id="d8"></p>
<p id="d9"></p>
<p id="d10"></p>

<form action="phpong.php" method="post">
<label for="w3review">Encrypted and Encoded Ready 2b sent:</label><br />
<textarea id="w3review" name="w3review" rows="20" cols="80"></textarea>
  <br><br>
  <input type="submit" value="Submit">
</form>

<script type="text/javascript">

/************************************************
 This tests the AES encrypt and decrypt javascript
 functions are working properly 
*************************************************/

var testdata  = "\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

var key = "\x19\x91\x9d\x94~'*\x971K\xd5]LV"; //is 32 chars

        //call encrypt and display result
		//error_log('sends result to server log'.$key,0);

        document.getElementById("d1").innerHTML = "<h2>TESTDATA</h2><hr>" + testdata + "<hr>";

		var enc = AES.encrypt(testdata,key); //test js encrypt echo on d1

        document.getElementById("d2").innerHTML = "<h2>ENCRYPTED TESTDATA</h2>" + enc + "<hr>";

		var dec = AES.decrypt(enc,key); //test js decrypt echo on d2

        document.getElementById("d3").innerHTML = "<h2>DECRYPTED TESTDATA - should be clear text testdata</h2>" + dec + "<hr>";

        // local decryption test ends here

//************************************************************
// To send encrypted data over network you need to encode it
// first because of its unicode form breaks along tranmisson
//***********************************************************/

        //base64 encode

            var enc_enc = window.btoa(testdata);
            var dec_dec = window.atob(enc_enc);

        document.getElementById("d4").innerHTML = "<h2>Encoded Testdata</h2>" + enc_enc + "<hr>";
        document.getElementById("d5").innerHTML = "<h2>Decoded Testdata - should be clear text testdata</h2>" + dec_dec + "<hr>";

/* Send encrypted data to PHP and get PHP to decrypt */

		var enc2 = AES.encrypt(testdata,key);
        document.getElementById("d6").innerHTML = "<h2>Encrypted Waiting 2B Encoded Testdata</h2>" + enc2 + "<hr>";
        var enc_enc2 = window.btoa(enc2);
        document.getElementById("d7").innerHTML = "<h2>Encrypted and Encoded Testdata</h2>" + enc_enc2 + "<hr>";

        var dec_dec = window.atob(enc_enc2);
        var dec3 = AES.decrypt(dec_dec,key); //test js decrypt echo on d2

        document.getElementById("d8").innerHTML = "<h2>DECODE DECRYPTED - should be clear text testdata</h2>" + dec3 + "<hr>";

//Send the data

        //var is encry enc from above exmple

        document.getElementById("w3review").innerHTML;
        document.getElementById("w3review").value = enc_enc2;

       
/*Recieve data from php and decrypt */

</script>

<?php

//https://stackoverflow.com/questions/23740548/how-do-i-pass-variables-and-data-from-php-to-javascript

        $encfromphp = $_POST['w3review'];

//var dec = AES.decrypt(enc,key);<!-- snip -->
?>

<script type="text/javascript">
// copy php var to javascript -->	
	
    var data = <?php echo json_encode($encfromphp, JSON_HEX_TAG); ?>; // Don't forget the extra semicolon!

    document.getElementById("d9").innerHTML = "<h2>ENCRYPTED DATA FROM PHP</h2>" + data + "<hr>";

        var dec_php = window.atob(data);
        var final = AES.decrypt(dec_php,key); //test js decrypt echo on d2

     document.getElementById("d10").innerHTML = "<h2>DECODE DECRYPTED from php to js - should be clear text testdata</h2>" + final + "<hr>";
    

</script>

</body>
</html>
