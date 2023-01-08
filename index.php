<?php

$rc = rand();
$a1024 = isset($_GET['size']) && $_GET['size'] == '1024' ? 1 : 0;

?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>

<meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

<style type="text/css"> 
@import 'base.css'; 
</style>

<title>aSSL</title>

<!-- Turning off caching for dev -->
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
<meta http-equiv="Pragma" content="no-cache" />
<meta http-equiv="Expires" content="0" />

<link rel="shortcut icon" href="images/favicon.ico" />

<!-- the entire aSSL system must be included in every page 10 files -->
<!-- the order of the files is important jsbn, prng4, rng, rsa, aes, assl -->
<!-- use jquery to post forms to server -->
<link rel="stylesheet" href="base.css" type="text/css" media="all">
<script type="text/javascript" src="jquery.js"></script>
<script type="text/javascript" src="jsassl/lib/jsbn/jsbn.js"></script>
<script type="text/javascript" src="jsassl/lib/jsbn/prng4.js"></script>
<script type="text/javascript" src="jsassl/lib/jsbn/rng.js"></script>
<script type="text/javascript" src="jsassl/lib/jsbn/rsa.js"></script>
<script type="text/javascript" src="jsassl/lib/aes.js"></script>
<script type="text/javascript" src="jsassl/assl_.js"></script>
<!--ends here -->

<?php
require_once "phpassl/lib/Crypt/RSA.php";
require_once "phpassl/lib/Crypt/AES.php";
require_once "phpassl/assl_.php";
?>

<script type="text/javascript">

// This functions shows the status of the connections during aSSL processes:

// Returns web root dir
var base = window.location.toString().split("?")[0].replace(/[^\/]+$/,"")

// Step 1 connect - aSSL.connect method
// showConn is the function that aSSL.connect calls after the connection is established
//*******************************//
// The connect routine - step 1  //
//*******************************//

    $(document).ready(function(){

        //Set browser cache to false for jquery.
        (function($) {
            $.ajaxSetup({
                cache: false,
            });
        })(jQuery);

        	$('#result').hide()
        	$("#connecting").show()

	    var url = base +'conn.php<?=$a1024 ? "?size=1024&" : ""?>'

	    aSSL.connect(url,showConn)
    })

//*********************************//
// The result of connect - step 2  //
//*********************************//
function showConn(response) {


	if (response) {

		$('#connecting').hide();
        $('.connecting').hide();

		$('#timeElapsed').html(aSSL.connections['0'].timeElapsed);
        $('.timeElapsed').html(aSSL.connections['0'].timeElapsed);

		$('#'+(aSSL.connections['0'].sessionTimeout?'connected':'noConnect')).show();
		$('.'+(aSSL.connections['0'].sessionTimeout?'connected':'noConnect')).show();

	} else {

	    $('#noConnect').show();
        $('.noConnect').show();
    }
}

/*
    connection routine ends here

    now do your back and forth
    send and receive functions

    call encrypt () and send ()
    call receive () and decrypt ()
*/

var nick = "";

// When we try to login we launch the following:

function encryptSend() {

	nick = $("#nickname").val()
	
// encrypt the querystring and run the ajax process usign the POST method
	var txt = aSSL.encrypt("nickname="+nick+"&password="+$("#password").val())
	var url = base +'login.php'
	$.ajax({url:url,type:"POST",data:"data="+txt,complete:decryptReceive});
	return false;
}


function decryptReceive(response) {

	if (response) {
/*
/************************************************************
/************************************************************
/************************************************************
 Todo: we must call the decrypt function which is missing
*************************************************************/

        window.alert(response.responseText); // only use with write and not send option see login.php

    var res = aSSL.decrypt(response.responseText);
    
        window.alert(res); // only use with write and not send option see login.php

        
        //This depends of what we expect from the server. In this example we expect the id of the user (i.e. 1 or 2):
		
        //if (response.responseText == '1' || response.responseText == '2') {

        if (res == '1' || response.res == '2') {
			$('#module').html('<h1>Welcome '+nick+'</h1><h2><a href="javascript:location.reload()">Logout</a></h2>')
			$('#login').hide()
            document.getElementById('login').innerHTML.hide()
            document.getElementById('result').innerHTML.hide()
			$('#result').hide()
            document.getElementById('status').innerHTML.hide()
			$('#status').hide()
		}
		else {
			$('#result').html("Incorrect username or password, try again").show();
            $('.result').html("Incorrect username or password, try again").show();
		}

	}
	else {

		$('#result').html("Connection error...").show();
        $('.result').html("Connection error...").show();
	}
}

</script>
</head>
<body>
<div id="asslbar">
	<div id="connecting" class="asslStatus">Establishing an aSSL encrypted connection with the server.</div>
	<div id="connected" class="asslStatus">An aSSL encrypted connection has been established. Time elapsed: <span id="timeElapsed"></span> ms.</div>
	<div id="noconnect" class="asslStatus">Warning! Unable to establish an aSSL encrypted connection.</div>
</div>

<div id="bodyAround">

<div id="bodyBody">

    <p id="over"><a href=""><img src="images/logo.gif" alt="aSSL logo" border="0"/></a></p>

    <p>This simple example uses aSSL with a <strong><?=$a1024 ? 1024 : 512?>-bit</strong> RSA key. After the encrypted connection has been established, try logging in with: <strong>guru</strong>/<strong>jolly</strong> or <strong>admin</strong>/<strong>easy</strong> :o)</p>

        <div id="loginform"><div id="module"></div>
        <div class="bloc" id="login" >

            <form name="login" onsubmit="return false;">

	            <label for="nickname">Nickname</label> <input type="text" id="nickname" name="nickname" onfocus="this.value='';$('#result').hide()" /><br />
	            <label for="password">Password</label> <input type="password" id="password" name="password" onfocus="this.value='';$('#result').hide()" /><br />

            <div id="result"></div>
	
                <input type="submit" class="button" value="login" onclick="encryptSend()" />

            </form>

        </div>
        </div>

<p><span class="style3">aSSL negotiate the exchange 128-bit key using <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/" target="_blank">RSA algorithm</a>. After negotiation, the data are encrypted and decrypted using <a href="http://www.movable-type.co.uk/scripts/AES.html" target="_blank">AES algorithm</a>. </span></p>

<p class="myp"><strong><a href="./<?=$a1024 ? "" : "?size=1024"?>">A <?=$a1024 ? "faster" : "slower"?> aSSL example using a <?=$a1024 ? 512 : 1024?>-bit RSA key</a></strong></p>

<p class="myp style3"><b>(c) 2006, 2007 Francesco Sullo - Rome, Italy </b></p>

</div>
</div>
</body>
</html>
