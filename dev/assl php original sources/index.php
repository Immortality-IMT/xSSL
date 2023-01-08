<?php

$rc = rand();
$a1024 = isset($_GET['size']) && $_GET['size'] == '1024' ? 1 : 0;

?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<style type="text/css"> 
@import '../css/base2.css';
@import 'css/base.css'; 
</style>
<title>aSSL 1.2beta</title>
<link rel="shortcut icon" href="pic/favicon.ico" />
<script type="text/javascript" src="lib/jquery.js"></script>
<script type="text/javascript" src="assl1.2/assl.js"></script>

<script type="text/javascript">

// This functions shows the status of the connections during aSSL processes:

// I define the base path:
var base = window.location.toString().split("?")[0].replace(/[^\/]+$/,"")

$(document).ready(function(){	
	$('#result').hide()
	$("#connecting").show()
	var url = base +'conn.php<?=$a1024 ? "?size=1024&" : ""?>'

// On document load this launches the aSSL.connect method to establish the aSSL connection.
// showConn is the function that the aSSL.connect method calls after the connection is established
	aSSL.connect(url,showConn)
})



function showConn(response) {
	if (response) {
		$("#connecting").hide()
		$("#timeElapsed").html(aSSL.connections['0'].timeElapsed)
		$('#'+(aSSL.connections['0'].sessionTimeout?'connected':'noConnect')).show()
	}
	$('#noConnect').show()
}



var nick = ""

// When we try to login we launch the following:

function loginGo() {
	nick = $("#nickname").val()
	
// encrypt the querystring and run the ajax process usign the POST method
	var txt = aSSL.encrypt("nickname="+nick+"&password="+$("#password").val())
	var url = base +'login.php'
	$.ajax({url:url,type:"POST",data:"data="+txt,complete:showResponse});
	return false;
}


function showResponse(response) {  
	if (response) {
	
// This depends of what we expect from the server. In this example we expect the id of the user (i.e. 1 or 2):
		if (response.responseText == '1' || response.responseText == '2') {
			$('#module').html('<div class="big">Welcome <b>'+nick+'</b></div><a href="javascript:location.reload()">Logout</a><br/>')
			$('#login').hide()
			$('#result').hide()
			$('#status').hide()
		}
		else {
			$('#result').html("Nickname or password is bad, try again").show()
		}
	}
	else {
		$('#result').html("Connection error...").show()
	}
}

</script>
<style type="text/css">
<!--
.style3 {font-size: 10px}
.style6 {
	color: #95B81A;
	font-size: 16px;
}
-->
</style>
</head><body>
<div id="asslbar">
	<div id="connecting" class="asslStatus">Establishing an aSSL encrypted connection with the server.</div>
	<div id="connected" class="asslStatus">An aSSL encrypted connection has been established. Time elapsed: <span id="timeElapsed"></span> ms.</div>
	<div id="noconnect" class="asslStatus">Warning! Unable to establish an aSSL encrypted connection.</div>
</div>
<div id="bodyAround">

<div id="bodyBody">
<div id="over"><a href="../"><img src="pic/logo.gif" border="0"/></a><br />
</div>
<p>This simple example uses aSSL with a <strong><?=$a1024 ? 1024 : 512?>-bit</strong> RSA key. After the encrypted connection has been established, try logging in with: <strong>guru</strong>/<strong>jolly</strong> or <strong>admin</strong>/<strong>crazy</strong> or anything else you'd like :o)</p>



<div id="loginform"><div id="module"></div>
<div class="bloc" id="login" >

<form name="login" onsubmit="return false;">

	<label for="nickname">Nickname</label> <input type="text" id="nickname" name="nickname" onfocus="this.value='';$('#result').hide()" /><br />
	<label for="password">Password</label> <input type="password" id="password" name="password" onfocus="this.value='';$('#result').hide()" /><br />
<div id="result"></div>
	<input type="submit" class="button" value="login" onclick="loginGo()" />
</form>
</div>
</div>
<p><span class="style3">aSSL negotiate the exchange 128-bit key using <a href="http://www-cs-students.stanford.edu/~tjw/jsbn/" target="_blank">RSA algorithm</a>. After negotiation, the data are encrypted and decrypted using <a href="http://www.movable-type.co.uk/scripts/AES.html" target="_blank">AES algorithm</a>. </span></p>
<p class="myp firstp style6"><b>More examples</b></p>
<p class="myp"><strong><a href="./<?=$a1024 ? "" : "?size=1024"?>">A <?=$a1024 ? "faster" : "slower"?> aSSL example using a <?=$a1024 ? 512 : 1024?>-bit RSA key</a></strong></p>

<p class="firstp myp"><img src="/assl/pic/green.gif" alt="Green" width="333" height="2" /></p>
<p class="myp style3"><b>(c) 2006, 2007 <a href="http://www.sullof.com">Francesco Sullo</a> -  Rome, Italy </b></p>

</div></div>
</body>
</html>