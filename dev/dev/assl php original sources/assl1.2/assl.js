
if (1) {
	var asslAllScripts = document.getElementsByTagName("script")
	for (var j=0;j<asslAllScripts.length;j++) {
		var src = asslAllScripts[j].src
		if (src.indexOf("assl.js") != -1) {
			var asslFolder = src.split("assl.js")[0]
			// this is necessary because inserting via DOM fails with some browsers
			document.write('<script type="text/javascript" src="'+asslFolder+'lib/jsbn/jsbn.js"></script>'+
			'<script type="text/javascript" src="'+asslFolder+'lib/jsbn/prng4.js"></script>'+
			'<script type="text/javascript" src="'+asslFolder+'lib/jsbn/rng.js"></script>'+
			'<script type="text/javascript" src="'+asslFolder+'lib/jsbn/rsa.js"></script>'+
			'<script type="text/javascript" src="'+asslFolder+'lib/aes.js"></script>'+
			'<script type="text/javascript" src="'+asslFolder+'assl_.js"></script>')
		}
	}
}