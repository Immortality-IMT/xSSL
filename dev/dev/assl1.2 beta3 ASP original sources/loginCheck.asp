<%@language="Javascript"%><%

// aSSL ASP example

%><!--#include file="assl1.2forAsp/assl2.asp" -->
<%

// Decode the encrypted data passed by aSSL:
var results = aSSL.decrypt(Request.Form("data").Item)

// aSSL.querystr produce an hash from a querystring format:
var np = aSSL.querystr(results)

// We check if the nickname and the password are correct:
var pass = {'guru':'jolly','admin':'crazy'}
var ret = pass[np.nickname] && pass[np.nickname] == np.password ? 1 : 0

// This writes the results:
aSSL.write(ret)
/* This method is a quick replace of:

Response.Clear()
Response.Write(ret)
Response.End()

*/

%>