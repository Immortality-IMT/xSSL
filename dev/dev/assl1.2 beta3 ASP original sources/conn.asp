<%@language="Javascript"%><%

// aSSL ASP example

// the key files:

%>
<!--#include file="mykey.asp" -->
<%

// the aSSL library

%>
<!--#include file="assl1.2forAsp/assl.asp" -->
<%

// To establish the aSSL connection it is sufficient the following line:

aSSL.response(Request.QueryString("size").Item == 1024 ? myKey1024 : myKey)

%>