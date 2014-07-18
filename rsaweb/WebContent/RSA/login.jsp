<%@ page language="java" pageEncoding="UTF-8" contentType="text/html; charset=UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html:html lang="true">
<head>
	<title>login</title>

	<script type="text/javascript" src="js/RSA.js"></script>
	<script type="text/javascript" src="js/BigInt.js"></script>
	<script type="text/javascript" src="js/Barrett.js"></script>
	
	<script type="text/javascript">
function rsalogin(){
	var thisPwd = document.getElementById("password").value;
	bodyRSA();
	var result = encryptedString(key, encodeURIComponent(thisPwd));
	//alert(encodeURIComponent(thisPwd)+"\r\n"+result);
	loginForm.action="loginCHK.jsp?result="+result;
	loginForm.submit();
}
var key;
function bodyRSA(){
	setMaxDigits(130);
 // key = new RSAKeyPair("10001","","8246a46f44fc4d961e139fd70f4787d272d374532f4d2d9b7cbaad6a15a8c1301319aa6b3f30413b859351c71938aec516fa7147b69168b195e81df46b6bed7950cf3a1c719d42175f73d7c97a85d7d20a9e83688b92f05b3059bb2ff75cd7190a042cd2db97ebc2ab4da366f2a7085556ed613b5a39c9fdd2bb2595d1dc23b5"); 
  	key = new RSAKeyPair("10001","","b7cdb92a9a1924bb2c920561bdec9d5cdf1c549468bd45a0e814588fa871b66821e2fa174395abe884bd1103b41691f39b2f92c9bf4827daf760ffd2ae751b470520552f3472a05e8a4e0571557edd56f0b48bbed92742b47e5618a6fb234cea3be822d641e1cfe339b2da6593d29bd70807e5fdd91795322cfdfc314f87f12d"); 
}
</script>
</head>

<body>
	<form method="post" name="loginForm" target=_blank>
		<table border="0">
			<tr>
				<td>
					Password:
				</td>
				<td>
					<input type='text' name="password" id=password style='width:400px' value="my passwd"/>
				</td>
			</tr>
			<tr>
				<td colspan="2" align="center">
					<input type="button" value="SUBMIT" onclick="rsalogin();" />
				</td>
			</tr>
		</table>
	</form>
</body>
</html:html>
