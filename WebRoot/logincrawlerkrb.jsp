<html>
  <head>
    <title>Login - Kerberos crawling form</title>
  </head>
  <body>
  
   <!--  DESCRIPTION
   	 logincrawlerkrb.jsp is the default login page for crawler (GSA) when 
         using Form Based AuthN approach and you would like the crawling process
         to be driven by the GSA, instead of injecting the content 
	 You can customize it and change its name as long as you update it in config files
   -->		
   
   <form method="post" action="/valve/kerberos" name="login_form">					
     <table width="300" border="0" align="center" cellpadding="2" cellspacing="1">
      <tr>
        <td align="center"><h3>Kerberos Credentials</h3></td>
      </tr>
      <tr>
        <td>
            <table width="100%" border="0" cellspacing="1" cellpadding="1">
               <tr>
	         <td><div align="right"><strong><font color="#333333" size="-1" face="Arial, Helvetica, sans-serif">Krb Username</font></strong></div></td>
                 <td><input type="text" name="UserIDKrb" size="30" maxlength="30"></td>
	      </tr>
	      <tr>
	        <td><div align="right"><strong><font color="#333333" size="-1" face="Arial, Helvetica, sans-serif">Krb Password</font></strong></div></td>
		<td><input type="password" name="PasswordKrb" size="30" maxlength="30"></td>
	      </tr>
	    </table>
        </td>
      </tr>
      <tr>
        <td align="center"><h3>Non Kerberos Credentials (optional)</h3></td>
      </tr>
      <tr>
        <td>
            <table width="100%" border="0" cellspacing="1" cellpadding="1">
               <tr>
	         <td><div align="right"><strong><font color="#333333" size="-1" face="Arial, Helvetica, sans-serif">Username</font></strong></div></td>
                 <td><input type="text" name="UserID" size="30" maxlength="30"></td>
	      </tr>
	      <tr>
	        <td><div align="right"><strong><font color="#333333" size="-1" face="Arial, Helvetica, sans-serif">Password</font></strong></div></td>
		<td><input type="password" name="Password" size="30" maxlength="30"></td>
	      </tr>
	    </table>
        </td>
      </tr>
      <tr>
        <td align="center"><input type="submit" name="Submit" style="background-color: transparent;" value="Enter"></td>
      </tr>
    </table>
  </body>
</html>