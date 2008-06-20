<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<%@ page contentType="text/html;charset=windows-1252" %>
<%@ page import="org.apache.log4j.Logger"%>
<%@ page import="com.google.gsa.valve.configuration.ValveConfigurationInstance"%>
<%@ page import="com.google.gsa.valve.configuration.ValveConfiguration"%>

	<!-- DESCRIPTION
	     loginkrbSAML.jsp is the default login page when using SAML approach
	     with Kerberos and you choose to have double authentication (username/password thru a login form)
	     It's similar to loginkrb.jsp but for SAML-based scenarios
	     You can customize it and change its name as long as you update it in config files
	-->


<%
    //Logger
    Logger logger = Logger.getLogger("com.google.gsa");

    logger.debug("loginKrbSAML.jsp starting");
    
    //Config
    String gsaValveConfigPath = null;        

    //SAML Params
    String relayState = null;
    String samlRequest = null;
    
    //Get Config
    javax.naming.Context ctx = new javax.naming.InitialContext();
    javax.naming.Context env = (javax.naming.Context)ctx.lookup("java:comp/env");

    //Get gsaValveConfigPath
    gsaValveConfigPath = (String) env.lookup("gsaValveConfigPath");

    logger.debug("gsaValveConfigPath is: "+gsaValveConfigPath);    

    //Get the Valve Configuration instance
    ValveConfiguration valveConf = ValveConfigurationInstance.getValveConfig (gsaValveConfigPath);

    if (valveConf == null) {
        logger.error("Valve Configuration does not found");
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Configuration Error: please contact your administrator");
        return;
    }
    
    boolean isSAML = new Boolean (valveConf.getSAMLConfig().isSAML()).booleanValue();

    
    if (isSAML) {
        //Get SAML Params        
        samlRequest = request.getParameter("SAMLRequest");
        relayState = request.getParameter("RelayState");
        boolean requestError = false;
        boolean authnError = true;

        //Protection
        if ((relayState==null)||(relayState.equals(""))) {            
            requestError = true;
        } else {
            if ((samlRequest==null)||(samlRequest.equals(""))) {
                requestError = true;
            }   
        }

        if (requestError) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid request");
            return;
        } else {
            logger.debug("RelayState is: "+relayState);
            logger.debug("samlRequest is: "+samlRequest);
        }
    }
%>

<html>
	<head>
		<title>Valve Toolkit Samples Login Page</title>
	</head>
	<body>
		<center>
		<form method="post" action="/valve/kerberos" name="login_form">
			<table width="300" border="0" align="center" cellpadding="2" cellspacing="1">
				
				<tr>
					<td>
						<table width="100%" border="0" cellspacing="1" cellpadding="1">
							<tr>
								<td><div align="right"><strong><font color="#333333" size="-1" face="Arial, Helvetica, sans-serif">Username</font></strong></div></td>
								<td><input type="text" name="UserIDKrb" size="30" maxlength="30"></td>
							</tr>
							<tr>
								<td><div align="right"><strong><font color="#333333" size="-1" face="Arial, Helvetica, sans-serif">Password</font></strong></div></td>
								<td><input type="password" name="PasswordKrb" size="30" maxlength="30"></td>
							</tr>
							<tr>
								<td>
                                                                    <!-- Hidden params -->   
                                                                    <input type="hidden" name="SAMLRequest" value="<%=samlRequest%>"/>
                                                                    <input type="hidden" name="RelayState" value="<%=relayState%>"/>
                                                                    <!-- End hidden params -->
                                                                </td>
								<td><input type="submit" name="Submit" style="background-color: transparent;" value="Enter"></td>
							</tr>
						</table>
					</td>
				</tr>
				
			</table>
		</form>
		</center>
	</body>
</html>