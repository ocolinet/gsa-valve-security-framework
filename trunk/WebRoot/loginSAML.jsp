<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<%@ page contentType="text/html;charset=windows-1252" %>
<%@ page import="com.google.gsa.authn.*" %>
<%@ page import="com.google.gsa.valve.saml.SAMLArtifactProcessor"%>
<%@ page import="com.google.gsa.valve.saml.authn.SAMLAuthN"%>
<%@ page import="com.google.gsa.valve.utils.ValveUtils"%>
<%@ page import="com.google.gsa.valve.configuration.ValveConfigurationInstance"%>
<%@ page import="com.google.gsa.valve.configuration.ValveConfiguration"%>
<%@ page import="java.util.Vector"%>
<%@ page import="java.util.Enumeration"%>
<%@ page import="javax.servlet.http.Cookie"%>
<%@ page import="javax.servlet.http.HttpServletRequest"%>
<%@ page import="javax.servlet.http.HttpServletResponse"%>
<%@ page import="org.apache.commons.httpclient.HttpException"%>
<%@ page import="java.io.IOException"%>
<%@ page import="org.apache.log4j.Logger"%>

<!--  DESCRIPTION
      loginSAML.jsp is the default login page for SAML
      You can customize it and change its name as long as you update it in config files
-->


<%
//Logger
Logger logger = Logger.getLogger("com.google.gsa");

logger.debug("loginSAML.jsp starting");

//Config
String gsaValveConfigPath = null;

//SAML Params
String relayState = null;
String samlRequest = null;

//HTTP Params
int httpError = HttpServletResponse.SC_UNAUTHORIZED;
Vector<Cookie> authCookies = new Vector<Cookie>();

//Get Config
javax.naming.Context ctx = new javax.naming.InitialContext();
javax.naming.Context env = (javax.naming.Context)ctx.lookup("java:comp/env");

//Get gsaValveConfigPath
gsaValveConfigPath = (String) env.lookup("gsaValveConfigPath");

logger.debug("gsaValveConfigPath is: "+gsaValveConfigPath);

//request.setAttribute("gsaValveConfigPath", gsaValveConfigPath);

//Get the Valve Configuration instance
ValveConfiguration valveConf = ValveConfigurationInstance.getValveConfig (gsaValveConfigPath);

if (valveConf == null) {
    logger.error("Valve Configuration does not found");
    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Configuration Error: please contact your administrator");
    return;
} 

logger.debug("Setting GSA request");

//set GSA Request cookie
ValveUtils.setRequestGSA (request, response, valveConf.getSearchHosts(), valveConf.getAuthCookieDomain(), valveConf.getAuthCookiePath());

logger.debug("Processing HTML");

%>

<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=windows-1252"/>
    <title>Login - login form for SAML authentication</title>
  </head>
  <body>

<%
    
    //Get SAML Params
    relayState = request.getParameter("RelayState");
    samlRequest = request.getParameter("SAMLRequest");
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
    }

%>
    <!-- Customize Look and Feel -->
        
    <center>
		<form method="post" action="/valve/Authenticate" name="login_form">
			<table width="300" border="0" align="center" cellpadding="2" cellspacing="1">
				
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
							<tr>                                                                
								<td>&nbsp;
                                                                    <!-- Hidden params -->   
                                                                    <input type="hidden" name="SAMLRequest" value="<%=samlRequest%>"/>
                                                                    <input type="hidden" name="RelayState" value="<%=relayState%>"/>
                                                                    <input type="hidden" name="gsaValveConfigPath" value="<%=gsaValveConfigPath%>"/>                                                                    
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