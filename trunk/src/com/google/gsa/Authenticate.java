 /**
  * Copyright (C) 2008 Google - Enterprise EMEA SE
  *
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy of
  * the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  * License for the specific language governing permissions and limitations under
  * the License.
  */

package com.google.gsa;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import com.google.gsa.sessions.SessionTimer;

import com.google.gsa.sessions.Sessions;
import com.google.gsa.sessions.UserIDEncoder;
import com.google.gsa.sessions.UserSession;

import com.google.gsa.valve.configuration.ValveConfiguration;

import com.google.gsa.valve.configuration.ValveConfigurationDigester;

import com.google.gsa.valve.configuration.ValveConfigurationException;
import com.google.gsa.valve.errormgmt.ErrorManagement;

import java.util.Vector;

import org.apache.log4j.Logger;

import javax.security.auth.Subject;


public class Authenticate extends HttpServlet {

	private static final long serialVersionUID = -8944353938289271212L;

	private static Logger logger = null;

	private ValveConfiguration valveConf;
            
        //Vars for Krb support
        private boolean isKerberos = false;
        private String userAgent = null;  
             
        //Session Management Var
        private boolean isSessionEnabled = false;
        long maxSessionAge;
        long sessionTimeout;
        long sessionCleanup;
        SessionTimer sessionTimer;

        public static final long SEC_IN_MIN = 60;        
        
        private static final String KRB5_ID = "krb5";
             

        //Cookie vars        
        Cookie gsaAuthCookie;
        String authCookieDomain = null;
        String authCookiePath = null;
        String authCookieName = null;
        int authMaxAge = 300;
        String refererCookieName = null;
        
        //AuthN classes vars
        String authenticationProcessClsName = null;
        AuthenticationProcessImpl authenticationProcessCls = null;
        
        ErrorManagement errorMngmt = null;
        
        //CLAZARO: cookie array
        Vector<Cookie> authCookies = new Vector<Cookie>();
	
	static {

		// Instantiate logger
		logger = Logger.getLogger(Authenticate.class);

	}

	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {        
		
                // Read XML config file pointer
                String gsaValveConfigPath = (request.getAttribute("gsaValveConfigPath")).toString();
                                
                logger.debug("Config file: "+gsaValveConfigPath);
                ValveConfigurationDigester valveConfDigester = new ValveConfigurationDigester();
                this.valveConf = valveConfDigester.run(gsaValveConfigPath);                            

                //credentials                
                Credentials creds = new Credentials();
                String username = null;                
                
                //reset authCookies vector
                authCookies.clear();
		
		logger.debug("Authenticate servlet Start");	
                
                //Read config vars from file
                boolean isConfigOK = setValveParams (request);
                logger.debug("Checking if vars were read properly");
                //protect
                if (!isConfigOK) {                    
                    logger.debug("Kerberos Negotiation cannot be used during Authentication. Please review documentation and use Kerberos servlet instead");
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Bad configuration. Contact application administrator");
                    return;
                }
                
		Cookie cookies[] = null;
		Cookie gsaRefererCookie = null;                                
		
		// Retrieve cookies
		cookies = request.getCookies();
		logger.debug(cookies.length + " cookies found before authenticating");
		// Protection
		if (cookies != null) {
			
			// Look for the referer cookie
			for (int i = 0; i < cookies.length; i++) {
				logger.trace(cookies[i].getName() + ":" + cookies[i].getValue());
				// Look for the referer cookie
				if ((cookies[i].getName()).equals(refererCookieName)) {
					
					// Cache cookie
					gsaRefererCookie = cookies[i];
					
					// Exit
					break;
					
				}
				
			}

		}

		// Protection
		if (gsaRefererCookie == null) {
			
			// Raise error
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "The GSA authentication servlet couldn't read the referer cookie");
			
			// Log error
			logger.error("The GSA authentication servlet couldn't read the referer cookie, pls. check the cookie domain value");
			
			// Return
			return;
			
		}
                
                //Setting root credentials coming from the login form
                settingRootCredentials (creds, username, request);

		// Instantiate the authentication process class
		try {
			
			// Instantiate the authorization process class
			authenticationProcessCls = (AuthenticationProcessImpl) Class.forName(authenticationProcessClsName).newInstance();

			authenticationProcessCls.setValveConfiguration(valveConf);
                        		
			
		} catch (InstantiationException e) {

			// Log error
			logger.error("InstantiationException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");

			// Return
			return;
			
		} catch (IllegalAccessException e) {
			
			// Log error
			logger.error("IllegalAccessException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");

			// Return
			return;
			
		} catch (ClassNotFoundException e) {

			// Log error
			logger.error("ClassNotFoundException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");
			logger.error("Cannot find class: " + authenticationProcessClsName);
			
			// Return
			return;
			
		}
		
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                
                //creation time var
                long creationTime = System.currentTimeMillis();
		
		gsaAuthCookie = null;
                
                //Instantiate authentication cookie with creation time
                //SET a value for the USERID
                gsaAuthCookie = new Cookie(authCookieName, UserIDEncoder.getID(username, creationTime));
		
		// Set cookie domain
		gsaAuthCookie.setDomain(authCookieDomain);
		
		// Set cookie path
		gsaAuthCookie.setPath(authCookiePath);
		
		// Set expiration time
		gsaAuthCookie.setMaxAge(authMaxAge);
		
		try {

			// Execute the authentication process in here			
                         statusCode = authenticationProcessCls.authenticate(request, response, authCookies, gsaRefererCookie.getValue(), creds, null);

		} catch(Exception e) {

			// Debug
			logger.error("Authentication process raised exception: " + e.getMessage(),e);
			
		} 

		// Protection                
		if (statusCode == HttpServletResponse.SC_UNAUTHORIZED) {			                                                                        
                        
                        //Send personalized error message (if any)
                        try {
                            //create the instance if it does not exist
                            if (errorMngmt == null) {                
                                errorMngmt = new ErrorManagement (valveConf.getErrorLocation());                
                            }
                            
                            //protection
                            if (errorMngmt != null) {
                                errorMngmt.showHTMLError(response, errorMngmt.processError(statusCode));
                            }
                        
                        } catch (ValveConfigurationException e) {
                            logger.error("Configuration error: " + e);
                        }
			
                        // Raise error
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication process failed!");

			// Debug
			if (logger.isDebugEnabled()) logger.debug("Authentication process failed");
			
			// Return
			return;
			
		}
                
                //Session support
                if (isSessionEnabled) {
                    logger.error("Full session is enabled");
                    UserSession userSession = new UserSession ();
                    userSession.setUserName(username);
                    userSession.setSessionCreationTime(creationTime);
                    userSession.setSessionLastAccessTime(creationTime);
                    
                    //Manage Cookies
                    //add Auth Cookie to the authCookies vector
                    authCookies.add(gsaAuthCookie);
                    //add cookies to session
                    userSession.setCookies(setCookieArray(authCookies));
                    
                    if (isKerberos) {
                        
                        //get credentials
                        boolean nonValidCred = getKrbCredentials (creds, userSession);                        
                        
                        if (nonValidCred) {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Credentials not valid");
                                              
                            // Log error
                            logger.error ("Kerberos Subject has not been created properly");
                                              
                            // Return
                            return;
                        }
                        
                    }
                    
                    //Store Session in the Session Map
                    Sessions sessions = Sessions.getInstance();     
                    //Setting session times
                    sessions.setMaxSessionAgeMinutes(maxSessionAge);
                    sessions.setSessionTimeoutMinutes(sessionTimeout);
                    sessions.addSession(gsaAuthCookie.getValue(), userSession);
                                      
                    logger.debug("User Session created");
                } else {
                    if (isKerberos) {
                        logger.error("Full session is not enabled but Kerberos does");
                        UserSession userSession = new UserSession ();                         
                        userSession.setUserName(username);
                        userSession.setSessionCreationTime(creationTime);
                        userSession.setSessionLastAccessTime(creationTime);
                        
                        //get credentials
                        boolean nonValidCred = getKrbCredentials (creds, userSession);                        
                        
                        if (nonValidCred) {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Credentials not valid");
                                              
                            // Log error
                            logger.error ("Kerberos Subject has not been created properly");
                                              
                            // Return
                            return;
                        }
                            

                        //Store Session in the Session Map
                        Sessions sessions = Sessions.getInstance();
                        sessions.setMaxSessionAgeMinutes(maxSessionAge);
                        sessions.setSessionTimeoutMinutes(-1);
                        sessions.addSession(gsaAuthCookie.getValue(), userSession);
                                          
                        logger.debug("User Session created: "+gsaAuthCookie.getValue());
                                          
                    }
                }

		// Add internal authentication cookie
		response.addCookie(gsaAuthCookie);

		// Debug
		if (logger.isDebugEnabled()) logger.debug("Authentication process successful");

		// Debug
		if (logger.isDebugEnabled()) logger.debug("Redirecting user to: " + gsaRefererCookie.getValue());

		// Redirect
		response.sendRedirect(gsaRefererCookie.getValue());
		
	}

	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
             
            //Add support for Kerberos    
	    if ((request.getAttribute("isKerberos")).toString().equals("true")) {
	                         
                doPost (request, response);   
	                         
            } else {
	                     
                // Raise error
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "The GSA Authenticate servlet does not accept GET requests!");
            }

	}
        
        public Cookie[] setCookieArray (Vector<Cookie> authCookies) {
            Cookie[] arrayCookie = null;
            if (!authCookies.isEmpty()) {
                logger.debug("Cookie array is not null. Contains "+authCookies.size()+" entries");
                arrayCookie = new Cookie[authCookies.size()];
                for (int i=0; i < authCookies.size(); i++) {
                    logger.debug ("Cookie ["+i+"]: "+authCookies.elementAt(i).getName()+":"+authCookies.elementAt(i).getValue());
                    arrayCookie[i] = authCookies.elementAt(i);
                }
            }
            return arrayCookie;
        }
        
        //Get Krb credentials
        public boolean getKrbCredentials (Credentials creds, UserSession userSession ) {
            boolean nonValidCred = true;
            try {
                if (creds.getCredential(KRB5_ID)!=null) {
                    Subject krbSubject = creds.getCredential(KRB5_ID).getSubject();
                    if (krbSubject != null) {
                        logger.error("Kerberos Subject exists");
                                          
                        userSession.setKerberosCredentials(krbSubject);
                        
                        nonValidCred = false;
                    }
                    
                }
            }
            catch (Exception e) {
               logger.error ("Error getting Krb credentials: "+e.getMessage(),e); 
               nonValidCred = true;
            }
            return nonValidCred;
        }

        
        public boolean setValveParams (HttpServletRequest request) {

             boolean isConfigOK = true;
             // Read HTTP request attributes
             logger.debug("Reading configuration vars");
             try {

                 authCookieName = valveConf.getAuthCookieName();
                 logger.debug("authCookieName: "+authCookieName);
                 refererCookieName = (request.getAttribute("refererCookie")).toString();
                 logger.debug("refererCookieName: "+refererCookieName);
                 
                 authCookieDomain = valveConf.getAuthCookieDomain();
                 authCookiePath = valveConf.getAuthCookiePath();                 
                 try { authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge()); } catch(NumberFormatException nfe) {}
                 authenticationProcessClsName = valveConf.getAuthenticationProcessImpl();                                                                                                   
                                   
                 //Is it Kerberos?
                 if (valveConf.getKrbConfig().isKerberos().equals("true")) {
                     isKerberos = true;
                     maxSessionAge = (new Long (valveConf.getSessionConfig().getMaxSessionAge())).longValue();
                     //Is it Negotiate?
                     if (valveConf.getKrbConfig().isNegotiate().equals("true")) {                        
                         isConfigOK = false;
                     } 
                 } else {
                     isKerberos = false;
                 }
                                   
                 //Set Session Vars
                 if (valveConf.getSessionConfig().isSessionEnabled().equals("true")) {
                     isSessionEnabled = true;
                     //Set Kerberos and Session vars
                     maxSessionAge = (new Long (valveConf.getSessionConfig().getMaxSessionAge())).longValue(); 
                     sessionTimeout = (new Long (valveConf.getSessionConfig().getSessionTimeout())).longValue(); 
                     sessionCleanup = (new Long (valveConf.getSessionConfig().getSessionCleanup())).longValue();
                 } else {
                     isSessionEnabled = false;
                 }             

                if ((isSessionEnabled)||(isKerberos)) {
                    logger.debug ("Getting sessionTimer instance");
                    sessionTimer = SessionTimer.getInstance(isSessionEnabled, isKerberos, sessionCleanup);
                    sessionTimer.setTimer();
                }
             }
             catch (NullPointerException e) {
                logger.error("Null pointer exception when setting config vars"+ e.getMessage(),e);
             }
             catch (Exception e) {
                logger.error("Exception when setting config vars"+ e.getMessage(),e);
             }
             
             return isConfigOK;
        }
        
        public void settingRootCredentials (Credentials creds, String username, HttpServletRequest request) {

             // Read HTTP request parameters
             username = request.getParameter("UserID");
             logger.debug("Adding credentials for root to credentials store");
             Credential rootCred = new Credential("root");
             rootCred.setUsername(username);
             rootCred.setPassword(request.getParameter("Password"));
             creds.add(rootCred);

        }

}
