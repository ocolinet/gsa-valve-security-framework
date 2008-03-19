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


package com.google.gsa.valve.modules.httpbasic;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.RequestType;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.io.IOException;
import java.util.Hashtable;

import java.util.Vector;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.log4j.Logger;


public class HTTPBasicAuthenticationProcess implements AuthenticationProcessImpl {
	
	// Number of auth cookies expected for this Authentication class, used as a check validation check
	private static final int NB_AUTH_COOKIES = 1;

	private static WebProcessor webProcessor = null;
        
	private ValveConfiguration valveConf = null;
	
	
	
	private Logger logger = null;
	
	public HTTPBasicAuthenticationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(HTTPBasicAuthenticationProcess.class);
		
	}
        
        //setIsNegotiate: delete it        
        /*
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
        */
    
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
                    this.valveConf = valveConf;                
        }
		
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
				
		Cookie[] cookies = null;

		
		//Authentication module that uses basic authentication 
		
		//The username and password for the source are assumed to be the ones captured during the 
		//SSO authentication. These are stored in creds and in this case the root parameters. creds is an array
		//of credentials for all external sources. The first element is 'root' which contains the credentials 
		//captured from the login page. In this example the same credentials are used to authenticate against
		//this HTTP Basic source
				
		UsernamePasswordCredentials credentials = null;
		
                	
		// Set counter
		int nbCookies = 0;
		
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		
		// Read cookies
		cookies = request.getCookies();

		// Debug
		logger.debug("HTTP Basic authentication start");

                Cookie basicAuthnCookie = null;

		//First check if gsa_basic_auth cookie exisits, if it does that assume still authenticated and return

		// Protection
		if (cookies != null) {
				
			// Check if the authentication process already happened by looking at the existing cookies	
			for (int i = 0; i < cookies.length; i++) {
	
				// Check cookie name
				if ((cookies[i].getName()).equals("gsa_basic_auth") ) {
					
					// Increment counter
					nbCookies++; 					
                                        
                                        basicAuthnCookie = cookies[i];
				}				
			}			
		}
		
		// Protection
	
		if (nbCookies == NB_AUTH_COOKIES) {
			
			logger.debug("Already Authenticated");
					
			// Set status code
			statusCode = HttpServletResponse.SC_OK;
                        
                        //CLAZARO: add the authN cookie
                        authCookies.add (basicAuthnCookie);

			// Return
			return statusCode;
			
		}
		
		
		//If the required cookie was not found need to authenticate.
		
		//First read the u/p the credentails store, in this case using the same as the root login
		logger.debug("HttpBasic: trying to get creds from repository ID: "+id);
		Credential httpBasicCred = null;
		try {
			httpBasicCred = creds.getCredential(id);
		} catch (NullPointerException npe) {
			logger.error("NPE while reading credentials of ID: " + id);
		}		
		if (httpBasicCred != null) {
			credentials = new UsernamePasswordCredentials(httpBasicCred.getUsername(), httpBasicCred.getPassword());
		} else {
                        logger.debug("HttpBasic: trying to get creds from repository \"root\"");
			httpBasicCred = creds.getCredential("root");
			if (httpBasicCred != null) {
				logger.info("Trying with root credentails");
				credentials = new UsernamePasswordCredentials(httpBasicCred.getUsername(), httpBasicCred.getPassword());
			}
		}
		logger.debug("Authenticating");
		Header[] headers = null;
		HttpMethodBase method = null;

		
                //Get Max connections
                int maxConnectionsPerHost = 30;                                
                int maxTotalConnections = 100;                                
                
                //Cookie Max Age
                int authMaxAge = -1;
                
                try { 
                    maxConnectionsPerHost = new Integer (valveConf.getMaxConnectionsPerHost()).intValue();                                
                    maxTotalConnections = (new Integer (valveConf.getMaxTotalConnections())).intValue();
                    authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());                
                } catch(NumberFormatException nfe) {
                    logger.error ("Configuration error: check the configuration file as the numbers set for any of the following parameters are not OK:");
                    logger.error ("  * maxConnectionsPerHost    * maxTotalConnections    * authMaxAge");
                }
		                 
                  
                // Protection
                if (webProcessor == null) {
		     // Instantiate Web processor
		     if ((maxConnectionsPerHost != -1)&&(maxTotalConnections!=-1)) {
		         webProcessor = new WebProcessor(maxConnectionsPerHost, maxTotalConnections);
		     } else {
		         webProcessor = new WebProcessor();
		     }
                }
		
		//
		// Launch the authentication process
		//

		// A fixed URL in the repository that all users have access to which can be used to authN a user
		// and capture the HTTP Authorization Header
		String authURL = valveConf.getRepository(id).getParameterValue("HTTPAuthPage");
		// Protection
		try {
		
			// Set HTTP headers
			headers = new Header[1];
			
			// Set User-Agent
			headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8) Gecko/20051111 Firefox/1.5");

			// Request page, testing if credentials are valid
			if (credentials != null){
				logger.debug("Username: " + credentials.getUserName());				
				logger.debug("URL: " + authURL);
			}
			
			// all users have access to http://sydney.lon.corp.google.com:82/testdocs/all.html, used to authenticate the user
			method = webProcessor.sendRequest(credentials, RequestType.GET_REQUEST, headers, null, authURL);
		    
	      
			//Read the auth header and store in the cookie, the authZ class will use this later
			headers = method.getRequestHeaders();
	        
	        Header authHeader = null;
	        authHeader = method.getRequestHeader("Authorization");
	        
	        // Cache status code
	        if (method != null) statusCode = method.getStatusCode();
	        
	        if (statusCode == HttpServletResponse.SC_OK) {
	        	//Authentication worked, so create the auth cookie to indicate it has worked
	        	Cookie extAuthCookie = null;
	        	extAuthCookie = new Cookie("gsa_basic_auth","");
	        	
	        	if (authHeader != null) {
                        
	        		extAuthCookie.setValue(getBasicAuthNChain(authHeader.getValue()));
	        		
	        	}
	        	String authCookieDomain = null;
                        String authCookiePath = null;
				
                        // Cache cookie properties
                        authCookieDomain = valveConf.getAuthCookieDomain();
                        authCookiePath = valveConf.getAuthCookiePath();
				
                        // Set extra cookie parameters
                        extAuthCookie.setDomain(authCookieDomain);
                        extAuthCookie.setPath(authCookiePath);
                        extAuthCookie.setMaxAge(authMaxAge);
	        	
                        // Log info
                        if (logger.isDebugEnabled()) logger.debug("Adding gsa_basic_auth cookie: " + extAuthCookie.getName() + ":" + extAuthCookie.getValue() 
                                        + ":" + extAuthCookie.getPath() + ":" + extAuthCookie.getDomain() + ":" + extAuthCookie.getSecure());
				
                        //sendCookies support
                        boolean isSessionEnabled = new Boolean (valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
                        boolean sendCookies = false;
                        if (isSessionEnabled) {
                            sendCookies = new Boolean (valveConf.getSessionConfig().getSendCookies()).booleanValue();
                        }
                        if ((!isSessionEnabled)||((isSessionEnabled)&&(sendCookies))) {
                            logger.debug("Adding cookie to response");
                            response.addCookie(extAuthCookie);
                        }
                                
                        //Add cookies to the Cookie array to support sessions
                        authCookies.add (extAuthCookie);
                        logger.debug("Cookie added to the array");
				
	        }

	        // Clear webProcessor cookies
	        webProcessor.clearCookies();
	        
		} catch(Exception e) {

			// Log error
			logger.error("HTTP Basic authentication failure: " + e.getMessage(),e);

			// Garbagge collect
			method = null;
			
			// Update status code
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;
			
		}

		// End of the authentication process
		logger.debug("HTTP Basic Authentication completed (" + statusCode + ")");
      
		
		
		// Return status code
		return statusCode;
		
	}
        
        public String getBasicAuthNChain (String basic) {
            String authNChain = "";
            String basicMsg = "Basic ";
            
            logger.debug("Basic is: "+basic);
            if ((!basic.equals(null))&&(!basic.equals(""))) {
                //treat basic chain and just get the chain
                int index = basicMsg.length();
                authNChain = basic.substring(index);
                logger.debug ("New Basic chain: "+authNChain+"; with index: "+index);
            }
            
            return authNChain;
        }
		
}
