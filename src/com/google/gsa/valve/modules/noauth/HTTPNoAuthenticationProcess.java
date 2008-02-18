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


package com.google.gsa.valve.modules.noauth;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.io.IOException;
import java.util.Hashtable;

import java.util.Vector;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.log4j.Logger;


public class HTTPNoAuthenticationProcess implements AuthenticationProcessImpl {
	
	// Number of auth cookies expected for this Authentication class, used as a check validation check
	private static final int NB_AUTH_COOKIES = 1;
	private static Hashtable<String, WebProcessor> webProcessors = new Hashtable<String, WebProcessor>();
	private ValveConfiguration valveConf = null;
	
	private Logger logger = null;
	
	public HTTPNoAuthenticationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(HTTPNoAuthenticationProcess.class);
		
	}
	
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
        
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
                
                Cookie noAuthNCookie = null;
                
		// Debug
		logger.debug("HTTP No authentication start");
                

		//First check if gsa_basic_auth cookie exisits, if it does that assume still authenticated and return

		// Protection
		if (cookies != null) {
				
			// Check if the authentication process already happened by looking at the existing cookies	
			for (int i = 0; i < cookies.length; i++) {
	
				// Check cookie name
				if ((cookies[i].getName()).equals("gsa_basic_noauth") ) {
					
                                        noAuthNCookie = cookies[i];
                                        
					// Increment counter
					nbCookies++; 					
				}				
			}			
		}
		
		// Protection	
		if (nbCookies == NB_AUTH_COOKIES) {
			
			logger.debug("Already Authenticated");
			
                        //add cookie
                        authCookies.add (noAuthNCookie);
                        		
			// Set status code
			statusCode = HttpServletResponse.SC_OK;

			// Return
			return statusCode;
			
		}
		
		
		//If the required cookie was not found need to authenticate.
		
		
		//
		// Launch the authentication process
		//
		
		// Protection
		try {
		
			Cookie extAuthCookie = null;
                        extAuthCookie = new Cookie("gsa_basic_noauth","");
        	
        	
                        extAuthCookie.setValue("true");
        		
        	
                        String authCookieDomain = null;
			String authCookiePath = null;
			
			// Cache cookie properties
			authCookieDomain = (request.getAttribute("authCookieDomain")).toString();
			authCookiePath = (request.getAttribute("authCookiePath")).toString();
			
			// Set extra cookie parameters
			extAuthCookie.setDomain(authCookieDomain);
			extAuthCookie.setPath(authCookiePath);
        	
			// Log info
			if (logger.isDebugEnabled()) logger.debug("Adding gsa_basic_noauth cookie: " + extAuthCookie.getName() + ":" + extAuthCookie.getValue() 
					+ ":" + extAuthCookie.getPath() + ":" + extAuthCookie.getDomain() + ":" + extAuthCookie.getSecure());
			
                         //add sendCookies support
                         boolean isSessionEnabled = new Boolean (valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
                         boolean sendCookies = false;
                         if (isSessionEnabled) {
                            sendCookies = new Boolean (valveConf.getSessionConfig().getSendCookies()).booleanValue();
                         }
                         if ((!isSessionEnabled)||((isSessionEnabled)&&(sendCookies))) {
                             response.addCookie(extAuthCookie);
                         }                       
                        
                        //add cookie to the array
                        authCookies.add (extAuthCookie);
			
			statusCode = HttpServletResponse.SC_OK;
	        
		} catch(Exception e) {

			// Log error
			logger.error("HTTP Basic authentication failure: " + e.getMessage(),e);			
			
			// Reset Web processor
			logger.debug("in catch exception BEFORE webprocessors PUT");
			webProcessors.put(Thread.currentThread().getName(), null);
			logger.debug("in catch exception AFTER webprocessors PUT");
			// Update status code
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;
			
		}

		// End of the authentication process
		logger.debug("HTTP No Authentication completed (" + statusCode + ")");
      
		
		
		// Return status code
		return statusCode;
		
	}
	
}
