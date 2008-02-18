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

package com.google.gsa.valve.modules.sample;

import java.io.IOException;
import java.util.Hashtable;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.log4j.Logger;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.RequestType;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.util.Vector;

public class NotesSampleAuthN   implements AuthenticationProcessImpl {

	private Logger logger = null;
	//Number of auth cookies expected for this Authentication class, used as a check validation check
	private static final int NB_AUTH_COOKIES = 1;
	private ValveConfiguration valveConf = null;

	private static Hashtable<String, WebProcessor> webProcessors = new Hashtable<String, WebProcessor>();

	private String testUrl = "http://zpag48.corp.google.com:8880/help/help7_admin.nsf/Main?OpenFrameSet";
	
	public NotesSampleAuthN() {
		//Instantiate logger
		logger = Logger.getLogger(NotesSampleAuthN.class);
		
	}
        
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }
		
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
		
		WebProcessor webProcessor = null;
		Cookie[] cookies = null;

		
		//Authentication module that uses basic authentication 
		
		//The username and password for the source sydney are assumed to be the ones captured during the 
		//SSO authentication. These are currently in clear text in gsa_sso_cookie
				
		UsernamePasswordCredentials credentials = null;
                
		// Set counter
		int nbCookies = 0;
		
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		
		// Read cookies
		cookies = request.getCookies();
                
                Cookie notesCookie = null;

		// Debug
		logger.debug("Sample Notes (Domino HTTP Basic) authentication start");
		

		//First check if gsa_notes_auth cookie exisits, if it does that assume still authenticated and return

		// Protection
		if (cookies != null) {
				
			// Check if the authentication process already happened by looking at the existing cookies	
			for (int i = 0; i < cookies.length; i++) {
	
				// Check cookie name
				if ((cookies[i].getName()).equals("gsa_notes_auth") ) {
					
                                        notesCookie = cookies[i];
                                        
					// Increment counter
					nbCookies++; 					
				}				
			}			
		}
		
		// Protection
	
		if (nbCookies == NB_AUTH_COOKIES) {
			
			logger.debug("Already Authenticated");
			
                        //add cookie
                        authCookies.add(notesCookie);
                        		
			// Set status code
			statusCode = HttpServletResponse.SC_OK;

			// Return
			return statusCode;
			
		}
		
		
		//If the required cookie was not found need to authenticate.
		
		//Hard coded credentials, but could be read from some where else. e.g gsaSSOCookie or external data respostiroy
		credentials = new UsernamePasswordCredentials("googlese", "googlese");
		
		logger.debug("Authenticating");
		Header[] headers = null;
		HttpMethodBase method = null;
	
		// Retrieve Web processor
		webProcessor = getWebProcessorInstance(logger);
		
		//
		// Launch the authentication process
		//
		try {
		
			// Set HTTP headers
			headers = new Header[1];
			
			// Set User-Agent
			headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8) Gecko/20051111 Firefox/1.5");

			// Request page, testing if credentials are valid
			//Should use a URL for this test that all valid user's have access to
			//TODO nbeed protection on this as crednetials could be null
			if (credentials != null){
				logger.debug("Username: " + credentials.getUserName());
			}
			
			// testing using a URL that all users have access to, this will validate their credentials
			method = webProcessor.sendRequest(credentials, RequestType.GET_REQUEST, headers, null, testUrl);
			logger.debug("send request complete");
         
	        
	      
			//Read the auth header and store in the cookie, the authZ class will use this later
			headers = method.getRequestHeaders();
	        
	        Header authHeader = null;
	        authHeader = method.getRequestHeader("Authorization");
	        
	        
	        
	        // Cache status code
	        if (method != null) statusCode = method.getStatusCode();
	        
	        if (statusCode == HttpServletResponse.SC_OK) {
	        	//Authentication worked, so create the auth cookie to indicate it has worked
	        	Cookie extAuthCookie = null;
	        	extAuthCookie = new Cookie("gsa_notes_auth","");
	        	
	        	if (authHeader != null) {
	        		extAuthCookie.setValue(authHeader.getValue());
	        		
	        	}
	        	String authCookieDomain = null;
				String authCookiePath = null;
				
				// Cache cookie properties
				authCookieDomain = (request.getAttribute("authCookieDomain")).toString();
				authCookiePath = (request.getAttribute("authCookiePath")).toString();
				
				// Set extra cookie parameters
				extAuthCookie.setDomain(authCookieDomain);
				extAuthCookie.setPath(authCookiePath);
	        	
				// Log info
				if (logger.isDebugEnabled()) logger.debug("Adding gsa_notes_auth cookie: " + extAuthCookie.getName() + ":" + extAuthCookie.getValue() 
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
								
	        }

	        // Clear webProcessor cookies
	        webProcessor.clearCookies();
	        
		} catch(Exception e) {

			// Log error
			logger.error("Notes Domino (HTTP Basic) authentication failure: " + e.getMessage(),e);

			// Garbagge collect
			method = null;
			
			// Reset Web processor
			logger.debug("in catch exception BEFORE webprocessors PUT");
			webProcessors.put(Thread.currentThread().getName(), null);
			logger.debug("in catch exception AFTER webprocessors PUT");
			// Update status code
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;
			
		}

		//
		// End of the authentication process
		//


		// Debug
		logger.debug("Notes Domino (HTTP Basic) Authentication completed (" + statusCode + ")");
      
		
		
		// Return status code
		return statusCode;
	}
	
        private static WebProcessor getWebProcessorInstance(Logger logger) {
		
		String threadName = null;
		WebProcessor webProcessor = null;
		
		// Read thread name
		threadName = Thread.currentThread().getName();
		
		// Retrieve Web processor
		webProcessor = (WebProcessor) webProcessors.get(threadName);
		
		// Protection
		if (webProcessor == null) {
			
			// Instantiate new Web processor
			webProcessor = new WebProcessor();
			
			// Register instance
			webProcessors.put(threadName, webProcessor);
			
		}
		
		// Return instance
		return webProcessor;
		
	}

}
