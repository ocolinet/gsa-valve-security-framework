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

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.io.IOException;

import java.util.Vector;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;


public class SampleAuthenticationProcess implements AuthenticationProcessImpl {
	
	// Number of auth cookies expected for this Authentication class, used as a check validation check
	private static final int NB_AUTH_COOKIES = 1;
	
	private ValveConfiguration valveConf = null;
	
	
	private Logger logger = null;
	
	public SampleAuthenticationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(SampleAuthenticationProcess.class);
		
	}
	
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }
	
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
		
		
		//Read Credentials for this implementation
		Credential cred = creds.getCredential(id);
		if (cred != null) {
			logger.debug("Credentials [" + id + "] username: " + cred.getUsername());
		}
                		

//		Read a property for this implemtation
		if (valveConf != null) {
			valveConf.getRepository(id).getParameterValue("config1");			
		} else {
			logger.error("ValveConfig is null");
		}
		
		
		
		
		Cookie[] cookies = null;
		
		// Cookie counter
		int nbCookies = 0;
		
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		
		// Read cookies
		cookies = request.getCookies();
                
                Cookie sampleCookie = null;
		
		//In this sample a single cookie is created after a succussfull authenitcation, gsa_sample_sessionID
		//First check if it exisits, if it does that assume still authenticated and return
		

		// Protection
		if (cookies != null) {
				
			// Check if the authentication process already happened by looking at the existing cookies	
			for (int i = 0; i < cookies.length; i++) {
	
				// Check cookie name
				if ((cookies[i].getName()).equals("gsa_sample_auth") ) {
                                        
                                        sampleCookie = cookies[i];
                                        
					// Increment counter
					nbCookies++; 					
				}				
			}			
		}
		
		// Protection
	
		if (nbCookies == NB_AUTH_COOKIES) {
			
			logger.debug("Already Authenticated");
				
                        //add cookie
                        authCookies.add (sampleCookie);
                                	
			// Set status code
			statusCode = HttpServletResponse.SC_OK;

			// Return
			return statusCode;
			
		}
		
		
		//If the required cookie was not found need to authenticate.
		logger.debug("Authenticating");
		try {
			//Perform any required authentication
			
			//TODO - Perform authentication here using availble credentials
			//This sample does none, but does create a cookie that would be used by the Sample AuthZ 
		
	        Cookie extAuthCookie = null;
						
			// Instantiate a new cookie
			extAuthCookie = new Cookie("gsa_sample_auth", "true");
			String authCookieDomain = null;
			String authCookiePath = null;
						
			// Cache cookie properties
			authCookieDomain = (request.getAttribute("authCookieDomain")).toString();
			authCookiePath = (request.getAttribute("authCookiePath")).toString();
						
			// Set extra cookie parameters
			extAuthCookie.setDomain(authCookieDomain);
			extAuthCookie.setPath(authCookiePath);
				
			// Log info
			logger.debug("Adding cookie: " + extAuthCookie.getName() + ":" + extAuthCookie.getValue() 
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
			
			//This would be set to OK or 401 in a real AuthN module
			statusCode = HttpServletResponse.SC_OK;
	        
		} catch(Exception e) {

			// Log error
			logger.error("Sample authentication failure: " + e.getMessage(),e);


			// Update status code
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;
			
		}


		// Debug
		logger.debug("Sample Authentication completed (" + statusCode + ")");
      
		// Return status code
		return statusCode;
		
	}
	
}
