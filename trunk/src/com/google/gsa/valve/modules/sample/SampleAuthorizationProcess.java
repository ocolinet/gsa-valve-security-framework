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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;

import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;


public class SampleAuthorizationProcess implements AuthorizationProcessImpl {
	
	private Logger logger = null;
	
	private ValveConfiguration valveConf = null;
	
	public SampleAuthorizationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(SampleAuthorizationProcess.class);
	}
	
        public void setCredentials (Credentials creds) {
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }
        
	
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url,  String id) throws HttpException, IOException {
                
		//Read a property for this implemtation
		if (valveConf != null) {
			valveConf.getRepository(id).getParameterValue("config1");			
		} else {
			logger.error("ValveConfig is null");
		}
		
		//Get the cookie(s) required for this implementation
		Cookie[] cookies = null;
		
		// Cookie counter
		int nbCookies = 0;
		
                //CLAZARO: add support to authCookies
                cookies = authCookies;
		
		// Protection
		if (cookies != null) {
				
			// Check if the authentication process already happened by looking at the existing cookies	
			for (int i = 0; i < cookies.length; i++) {
	
				// Check cookie name
				if ((cookies[i].getName()).equals("gsa_sample_auth") ) {
					logger.debug("Cookie gsa_sample_auth:" + cookies[i].getValue());
					
					// Increment counter
					nbCookies++; 					
				}				
			}			
		}
		
		
		//TODO Implement code to authorise the document
                SampleProcessor sampleProcessor = null;
		Request rqst = null;
		int statusCode = 0;
		
		
		// Retrieve Web processor
		sampleProcessor = SampleProcessor.getInstance(logger);

		// Instantiate request object
		rqst = new Request(request, response, authCookies, url);
		
		// Set status code
		rqst.setStatusCode(HttpServletResponse.SC_UNAUTHORIZED);
		
		// Process request
		sampleProcessor.processRequest(rqst);

		// Debug info
		if (logger.isDebugEnabled()) logger.debug("Sending new request to the Sample processor: " + rqst.getUrl());
		  
        // Wait until the request has been processed
        synchronized (rqst) {
            try { rqst.wait(); } catch (InterruptedException ie) {}
        }

        // Cache status code 
        synchronized (rqst) {
            statusCode = rqst.getStatusCode();
        }
        
		// Debug info
		if (logger.isDebugEnabled()) logger.debug("Request processed successfully by the Sample processor: " + rqst.getUrl());
		
		// Return status code
		return statusCode;
		
	}
	
}
