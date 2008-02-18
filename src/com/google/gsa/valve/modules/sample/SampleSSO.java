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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.util.Vector;

public class SampleSSO implements AuthenticationProcessImpl{

	private Logger logger = null;
	private ValveConfiguration valveConf = null;
        private Cookie gsaAuthCookie;
	
	public SampleSSO() {
		logger = Logger.getLogger(SampleSSO.class);
		
	}
	
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }
		
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
		               
                int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		
		logger.debug("Performing " + id + " authentication");
		//Create credentials for sample implementation
		Credential cred = new Credential("sample");
		cred.setUsername("test");
		cred.setPassword("testpassword");
		creds.add(cred);
		
		Credential dctmCred = new Credential("dctm");
		dctmCred.setUsername("emilie");
		dctmCred.setPassword("emilie2");
		creds.add(dctmCred);
		
		
		
		Cookie[] cookies = null;
		
		// Read cookies
		cookies = request.getCookies();
                
                Cookie sampleSSOCookie = null;
		
		boolean alreadyAuthenticated = false;
		
		if (cookies != null) {
			
			// Check if the authentication process already happened by parsing the existing cookies	
			for (int i = 0; i < cookies.length; i++) {
	
				// Check cookie name
				if ( cookies[i].getName().equals("gsa_sso_sample") )  {
					alreadyAuthenticated = true;
                                        sampleSSOCookie = cookies[i];
				}
				
			}
			
		}
		
		if (!alreadyAuthenticated) {
			
			String username = null;
			String password = null;
			
			// Read HTTP request parameters
			username = request.getParameter("UserID");
			password = request.getParameter("Password");
			
			
			//Set the gsa Auth cookie to the u/p from the login page
			gsaAuthCookie.setValue("sampleSSO||" + username + "||" + password);
                        //add sendCookies support
                        boolean isSessionEnabled = new Boolean (valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
                        boolean sendCookies = false;
                        if (isSessionEnabled) {
                            sendCookies = new Boolean (valveConf.getSessionConfig().getSendCookies()).booleanValue();
                        }
                        if ((!isSessionEnabled)||((isSessionEnabled)&&(sendCookies))) {
                            response.addCookie(gsaAuthCookie);
                        }
                        
                        //add cookie to the array
                        authCookies.add (gsaAuthCookie);

		} else {
                    authCookies.add (sampleSSOCookie);
                }
		
		statusCode = HttpServletResponse.SC_OK;
		
		
		return statusCode;
		
	}
	
}
