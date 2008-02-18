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


import com.google.gsa.valve.modules.utils.HTTPVisitor;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.log4j.Logger;
import org.htmlparser.Parser;
import org.htmlparser.visitors.NodeVisitor;

import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.RequestType;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.modules.utils.HTTPAuthZProcessor;


public class HTTPBasicAuthorizationProcess implements AuthorizationProcessImpl {
	
	private Logger logger = null;
	private static WebProcessor webProcessor = null;
	private ValveConfiguration valveConf = null;
        //Method
        private HttpMethodBase method = null;
        //Header
        private Header[] headers = null;
        private Header authHeader = null;
        //Max Connections
        private int maxConnectionsPerHost = -1;
        private int maxTotalConnections = -1;
        
	
	public HTTPBasicAuthorizationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(HTTPBasicAuthorizationProcess.class);
	}
        
        public void setCredentials (Credentials creds) {
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
                this.valveConf = valveConf;
                             
        }
		
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {
                
                logger.debug("HTTP Basic Authorization");						
		
		String loginUrl = null;

                loginUrl = valveConf.getLoginUrl();
                
                //Get Max connections
                maxConnectionsPerHost = new Integer (valveConf.getMaxConnectionsPerHost()).intValue();                                
                maxTotalConnections = (new Integer (valveConf.getMaxTotalConnections())).intValue();
		                
                logger.debug("HttpBasic AuthZ maxConnectionsPerHost: "+maxConnectionsPerHost);
		logger.debug("HttpBasic AuthZ maxTotalConnections: "+maxTotalConnections);
		 
		// Protection
		if (webProcessor == null) {
                    // Instantiate Web processor
                    if ((maxConnectionsPerHost != -1)&&(maxTotalConnections!=-1)) {
                        webProcessor = new WebProcessor(maxConnectionsPerHost, maxTotalConnections);
                    } else {
                        webProcessor = new WebProcessor();
                    }
		}
		
		
		//Get the http AuthZ header
		Cookie[] requestCookies = null;
                
                //CLAZARO: add support to authCookies
                requestCookies = authCookies;

                                
		// Protection
                logger.debug("Checking request cookies");
		if (requestCookies != null) {		    
			// Check if the authentication process already happened by looking at the existing cookie
			// The gsa_basic_auth cookie contains the HTTP Basic AuthZ header
			for (int i = 0; i < requestCookies.length; i++) {
				// Check cookie name
                                logger.debug("request cookie: "+requestCookies[i].getName()+":"+requestCookies[i].getValue());
				if ((requestCookies[i].getName()).equals("gsa_basic_auth") ) {
					if (requestCookies[i].getValue() != null) {
						logger.debug("gsa_basic_auth: " + requestCookies[i].getValue());
						authHeader = new Header("Authorization", requestCookies[i].getValue());
					}
				}				
			}			
		}
		
		
		

		//
		// Launch the authorization process
		//
		
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		
		if (authHeader == null) {
			
			// no authZ header, can't auth this URL
			logger.debug("No authZ header");
			return statusCode;
		
		} else {
		    
                        //is a Head request?
                        boolean isHead = false;                           
                        setHead (request, isHead);
                                                 
			// Protection
			if (webProcessor != null) {
				
				// Protection
				try {
	
					// Process authz request
					
					method = webProcessor.sendRequest(null, RequestType.GET_REQUEST, headers, null, url);					

                                         // Protection
                                         if (method != null) {
                                            // Cache status code
                                            statusCode =  method.getStatusCode();
                                            logger.debug ("statusCode is.... "+statusCode);
                                                                                                
                                            if (statusCode == HttpServletResponse.SC_OK) {
                                                //check if it's a Head request
                                                if (!isHead) {
                                                    //call HTTPAuthZProcessor
                                                     HTTPAuthZProcessor.processResponse (response, method, url, loginUrl);
                                                }
                                            } else {
                                                     
                                                     logger.debug("not AuthZ : should return response Code");
                                             }                                            
                                         } 
					
					 // Garbagge collect
					 if (method != null) {
                                            method.releaseConnection();
                                            method = null;
                                         }
                                         webProcessor = null;
					                                         
                                } catch(Exception e) {
					                                         
                                        // Log error
                                        logger.error("authorization failure: " + e.getMessage(),e);
                                        statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;                                        
					                                         
                                        // Garbagge collect
                                        webProcessor = null;                                    
                                        method.releaseConnection();
                                        method = null;                                  
                                }
				
			}
			
			//
			// End of the authorization process
			//
			
			// Return status code
			return statusCode;
		}
		
	}
        
        public void setHead (HttpServletRequest request, boolean isHead) {
            
            int numHeaders = 2;
                                                       
            String range = request.getParameter("Range");
            logger.debug("Range Parameter: "+range);
                                                                               
            if (request.getMethod().equals(RequestType.HEAD_REQUEST)) {
                isHead = true;
            } else {
                if (range != null) {
                    if (range.contains("0-0")) {
                        isHead = true;
                        numHeaders = 3;
                    }
                }
            }
                                                       
            if (numHeaders == 2) {
                //Set HTTP headers
                headers = new Header[2];
                // Set User-Agent
                headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");          
                headers[1] = authHeader;
            } else {
                //Set HTTP headers
                headers = new Header[3];
                // Set User-Agent
                headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");
                headers[1] = authHeader;
                headers[2] = new Header("Range", range);
            }
        }
	

}
