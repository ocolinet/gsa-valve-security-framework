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

package com.google.gsa.valve.modules.krb;

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
import com.google.gsa.valve.modules.utils.HTTPVisitor;
import com.google.krb5.Krb5Credentials;

import java.net.MalformedURLException;
import java.net.URL;

import java.net.URLDecoder;


public class KerberosAuthorizationProcess implements AuthorizationProcessImpl {
	
	private Logger logger = null;
	private WebProcessor webProcessor = null;
        private Krb5Credentials credentials = null;
        private Credentials creds = null;
        //Header
        private Header[] headers = null;
        //Max Connections
        private int maxConnectionsPerHost = -1;
        private int maxTotalConnections = -1;
        //Method
        private HttpMethodBase method = null;
        
        //Var that tells the default Credential ID for Kerberos
        private static final String KRB5_ID = "krb5";
        
        //Config
        private ValveConfiguration valveConf;
        
        
	public KerberosAuthorizationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(KerberosAuthorizationProcess.class);
	}
        
        public KerberosAuthorizationProcess(Krb5Credentials credentials) {
            
            //Instantiate logger
            logger = Logger.getLogger(KerberosAuthorizationProcess.class);
            
            //set credentials
            this.credentials = credentials;
            
        }
                
        public void setKrbCredentials (Krb5Credentials credentials) {
            this.credentials = credentials;
        }
        
        public Krb5Credentials getKrbCredentials () {
            return (this.credentials);
        }
        
        public void setCredentials (Credentials creds) {
            this.creds = creds;
        }        
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                    
        }
                                    
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] responseCookies, String url, String id) throws HttpException, IOException {

                logger.debug("Krb Authorization");
                
		String loginUrl = null;

                loginUrl = valveConf.getLoginUrl();		
                
                maxConnectionsPerHost = (new Integer (valveConf.getMaxConnectionsPerHost())).intValue();
                maxTotalConnections = (new Integer (valveConf.getMaxTotalConnections())).intValue();
                
                logger.debug("KrbAuthZ maxConnectionsPerHost: "+maxConnectionsPerHost);
                logger.debug("KrbAuthZ maxTotalConnections: "+maxTotalConnections);
	    
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
		// Launch the authorization process
		//
		
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                
                //set credentials
                if (creds != null) {
                    logger.debug("creds is not null");
                    if (creds.getCredential(KRB5_ID)!= null) {
                        credentials = new Krb5Credentials ( valveConf.getKrbConfig().getKrbconfig (), valveConf.getKrbConfig().getKrbini(), creds.getCredential(KRB5_ID).getSubject());
                    }
                }
		
		if (credentials == null) {
			
			// no authZ header, can't auth this URL
			logger.debug("No Kerberos credentials");
			return statusCode;
		
		} else {                                                               
		                            
                        //is a Head request?
                        boolean isHead = false;                                                                        
		          
                        setHead (request, isHead);  
                        
			// Protection
			if (webProcessor != null) {
				
				// Protection
				try {
                                                                                                           
                                         method = webProcessor.sendRequest(credentials, request.getMethod(), headers, null, url);                                                                                                                         
                                        
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
                                        logger.debug("Let's release the connection");										
					method.releaseConnection();
					method = null;				
                                        webProcessor = null;
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
        
        int numHeaders = 1;
                                                   
        String range = request.getParameter("Range");
        logger.debug("Range Parameter: "+range);
                                                                           
        if (request.getMethod().equals(RequestType.HEAD_REQUEST)) {
            isHead = true;
        } else {
            if (range != null) {
                if (range.contains("0-0")) {
                    isHead = true;
                    numHeaders = 2;
                }
            }
        }
                                                   
        if (numHeaders == 1) {
            //Set HTTP headers
            headers = new Header[1];
            // Set User-Agent
            headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");          
        } else {
            //Set HTTP headers
            headers = new Header[2];
            // Set User-Agent
            headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");
            headers[1] = new Header("Range", range);
        }
    }
	
}
 