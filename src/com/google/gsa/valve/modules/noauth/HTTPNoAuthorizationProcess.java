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


import com.google.gsa.valve.modules.utils.HTTPVisitor;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Properties;

import javax.servlet.ServletInputStream;
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


public class HTTPNoAuthorizationProcess implements AuthorizationProcessImpl {
	
	private Logger logger = null;
	private WebProcessor webProcessor = null;
	
	private ValveConfiguration valveConf = null;
	
	public HTTPNoAuthorizationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(HTTPNoAuthorizationProcess.class);
	}
        
        public void setCredentials (Credentials creds) {
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }
			
        public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {

		
		Header[] headers = null;
		HttpMethodBase method = null;
                
		String loginUrl = null;
		loginUrl = valveConf.getLoginUrl();
		
		logger.debug("Authorizing" + url);
		// Protection
		if (webProcessor == null) {
			// Instantiate Web processor
			webProcessor = new WebProcessor();
		}
		
		
		//Get the http AuthZ header
		Cookie[] requestCookies = null;
                
                //CLAZARO: add support to authCookies
                requestCookies = authCookies;

		
		Header authHeader = null;
		// Protection
		if (requestCookies != null) {
			// Check if the authentication process already happened by looking at the existing cookie
			// The gsa_basic_auth cookie contains the HTTP Basic AuthZ header
			for (int i = 0; i < requestCookies.length; i++) {
				// Check cookie name
				if ((requestCookies[i].getName()).equals("gsa_basic_noauth") ) {
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

			//Set HTTP headers
			headers = new Header[2];
			// Set User-Agent
			headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");
			headers[1] = authHeader;
			// Protection
			if (webProcessor != null) {
				
				// Protection
				try {
	
					// Process authz request
					
					//Reformat URL************************************************************
					logger.info("url before encoding: " + url);
					int afterPr = url.indexOf("//")+2;
					int slash =url.substring(afterPr).indexOf("/");
					StringBuilder nURL = null;
					
					// If this is -1 no / was found, so the URL is the base
					//logger.debug("last Slash: " + lastSlash + ":" + afterProcotol);
					if (slash < 0) {
						nURL = new StringBuilder(url);
					} else {
						nURL = new StringBuilder(url.substring(0, slash + afterPr + 1));
						//URLEncoder.encode(url.substring(slash + afterPr + 1),"UTF-8")
						nURL.append(url.substring(slash + afterPr + 1).replaceAll(" ","%20"));
					}
					logger.info("url after encoding: " + nURL.toString());
					//******************************************************************************

					URI test = new URI(url);
					
					logger.debug("URI: " + test.toString());
					
					method = webProcessor.sendRequest(null, RequestType.GET_REQUEST, headers, null, nURL.toString());
	
					
					// Protection
					if (method != null) {
						
						if (method.getStatusCode() == HttpServletResponse.SC_OK) {
							// Cache status code
					        statusCode = method.getStatusCode();
					        
							String contentType = method.getResponseHeader("Content-Type").getValue();
							if (contentType != null) {
								if (contentType.equals("text/html")) {
									logger.debug("Processing an HTML document");
									String stream = null;
							        Parser parser = null;
							        NodeVisitor visitor = null;
							        
							        // Retrieve HTML stream					      
							        stream = readFully(new InputStreamReader(method.getResponseBodyAsStream()));

							        // stream = method.getResponseBodyAsString();
				
					    			// Protection
					    			if (stream != null) {
					    				logger.debug("Stream content size: " + stream.length());
								        // Parse HTML stream to replace any links to include the path to the valve
								        parser = Parser.createParser(stream, null);
								        
								        				        // Instantiate visitor
								        visitor = new HTTPVisitor(url, loginUrl);
								        // Parse nodes
								        parser.visitAllNodesWith(visitor);
								        
					    		        // Get writer
					    		        PrintWriter out = response.getWriter();
				
					    		        // Push HTML content
					    	            if (out != null) { 
					    	            	out.flush(); 
					    	            	out.print(((HTTPVisitor)visitor).getModifiedHTML()); 
					    	            	out.close();
					    	            	logger.debug("Wrote: " + ((HTTPVisitor)visitor).getModifiedHTML().length());
					    	            }
					    	            //	Garbagge collect
						    			stream = null;
					    			}
									
								} else { //non html document type
									int next;
									logger.debug("Processing a non HTML document");
									
									response.setHeader("Content-Type", contentType);
									
									BufferedInputStream bis = null;
									InputStream in = method.getResponseBodyAsStream();
									bis = new BufferedInputStream(in);
									
									ServletOutputStream sOutStream = response.getOutputStream();
									BufferedOutputStream bos = null;              
									bos = new BufferedOutputStream(sOutStream);
									
									//int length = urlc.getContentLength();
									long length = method.getResponseContentLength();
									logger.debug(length);
									//byte[] buff = new byte[(int)1000];
									byte[] buff = new byte[(int)length];
									int bytesRead;
//									 Simple read/write loop.
									int offset = 0;
									try {
									//while(-1 != (bytesRead = bis.read(buff, offset, buff.length))) {
									while(-1 != (bytesRead = bis.read(buff, 0, buff.length))) {
										//logger.debug("offset: " + offset + ": read=(" + bytesRead + ")");
										
										if (bos != null) {
											//bos.write(buff, offset, bytesRead);
											bos.write(buff, 0, bytesRead);
										} else {
											logger.error("bos in null");
										}
										offset = offset + bytesRead;
									}
									} catch (IOException ioe) {
										logger.error("Error while reading binary document" + ioe.getMessage(),ioe);
									}
									
										
									
								}
		
			    			} // End contenttype check not null
		
			    			
						} else {
							
							logger.debug("not AuthZ : should return 401");
							statusCode = HttpServletResponse.SC_UNAUTHORIZED;
						}
	        
		    			
					}
					
					// Garbagge collect
					
					method.releaseConnection();
					method = null;
					
				} catch(Exception e) {
					
					// Log error
					logger.error("authorization failure: " + e.getMessage(),e);
					
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
	
	 public static String readFully(Reader input) throws IOException {
         BufferedReader bufferedReader = input instanceof BufferedReader 
 	        ? (BufferedReader) input
 	        : new BufferedReader(input);
         StringBuffer result = new StringBuffer();
         char[] buffer = new char[4 * 1024];
         int charsRead;
         while ((charsRead = bufferedReader.read(buffer)) != -1) {
             result.append(buffer, 0, charsRead);
         }	        
         return result.toString();
     }

}
