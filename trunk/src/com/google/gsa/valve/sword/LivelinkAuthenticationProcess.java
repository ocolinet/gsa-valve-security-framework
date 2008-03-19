 /**
  * Copyright (C) 2008 Sword
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

package com.google.gsa.valve.sword;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.security.auth.login.LoginException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;


public class LivelinkAuthenticationProcess implements AuthenticationProcessImpl {
	
	private static final String UIDCookName = "userId";
	private static final String CMSCookName = "LLCookie";
	
	private Logger logger = null;
	private WebProcessor  webProcessor = null;
	private HttpMethodBase webProcResponse = null;
	private ValveConfiguration conf = null;
	
	public void setLogger(Logger logger) {
		this.logger = logger;
	}
	
	public LivelinkAuthenticationProcess() {
		logger = Logger.getLogger(this.getClass());
	}
	
	public void setValveConfiguration(ValveConfiguration valveConf) {
		this.conf  = valveConf;
		
	}

	public int authenticate(HttpServletRequest request,
			HttpServletResponse response, Vector<Cookie> reusableCookies, String url,
			Credentials creds, String id) throws HttpException, IOException {

		// Initialize status code
		int statusCode 							= HttpServletResponse.SC_UNAUTHORIZED;
		String userID 							= null;
		String password 						= null;
		String domain							= null;
		Cookie extAuthCookie 					= null;
		
		String authNparameter = null;
		
		
		Credential cred = creds.getCredential(id);

		if (this.conf.getRepository(id).getParameterValue("livelinkAuthenticationConfFilePath") != null) {
			logger.debug("livelinkAuthenticationConfFilePath: " + this.conf.getRepository(id).getParameterValue("livelinkAuthenticationConfFilePath"));
			authNparameter = this.conf.getRepository(id).getParameterValue("livelinkAuthenticationConfFilePath");
		}
		
		//Protection
		Cookie[] cookies = null;
		boolean authN = false;
		boolean user = false;
		
		logger.debug("[LIVELINKAUTHENTICATIONPROCESS]  Launching the livelink authentication process");
		
//		Read cookies
		cookies = request.getCookies();
//		Protection
		if (cookies != null) {
			if (logger.isDebugEnabled()) logger.debug("[LIVELINKAUTHENTICATIONPROCESS]  Cookies trouvés");	
			// Check if the authentication process already happened by looking at the existing cookies
			
			for (int i = 0; i < cookies.length; i++) {
				
				// Check cookie name
				if ((cookies[i].getName()).equals("gsa_livelink_LLCookie_"+id)) {
					
					logger.debug("[LIVELINKAUTHENTICATIONPROCESS]  Cookie gsa_livelink_LLCookie found");
					// Increment counter
					authN = true; 
					
				}
				
				if ((cookies[i].getName()).equals(LivelinkAuthenticationProcess.UIDCookName+"_"+id)) {
					
					logger.debug("[LIVELINKAUTHENTICATIONPROCESS]  Cookie gsa_livelink_LLCookie found");
					
					user = true;
					
				}
				
			}
			
		}
		
		// Protection
		if (authN && user) {
			
			logger.debug("[LIVELINKAUTHENTICATIONPROCESS]  Authentication on livelink already happened");
			
			// Set status code
			statusCode = HttpServletResponse.SC_OK;
			
			// Return
			return statusCode;
			
		} else {
			logger.debug("[LIVELINKAUTHENTICATIONPROCESS]  Authenticating user.");
		}
		
		
		
		// Read HTTP parameters
		/* version pour demo Google
		 userID 	= (String)request.getAttribute("Username");
		 password = (String)request.getAttribute("Password");
		 domain = (String)request.getAttribute("Domain");
		 */
		userID 	= cred.getUsername();
		logger.debug("[LIVELINKAUTHENTICATIONPROCESS] userID vaut "+userID);
		password = cred.getPassword();
		domain = conf.getAuthCookieDomain();
		
		
		logger.debug("[LIVELINKAUTHENTICATIONPROCESS] userID: "+userID);
		
		
		if ((userID==null) || (userID.equals(""))) {
			
			// Debug
			logger.error("HTTP 'UserID' parameter required!");
			
			// Return
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;
			
		}
		
		// Protection
		if ((password==null) || (password.equals(""))) {
			
			logger.error("HTTP 'Password' parameter required!");
			
			// Return
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;
			
		}
		
		try{
			this.webProcessor=new WebProcessor();
			DOMParser parser = new DOMParser();
			
			parser.parse(authNparameter);
			Document document = parser.getDocument();
			NodeList requests = document.getElementsByTagName("request"), tmpLst = null;
			String type = null;
			String urltofetch = null;
			boolean cookieSessionfound = false;
			Element element1 = null;
			String attValue = null;
			Hashtable<String,NameValuePair> hashtable = new Hashtable<String,NameValuePair>(0);
			Vector<NameValuePair> vector1 = new Vector<NameValuePair>(0);
			for(int i = 0 ; i< requests.getLength(); i++){
				hashtable = new Hashtable<String,NameValuePair>(0);
				vector1 = new Vector<NameValuePair>(0);
				tmpLst = requests.item(i).getChildNodes();
				for (int j=0 ; j<tmpLst.getLength() ; j++) {
					
					if (tmpLst.item(j).getNodeType() == Node.ELEMENT_NODE) {
						element1 = (Element)tmpLst.item(j);
						if(tmpLst.item(j).getNodeName().equalsIgnoreCase("type")){
							type = tmpLst.item(j).getFirstChild().getNodeValue();
							continue;
						}
						
						if(tmpLst.item(j).getNodeName().equalsIgnoreCase("URL")){
							urltofetch = tmpLst.item(j).getFirstChild().getNodeValue();
							continue;
						}
						if(tmpLst.item(j).getNodeName().equalsIgnoreCase("header")){
							Header header1 = new Header(element1.getAttribute("name"), element1.getAttribute("value"));
							hashtable.put(header1.getName(), header1);
							continue;
						}
						if(tmpLst.item(j).getNodeName().equalsIgnoreCase("parameter")){
							if(element1.getAttribute("name").equals("Username")){
								attValue = userID;
							}else if(element1.getAttribute("name").equals("Password")){
								attValue = password;
							}else if(element1.getAttribute("name").equals("Domain")){
								attValue = domain;
							}else{
								attValue = element1.getAttribute("value");
							}
							vector1.add(new NameValuePair(element1.getAttribute("name"), attValue));
						}
					}
				}
				Enumeration<NameValuePair> enumeration1 = vector1.elements();
				NameValuePair anamevaluepair1[] = new NameValuePair[vector1.size()];
				for(int l = 0; enumeration1.hasMoreElements(); l++){
					anamevaluepair1[l] = (NameValuePair)enumeration1.nextElement();
					logger.debug(anamevaluepair1[l].getName());
				}
				
				enumeration1 = hashtable.elements();
				Header aheader1[] = new Header[hashtable.size()];
				for(int i1 = 0; enumeration1.hasMoreElements(); i1++){
					aheader1[i1] = (Header)enumeration1.nextElement();
					logger.debug(aheader1[i1].getName() + " : " + aheader1[i1].getValue());
				}
				
				try {
					webProcResponse = webProcessor.sendRequest(/*credentials*/null,type,aheader1,anamevaluepair1,urltofetch);
				} catch (LoginException e) {
					return 401;
				}
				String larep=webProcResponse.getResponseBodyAsString();
				if (conf.getRepository(id).getParameterValue("OutputAUTHN")!=null && "true".equals(conf.getRepository(id).getParameterValue("OutputAUTHN"))) {
					logger.trace("----------------[LIVELINKAUTHENTICATIONPROCESS]___________Response\r\n"+larep);
				}
				
				org.apache.commons.httpclient.Cookie[] responseCookies = webProcessor.getResponseCookies();
				org.apache.commons.httpclient.Cookie gsaAuthCookie = new org.apache.commons.httpclient.Cookie();
				
				// if this is the first request done, we retrieve the cookie
				// generated by the source 
				if(!cookieSessionfound){
					logger.info("[LIVELINKAUTHENTICATIONPROCESS] cookie Session not found" );
					
					for (int j = 0; j < responseCookies.length; j++) {
						if ((responseCookies[j].getName()).equals(CMSCookName)){
							gsaAuthCookie.setValue(responseCookies[j].getValue());
							logger.info("\t[LIVELINKAUTHENTICATIONPROCESS] cookie "+CMSCookName);
							String authCookieDomain = this.conf.getAuthCookieDomain();
							String authCookiePath = this.conf.getAuthCookiePath();
                                                        int authMaxAge = -1;
                                                        try {                                                                             
                                                            authMaxAge = Integer.parseInt(this.conf.getAuthMaxAge());                
                                                        } catch(NumberFormatException nfe) {
                                                            logger.error ("Configuration error: check the configuration file as the number set for authMaxAge is not OK:");
                                                        }
							
							//Instantiate a new cookie
							extAuthCookie = new Cookie(("gsa_livelink_" + responseCookies[j].getName() + "_" + id), (responseCookies[j].getName() + 
									"||" + responseCookies[j].getValue() + "||" + responseCookies[j].getPath() + 
									"||" + responseCookies[j].getDomain() + "||" + responseCookies[j].getSecure()));
							
							extAuthCookie.setDomain(authCookieDomain);
							
							extAuthCookie.setPath(authCookiePath);
                                                        
                                                        extAuthCookie.setMaxAge(authMaxAge);
							
							// Add authentication cookie
							reusableCookies.add(extAuthCookie);
							
							Cookie userIdCookie = new Cookie (LivelinkAuthenticationProcess.UIDCookName, userID);
							userIdCookie.setPath(authCookiePath);
							userIdCookie.setDomain(authCookieDomain);
                                                        userIdCookie.setMaxAge(authMaxAge);
							
							reusableCookies.add(userIdCookie);
							
							cookieSessionfound = true;
							break;
							
							
						}
					}
					
				}
			}
			

			
			String error = conf.getRepository(id).getParameterValue("livelinkErrorPage");
			
			if (error==null) {
				error = "<title>Livelink - Error</title>";
			}
			String resp = webProcResponse.getResponseBodyAsString();
			//<p>Error fetching item.
			if (resp.indexOf(error)!=-1 || resp.indexOf("window.document.LoginForm.Username.focus()")!=-1 || resp.indexOf("Invalid username/password specified") != -1 || webProcResponse.getStatusCode() != 200){
				statusCode=HttpServletResponse.SC_UNAUTHORIZED;
				logger.error("[LIVELINKAUTHENTICATIONPROCESS] failed ("+webProcResponse.getStatusCode()+")");
			}else{
				statusCode=HttpServletResponse.SC_OK;
				logger.info("[LIVELINKAUTHENTICATIONPROCESS] Authentication successfull");
			}
			//Clear webProcessor cookies
			webProcessor.clearCookies();
			webProcessor = null;
		}catch (HttpException he) {
			logger.error("[LIVELINKAUTHENTICATIONPROCESS] HttpException... Aborting",he);
			return HttpServletResponse.SC_UNAUTHORIZED;
		} catch (IOException ioe) {
			logger.error("[LIVELINKAUTHENTICATIONPROCESS] IOException... Aborting",ioe);
			return HttpServletResponse.SC_UNAUTHORIZED;
		} catch (SAXException e) {
			logger.error("[LIVELINKAUTHENTICATIONPROCESS] SAXException... Aborting",e);
			return HttpServletResponse.SC_UNAUTHORIZED;
		}
		
		return statusCode;
	}
}

