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
import java.util.Vector;

import javax.security.auth.login.LoginException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.IWebProcess;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;

public final class DCTMAuthenticationProcess implements AuthenticationProcessImpl {

	private Logger logger = null;
	private ValveConfiguration conf = null;
	private final String CMSCookName = "JSESSIONID";

	public DCTMAuthenticationProcess() {
		logger = Logger.getLogger(DCTMAuthenticationProcess.class);
	}

	public void setValveConfiguration(ValveConfiguration valveConf) {
		this.conf = valveConf;
	}

	/**
	 * The DCTMAuthNProcess intends to authenticate a user using Webtop's login form.
	 * For Kerberos AuthN, use an HTTPKerbAuthNProcess as no particular cookie needs to be generated for DctmKerb
	 */
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> reusableCookies, String url, Credentials creds, String id) throws HttpException, IOException {
		logger.info("DCTMAUTHENTICATION started");
//		boolean session = false;
//		boolean send = false;
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		String userID = null;
		String password = null;
		String docbase = null;
//		UsernamePasswordCredentials credentials = null;

		String path_to_conf_file = null;

		if (this.conf == null || this.conf.getRepository(id)==null) {
			logger.error("The configuration was not correctly set.");
			return statusCode;
		} else {
			if (this.conf.getRepository(id).getParameterValue("webtopAuthenticationConfFilePath") != null) {
//				session = new Boolean(this.conf.getSessionConfig().isSessionEnabled()).booleanValue();
//				send = new Boolean(this.conf.getSessionConfig().getSendCookies()).booleanValue();
				logger.debug("ValveConfig is: "+ this.conf.getRepository(id).getParameterValue("webtopAuthenticationConfFilePath"));
				path_to_conf_file = this.conf.getRepository(id).getParameterValue("webtopAuthenticationConfFilePath");
			}

			docbase = id;
			logger.debug("Selected Docbase: "+docbase);
		}

		Cookie extAuthCookie = null;

		// Protection
		Cookie[] cookies = null;

		// Set counter
		int nbCookies = 0;

		Credential cred = creds.getCredential(id);
		if (cred != null) {
			logger.debug("Credentials [" + id + "] username: "
					+ cred.getUsername());
		}

		// Read cookies
		cookies = request.getCookies();
		// Protection

		if (cookies != null) {
			// Check if the authentication process already happened by looking
			// at the existing cookies

			for (int i = 0; i < cookies.length; i++) {

				// Check cookie name
				if ((cookies[i].getName()).equals("gsa_webtop_JSESSIONID_"+id)) {

					logger.debug("Cookie gsa_webtop_JSESSIONID_"+id+" found");
					nbCookies++;

				}
				if ((cookies[i].getName()).equals("userId")) {

					logger.debug("userId cookie found");
					nbCookies++;

				}

			}

		}

		// Protection
		if (nbCookies >= 2) {

			if (logger.isDebugEnabled())
				logger.error("Authentication on webtop already happened. The Authentication process shoud not be called for authenticated sessions.");

			// Set status code
			statusCode = HttpServletResponse.SC_OK;

			// Return
			return statusCode;

		}

		userID = cred.getUsername();
		password = cred.getPassword();
		
		if (userID==null || "null".equals(userID) || "".equals(userID)) {
			logger.error("  HTTP 'UserID' parameter required!");

			// Return
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;

		}

		// Protection
		if (password==null || "null".equals(password) || "".equals(password)) {

			logger.error("  HTTP 'Password' parameter required!");

			// Return
			statusCode = HttpServletResponse.SC_UNAUTHORIZED;

		}

		try {
//			credentials = new UsernamePasswordCredentials(userID, password);
			IWebProcess webProcessor = new WebProcessor();
			HttpMethodBase webResponse = null;
			DOMParser parser = new DOMParser();
			parser.parse(path_to_conf_file);
			Document document = parser.getDocument();
			NodeList nodes, nodes2;
			nodes = document.getChildNodes().item(0).getChildNodes();
			Element e = null;
			String type = null;
			String urltofetch = null;
			boolean cookieSessionfound = false;
			String authCookieDomain = null;
			String authCookiePath = null;
                        int authMaxAge = -1;		    		    
			String CMSCookValue = null;
			String CMSCookDomain = null;
			String CMSCookPath = null;
			boolean CMSCookSecure = false;

			// read the XML file containing the request for authentication
			for (int i = 1; i < nodes.getLength(); i++) {
				if (nodes.item(i).getNodeType() == Node.ELEMENT_NODE) {
					e = (Element) nodes.item(i);
					if (e.getNodeName().equalsIgnoreCase("request")) {

						i++;
						Vector<NameValuePair> vector1 = new Vector<NameValuePair>(0);

						nodes2 = e.getChildNodes();
						Element element1 = null;
						String attValue = null;
						//Uggly XML parsing. change it
						for (int j = 0; j < nodes2.getLength(); j++) {
							if (nodes2.item(j).getNodeType() == Node.ELEMENT_NODE) {
								element1 = (Element) nodes2.item(j);
								if (nodes2.item(j).getNodeName().equalsIgnoreCase("type"))
									type = nodes2.item(j).getFirstChild().getNodeValue();

								if (nodes2.item(j).getNodeName().equalsIgnoreCase("URL"))
									urltofetch = nodes2.item(j).getFirstChild().getNodeValue();
//								if (nodes2.item(j).getNodeName().equalsIgnoreCase("header")) {
//									Header header1 = new Header(element1.getAttribute("name"), element1.getAttribute("value"));
//									hashtable.put(element1.getAttribute("name"), header1);
//								}
								if (nodes2.item(j).getNodeName().equalsIgnoreCase("parameter")) {
									if (element1.getAttribute("name").equals("Login_username_0")) {
										attValue = userID;
									} else if (element1.getAttribute("name").equals("Login_password_0")) {
										attValue = password;
									} else if (element1.getAttribute("name").equals("Login_docbase_0")) {
										attValue = docbase;
									} else {
										attValue = element1.getAttribute("value");
									}
									vector1.add(new NameValuePair(element1.getAttribute("name"), attValue));
								}
							}

						}
						Enumeration<NameValuePair> enumeration1 = vector1.elements();
						NameValuePair anamevaluepair1[] = new NameValuePair[vector1.size()];
						for (int l = 0; enumeration1.hasMoreElements(); l++) {
							anamevaluepair1[l] = (NameValuePair) enumeration1.nextElement();
						}

						if (webResponse != null) {
							logger.debug("release previous connection");
							webResponse.releaseConnection();
						}
						try {
							//No credentials
							webResponse = webProcessor.sendRequest(/*credentials*/null, type, null, anamevaluepair1, urltofetch);
						} catch (LoginException e1) {
							return 401;
						}
						
						//DEBUG
						if (this.conf.getRepository(id).getParameterValue("OutputAUTHN")!=null) {
							Outputter o = new Outputter(this.conf.getRepository(id).getParameterValue("OutputAUTHN"));
							o.fillIn(webResponse.getResponseBodyAsString());
							new Thread(o).start();
							
						}

						org.apache.commons.httpclient.Cookie[] responseCookies = webProcessor.getResponseCookies();

						if (!cookieSessionfound) {
							for (int j = 0; j < responseCookies.length; j++) {
								logger.debug("Parsing cookie: "+responseCookies[j].getName());
								if ((responseCookies[j].getName()).equals(CMSCookName)) {
									logger.info("cookie " + CMSCookName);
									authCookieDomain = this.conf.getAuthCookieDomain();
									authCookiePath = this.conf.getAuthCookiePath();
                                                                        try {                                                                             
                                                                            authMaxAge = Integer.parseInt(this.conf.getAuthMaxAge());                
                                                                        } catch(NumberFormatException nfe) {
                                                                            logger.error ("Configuration error: check the configuration file as the number set for authMaxAge is not OK:");
                                                                        }

									CMSCookValue = responseCookies[j].getValue();
									CMSCookDomain = responseCookies[j].getDomain();
									CMSCookPath = responseCookies[j].getPath();
									CMSCookSecure = responseCookies[j].getSecure();
								

									cookieSessionfound = true;
									break;

								}

							}
						}
					}
				}
			}
			
			//DEBUG
			if (this.conf.getRepository(id).getParameterValue("OutputAUTHN")!=null) {
				Outputter o = new Outputter(this.conf.getRepository(id).getParameterValue("OutputAUTHN")+"_Final");
				o.fillIn(webResponse.getResponseBodyAsString());
				new Thread(o).start();
				
			}

			if (webResponse.getResponseBodyAsString().indexOf("login.jsp") != -1) {
				logger.info("login.jsp page => authN failed.");
				statusCode = HttpServletResponse.SC_UNAUTHORIZED;
				webResponse.releaseConnection();
			} else {
				statusCode = HttpServletResponse.SC_OK;

				// /création des cookies

				extAuthCookie = new Cookie(("gsa_webtop_" + CMSCookName + "_"+id),
						(CMSCookName + "||" + CMSCookValue + "||" + CMSCookPath
								+ "||" + CMSCookDomain + "||" + CMSCookSecure));
				
				logger.info("AuthN successful. Wrapping the authentication cookie.");

				// Set extra cookie parameters
				extAuthCookie.setDomain(authCookieDomain);
				extAuthCookie.setPath(authCookiePath);
                                extAuthCookie.setMaxAge(authMaxAge);

				Cookie userIdCookie = new Cookie("userId", userID);
				userIdCookie.setPath(authCookiePath);
				userIdCookie.setDomain(authCookieDomain);
                                userIdCookie.setMaxAge(authMaxAge);

				/**Add to the vector any case.
				The choice to add cookies to the request, object according to send and session,
				will be made getting back to the rootAuthNProcess**/
					reusableCookies.add(userIdCookie);
					reusableCookies.add(extAuthCookie);

				logger.debug("release connection");
				webResponse.releaseConnection();

			}

			///request.setAttribute("status",Integer.toString(statusCode));
			logger.info(" Return status is :" + Integer.toString(statusCode));

			//			Clear webProcessor cookies
			webProcessor.clearCookies();

		} catch (Exception e) {
			logger.error("Exception " + e.getClass().getName(),e);
		}
		return statusCode;
	}
}
