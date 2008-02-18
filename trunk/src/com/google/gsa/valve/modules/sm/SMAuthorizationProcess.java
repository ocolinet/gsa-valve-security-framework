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


package com.google.gsa.valve.modules.sm;


import java.io.IOException;
import java.net.ProtocolException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.log4j.Logger;

import sun.misc.BASE64Decoder;

import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.RequestType;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;


public class SMAuthorizationProcess implements AuthorizationProcessImpl {

	private Logger logger = null;
	private WebProcessor webProcessor = null;
	private ValveConfiguration valveConf = null;

	public SMAuthorizationProcess() {
		//Instantiate logger
		logger = Logger.getLogger(SMAuthorizationProcess.class);
	}
        
        public void setCredentials (Credentials creds) {
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }

	private String getHTTPBasicUsername(String sHeader)
	{
		String sUsername = null;
//		String sPassword = null;
		BASE64Decoder decoder = new BASE64Decoder();
		java.util.StringTokenizer st = new java.util.StringTokenizer(sHeader);
		if (st.hasMoreTokens()) {

			String basic = st.nextToken();
			// We only handle HTTP Basic authentication

			if (basic.equalsIgnoreCase("Basic")) {
				String credentials = st.nextToken();
//				System.out.println("Credentials for authorization, from request -- "
//				+ credentials);
				String userPass = null;
				try {
					userPass = new String(decoder.decodeBuffer(credentials));
//					System.out.println( "Decoded credentials -- "
//					+ userPass);
				} catch (IOException e) {
					e.printStackTrace();
//					System.out.println( "Excpion Occured"+e);
				}
				// The decoded string is in the form
				// "userID:password".

				int p = userPass.indexOf(":");
				if (p != -1) {
					sUsername = userPass.substring(0, p);
//					sPassword = userPass.substring(p + 1);
					//System.out.println( "UserName -- " + sUsername + " Password -- " + sPassword);
				}				
			}
		}
		return sUsername;

	}

	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {
		logger.debug("URL from the : "+ url);

//		logger.debug("calling old method...");
//		//int statusCode = HttpServletResponse.SC_OK;
//		return authorize(request, response, authCookies, url, "");

		Header[] headers = null;
		HttpMethodBase method = null;

		//String smURL = request.getParameter("returnPath");


		//queryString.spl

		
		logger.debug("Authorizing [" + request.getMethod() + "]");
		logger.debug("in SM AuthZ: URL: "+url);
		//logger.debug("SM URL: "+smURL);
		// Protection
		if (webProcessor == null) {
			// Instantiate Web processor
			webProcessor = new WebProcessor();
			//webProcessor.setLogger(logger);
		}

		//Get the http AuthZ header
		Cookie[] requestCookies = null;
                
                //CLAZARO: add support to authCookies
                requestCookies = authCookies;
                
		String userName = null;

		// Protection
		if (requestCookies != null) {
			// Check if the authentication process already happened by looking at the existing cookie
			// The gsa_sm_auth cookie contains the HTTP Basic AuthZ header
			for (int i = 0; i < requestCookies.length; i++) {
				// Check cookie name
				//logger.debug("cookie name: "+ requestCookies[i].getName()+ " cookie.getValue: "+requestCookies[i].getValue());
				if ((requestCookies[i].getName()).equals("gsa_sm_auth") ) {
					if (requestCookies[i].getValue() != null) {
						//userName = getHTTPBasicUsername(requestCookies[i].getValue());
						userName = requestCookies[i].getValue();

//						logger.debug("gsa_sydney_auth: " + );
						//authHeader = new Header("Authorization", requestCookies[i].getValue());
					}
				}
			}
		}

	
		//
		// Launch the authorization process
		//

		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

		//Set HTTP headers
		headers = new Header[4];
		// Set User-Agent
		//The Persistent SM uses a header to control how it is used. With authN-skip set to true it does not need to authenticate the user, it just requires the 
		// user username, as set in sm_cookie
		headers[0] = new Header("authn-skip","true");
		headers[1] = new Header("authz-skip","false");
		headers[2] = new Header("ssocookie","sm_cookie");
		logger.debug("Adding header: sm_cookie=" + userName);
		headers[3] = new Header("Cookie","sm_cookie="+userName);

		// Protection
		if (webProcessor != null) {

			// Protection
			try {
				// Process authz request
				// preparing e,mpty credentials:
				//Credentials cred = new Credentials(0);

				/*				try {
					URL uSM = new URL(url);
					url = uSM.getProtocol() + "//" + uSM.getAuthority() + "/" + uSM.getPath() + "?" + URLEncoder.encode(uSM.getQuery(), "UTF-8") ;
				} catch (Throwable e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				 */
				url = replaceString(url, "\n","%0A");
				url = replaceString(url, "\r","%0D");
				url = replaceString(url, "=","%3D");
				logger.debug("authZ request to SM [" + url + "]");
				method = webProcessor.sendRequest(null, RequestType.GET_REQUEST, headers, null, url);
				

				// Protection
				if (method != null) {

					if (method.getStatusCode() == HttpServletResponse.SC_OK) 
					{
						logger.debug("AuthZ successful: 200");
						statusCode = HttpServletResponse.SC_OK;
						
					} else 
					{
						logger.debug("AuthZ unsuccessful");
						statusCode = HttpServletResponse.SC_UNAUTHORIZED;
					}


				}

				// Garbagge collect

				method.releaseConnection();
				method = null;

			} catch (ProtocolException protExp) {
				logger.error("authorization failure: Protocol exception");
			} catch(Exception e) {

				// Log error
				logger.error("authorization failure: " +  e.getMessage());

				// Garbagge collect
				webProcessor = null;					
				//method.releaseConnection();
				method = null;					
			}

		}

		//
		// End of the authorization process
		//

		// Return status code
		return statusCode;

	}
	/**
	 * This method replaces a string from a string by another string.
	 * @param baseString Parent string.
	 * @param stringToFind String needs to be replaces with.
	 * @param stringToReplace String needs to be replaced by.
	 * @return String with replacement or original string.
	 * 
	 */
	public static String replaceString(String baseString, String stringToFind, String stringToReplace) {
		String result = baseString;
		StringBuffer buffer = null;
		int index = baseString.indexOf(stringToFind);
		if (index != -1) {
			buffer = new StringBuffer(baseString);
			buffer.replace(index, (index + stringToFind.length()), stringToReplace);
			result = buffer.toString();
		}
		return result;
	}
	

}
