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
import java.security.Principal;
import java.util.Iterator;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.log4j.Logger;
import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.IWebProcess;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;

public final class DCTMAuthorizationProcess implements AuthorizationProcessImpl {

	private static Logger logger = null;
	private boolean dctmKerb = false;

	public DCTMAuthorizationProcess() {
		logger = Logger.getLogger(DCTMAuthorizationProcess.class);
	}

	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {
		logger.info("Authorization process");

		String httpMethod = request.getMethod();
		logger.trace("httpmethod: " + httpMethod);

		//3 mandatory parameters.
		String webtopServletPath = null;
		String authzServletPath = null;
		String webtopDomain = null;

		try 
		{
			webtopServletPath = this.conf.getRepository(id).getParameterValue("webtopServletPath");
			logger.debug("webtopServletPath: " + webtopServletPath);

			authzServletPath = this.conf.getRepository(id).getParameterValue("authzServletPath");
			logger.debug("authzServletPath: " + authzServletPath);

			webtopDomain = this.conf.getRepository(id).getParameterValue("webtopDomain");
			logger.debug("webtopDomain: " + webtopDomain);

			String authN = this.conf.getRepository(id).getAuthN();
			dctmKerb = !("com.google.gsa.valve.sword.DCTMAuthenticationProcess".equals(authN));
			logger.debug("Authentication Documentum: " + (dctmKerb?"Windows integrated":"Native login form"));

		} 
		catch (NullPointerException e)
		{
			logger.error("A mandatory configuration parameter is missing.\r\n\t- webtopServletPath: "
					+webtopServletPath+"\r\n\t- authzServletPath: "+authzServletPath+"\r\n\t- webtopDomain: "+webtopDomain,e);
			return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
		}


		String[] tabURL = url.split("/");
		IWebProcess webProcessor = new WebProcessor();
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		try {

			String userAgent = request.getHeader("User-Agent");
			logger.trace("UserAgent : " + userAgent);

			boolean webtopCookieok = false;

			//TODO jpn: userAgent can be customized. Should be externalized.
			if ((userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise") != -1)) {//crawl
				logger.info("CRAWLING request");
				TransformURL tu = new TransformURL(webtopServletPath,authzServletPath);
				url = tu.transform(request.getMethod(), url, userAgent);
				logger.debug("Transformed URL: " + url);
				statusCode = HttpServletResponse.SC_FOUND;
				try {

/**Cookies not required by the gsaDctmCrawl component
//					//If sendCookie = true or Session = false, the cookies are already in the response
//					//As we cannot have dependency on those parameters, let's add them anyway 
//					for (int i=0 ; i<authCookies.length ; i++) {
//						response.addCookie(authCookies[i]);
//						logger.trace("Adding the cookie "+authCookies[i].getName());
//					}
**/

					response.sendRedirect(url);
				} catch (IOException e) {
					logger.error("IOException when directing toward: " + url,e);
					statusCode = HttpServletResponse.SC_UNAUTHORIZED;//UnauthZ is the only status code the valve should be able to send (apart from 500 for internal errors)
				}
				return statusCode;

			} else if (userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise") == -1 && userAgent.indexOf("RPT") == -1) {
				// create the webtop cookie

				logger.info("Authorization request.");

				org.apache.commons.httpclient.Cookie extAuthcookie = null;
				org.apache.commons.httpclient.Cookie userIdCookie = null;

				extAuthcookie = apacheCookie(buildAuthCookie(authCookies,id));

				if (extAuthcookie!=null) {
					webtopCookieok = true;
					logger.debug("Adding session cookie to the web processor");
					webProcessor.addCookie(extAuthcookie);
				} else if (!dctmKerb) {
					logger.info("User unauthorized (no session cookie found).");
					return 401;
				}

				//if kerb, the cookies where not generated => build dummy ones.
				if (dctmKerb) {
					//TODO use the static mthd of the KerberosAuthNProcess which build user name from ticket instead.
					logger.debug("useridCookie built from kerberos ticket.");
					Iterator<Principal> i = this.credz.getCredential("krb5").getSubject().getPrincipals().iterator();
					if (!i.hasNext()) {
						logger.error("No principal found in the credential array.");
						return 401;
					}
					String userName = i.next().getName();
					if (userName.indexOf("@")!=-1) {
						userName = userName.substring(0,userName.indexOf("@"));
					}
					userIdCookie = new org.apache.commons.httpclient.Cookie();
					userIdCookie.setName("userId");
					userIdCookie.setValue(userName);
					logger.debug("useridCookie: " + userIdCookie.getValue());
				} else {
					for (int i = 0; i < authCookies.length; i++) {
						if ((authCookies[i].getName()).equals("userId")) {//Mandatory
							userIdCookie = new org.apache.commons.httpclient.Cookie();
							userIdCookie.setName("userId");
							userIdCookie.setValue(authCookies[i].getValue());
							logger.debug("useridCookie: " + userIdCookie.getValue());
							break;
						}
					}
				}

				if (userIdCookie==null) {
					logger.error("An authZ request for a unauthenticated user has been made. Exiting.");
					return 401;
				}

				if (webtopCookieok == true) {

					NameValuePair nvPairs[] = new NameValuePair[3];

					logger.debug("objectId: " + tabURL[tabURL.length - 1]);
					nvPairs[0] = new NameValuePair("objectId", tabURL[tabURL.length - 1]);

					logger.debug("dctm_docbase: " + tabURL[tabURL.length - 3]);
					nvPairs[1] = new NameValuePair("dctm_docbase",tabURL[tabURL.length - 3]);

					logger.debug("userId vaut " + userIdCookie.getValue());
					nvPairs[2] = new NameValuePair("userId", userIdCookie.getValue());

					HttpMethodBase method = webProcessor.sendRequest(null,"GET", null, nvPairs,authzServletPath+"/Authorise");

					statusCode = method.getStatusCode();

				} else {
					statusCode = HttpServletResponse.SC_UNAUTHORIZED;
				}

				if (statusCode == HttpServletResponse.SC_OK || statusCode == HttpServletResponse.SC_ACCEPTED) {
					logger.info("User authorized");
					statusCode = HttpServletResponse.SC_OK;
				} else {
					logger.info("User not authorized ");
					statusCode = HttpServletResponse.SC_UNAUTHORIZED;
				}


				return statusCode;

			} else {
				logger.info("Serving the document to a browser.");

				Cookie authWebtopcookie = buildAuthCookie(authCookies,id);
				if (authWebtopcookie==null) {
					logger.error("Authentication failed. Authorization cannot be performed. Exiting.");
					return 401;
				}
				authWebtopcookie.setDomain(webtopDomain);

				TransformURL tu = new TransformURL(webtopServletPath,authzServletPath);
				url = tu.transform(request.getMethod(), url, userAgent);
				statusCode = HttpServletResponse.SC_FOUND;
				logger.debug("Redirecting web browser toward "+url + 
						"\r\nSession cookie added to the response: " + 
						"\r\n\t\t- " + authWebtopcookie.getName() + 
						"\r\n\t\t- " + authWebtopcookie.getValue() + 
						"\r\n\t\t- " + authWebtopcookie.getDomain() + 
						"\r\n\t\t- " + authWebtopcookie.getPath() + 
						"\r\n\t\t- " + authWebtopcookie.getSecure());
				response.addCookie(authWebtopcookie);

				try {
					response.setStatus(HttpServletResponse.SC_FOUND);
					response.sendRedirect(url);
				} catch (IOException e) {
					logger.error("Exception when redirecting toward: "+url,e);
					return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
				}
			}

			return statusCode;
		} catch (Throwable t) {
			System.err.println("Exiting because of an exception : "+t.getMessage());
			logger.error("Exiting because of an exception.",t);
			return HttpServletResponse.SC_UNAUTHORIZED;
		}

	}

	private org.apache.commons.httpclient.Cookie apacheCookie(Cookie cookie) {
		if (cookie==null) {
			return null;
		}
		org.apache.commons.httpclient.Cookie ret = new org.apache.commons.httpclient.Cookie();
		ret.setName(cookie.getName());
		ret.setValue(cookie.getValue());
		ret.setDomain(cookie.getDomain());
		ret.setPath(cookie.getPath());
		ret.setSecure(cookie.getSecure());
		return ret;
	}

	private Cookie buildAuthCookie(Cookie[] cookies, String id) {
		StringTokenizer tkz = null;
		Cookie extAuthcookie = null;

		for (int i = 0; i < cookies.length; i++) {
			if ((cookies[i].getName()).equals("gsa_webtop_JSESSIONID_"+id)) {
				logger.debug("gsa_webtop_JSESSIONID_"+id+" cookie found. "+cookies[i].getValue());
				tkz = new StringTokenizer(cookies[i].getValue(), "||");
				break;
			} else {
				logger.debug("Additive Cookie: "+cookies[i].getName());
			}
		}

		if (tkz==null) {//No Auth Cookie present
			logger.info("No session cookie found.");
			if (!dctmKerb) {
				return null;
			} else {
				extAuthcookie = new Cookie("JSESSIONID","NA");
				extAuthcookie.setPath("NA");
				extAuthcookie.setDomain("NA");
				extAuthcookie.setSecure(false);
				return extAuthcookie;
			}
		}


		if (tkz.countTokens()>4) {
			extAuthcookie = new Cookie(tkz.nextToken(),tkz.nextToken());

			extAuthcookie.setPath(tkz.nextToken());

			extAuthcookie.setDomain(tkz.nextToken());

			extAuthcookie.setSecure(new Boolean(tkz.nextToken()).booleanValue());

			logger.debug("Created the session cookie: "+extAuthcookie.getName() + " ; "+extAuthcookie.getValue());

		} else { // SSO (Kerberos, SiteMinder, ...) system probably.
			logger.debug("Created the session cookie: JSESSIONID ; NA");
			extAuthcookie = new Cookie("JSESSIONID","NA");
			extAuthcookie.setPath("NA");
			extAuthcookie.setDomain("NA");
			extAuthcookie.setSecure(false);
		}
		return extAuthcookie;
	}

	public void setValveConfiguration(ValveConfiguration valveConf) {
		this.conf=valveConf;
	}

	private ValveConfiguration conf;
	
	private Credentials credz;

	public void setCredentials(Credentials creds) {
		this.credz = creds;
	}
}
