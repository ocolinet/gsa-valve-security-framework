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
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.catalina.connector.Response;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.log4j.Logger;
import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;

public class DCTMAuthorizationProcess implements AuthorizationProcessImpl {
	
	private static Logger logger = null;
	private WebProcessor webProcessor = null;
	private Header[] headers = null;
	private HttpMethodBase method = null;
	
	public DCTMAuthorizationProcess() {
		
		// Set HTTP headers
		headers = new Header[2];
		
		// Set User-Agent
		headers[0] = new Header("User-Agent", "Authorization Web Processor");
		
		logger = Logger.getLogger(DCTMAuthorizationProcess.class);
		
	}
	
	public void setWebProcessor(WebProcessor webProcessor) {
		this.webProcessor = webProcessor;
	}
        
        public void setCredentials (Credentials creds) {
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.conf = valveConf;
                                  
        }
	
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {
		//JPN. Change 17/10/07 - Remove AuthZ config file. Two parameters instead:
		//									- webtopSerlvetPath
		//									- authzSerlvetPath
		
		
		logger.info("[DCTMAUTHORIZATIONPROCESS] Authorization process");
                
                //CLAZARO: set config
                //conf = ValveConfiguration.getInstance();
                //CLAZARO: end set config
		
		String httpMethod = request.getMethod();
		logger.info("httpmethod: " + httpMethod);
		
		//3 mandatory parameters.
		String webtopServletPath = null;
		String authzServletPath = null;
		String webtopDomain = null;
		
		if (conf == null) {
			logger.error("valveConfig is null");
			return 500;
		} else {
			if (this.conf.getRepository(id).getParameterValue("webtopServletPath") != null) {
				webtopServletPath = this.conf.getRepository(id).getParameterValue("webtopServletPath");
				logger.debug("valveConfig webtopServletPath is: " + webtopServletPath);
			} else {
				return 500;
			}
			if (this.conf.getRepository(id).getParameterValue("authzServletPath") != null) {
				authzServletPath = this.conf.getRepository(id).getParameterValue("authzServletPath");
				logger.debug("valveConfig authzServletPath is: " + authzServletPath);
			} else {
				return 500;
			}
			if (this.conf.getRepository(id).getParameterValue("webtopDomain") != null) {
				webtopDomain = this.conf.getRepository(id).getParameterValue("webtopDomain");
				logger.debug("valveConfig webtopDomain is: " + webtopDomain);
			} else {
				return 500;
			}
		}
		
		UsernamePasswordCredentials credentials = null;
		String[] tabURL = url.split("/");
		
		webProcessor = new WebProcessor();
		
		Cookie[] requestCookies = null;
		Cookie[] cookies = null;
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		try {
			int length = 0;
			
			//JPN to test.
			Cookie[] responseCookies = ((Response) response).getCookies();
			
			String userAgent = request.getHeader("User-Agent");
			logger.info("[DCTMAUTHORIZATIONPROCESS] userAgent : " + userAgent);
			
			// Cache request cookies
			// /Traitement générique des cookies
                        
                        //CLAZARO: add support to authCookies
                        requestCookies = authCookies;
                    
			boolean webtopCookieok = false;
			
			// /appel a TransformUrl : cas du crawling = appel à la servlet d'accès
			// aux docs et redirection sur le document
			if ((userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise") != -1)) {//crawl
				logger.info("[DCTMAUTHORIZATIONPROCESS] CRAWLING or AUTHENTICATION RULE");
				TransformURL tu = new TransformURL(webtopServletPath,authzServletPath);
				url = tu.transform(request.getMethod(), url, userAgent);
				logger.info("[DCTMAUTHORIZATIONPROCESS] Transformed URL: " + url);
				statusCode = HttpServletResponse.SC_FOUND;
				try {
					response.sendRedirect(url);
				} catch (IOException e) {
					logger.error("IOException when directing toward: " + url,e);
				}
				return statusCode;
				
				// /cas authorization
			} else if (userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise") == -1 && userAgent.indexOf("RPT") == -1) {
				// create the webtop cookie
				
				logger.info("[DCTMAUTHORIZATIONPROCESS] Authorization request.");
				logger.info("httpmethod: " + httpMethod);
				// Protection
				if (requestCookies != null) length = requestCookies.length;
				
				// Protection
				if (responseCookies != null) {
					
					// Instantiate cookie array
					cookies = new Cookie[length + responseCookies.length];
					// Copy request cookies
					for (int i = 0; i < length; i++) {
						cookies[i] = requestCookies[i];
					}
					// Copy response cookies
					for (int i = 0; i < responseCookies.length; i++) {
						cookies[i + length] = responseCookies[i];
					}
					
				} else {
					// Copy reference
					cookies = requestCookies;
					
				}
				
				org.apache.commons.httpclient.Cookie extAuthcookie = null;
				org.apache.commons.httpclient.Cookie userIdCookie = null;
				org.apache.commons.httpclient.Cookie userDocBaseCookie = null;
				
				extAuthcookie = apacheCookie(buildAuthCookie(cookies,id));
				
				if (extAuthcookie!=null) {
					webtopCookieok = true;
					webProcessor.addCookie(extAuthcookie);
				}


				for (int i = 0; i < cookies.length; i++) {
					if ((cookies[i].getName()).equals("userId")) {//Mandatory
						userIdCookie = new org.apache.commons.httpclient.Cookie();
						userIdCookie.setValue(cookies[i].getValue());
						if (logger.isDebugEnabled())
							logger.info("useridCookie: " + userIdCookie.getValue());
					}
					
					if ((cookies[i].getName()).equals("userDocBase_"+id)) {
						userDocBaseCookie = new org.apache.commons.httpclient.Cookie();
						userDocBaseCookie.setValue(cookies[i].getValue());
						if (logger.isDebugEnabled())
							logger.info("userDocBaseCookie: " + userDocBaseCookie.getValue());
					}
				}
				
				if (userIdCookie==null) {
					logger.error("An authZ request for a unauthenticated user has been made. Exiting.");
					return 401;
				}

				logger.info("[DCTMAUTHORIZATIONPROCESS] cookie added to the web process");
				
				if (webtopCookieok == true) {
					
					NameValuePair anamevaluepair1[] = new NameValuePair[3];
					
					logger.info("\t[DCTMAUTHORIZATIONPROCESS] objectId: " + tabURL[tabURL.length - 1]);
					anamevaluepair1[0] = new NameValuePair("objectId", tabURL[tabURL.length - 1]);
					
					logger.info("\t[DCTMAUTHORIZATIONPROCESS] dctm_docbase: " + tabURL[tabURL.length - 3]);
					anamevaluepair1[1] = new NameValuePair("dctm_docbase",tabURL[tabURL.length - 3]);
					
					logger.info("\t[DCTMAUTHORIZATIONPROCESS] userId vaut " + userIdCookie.getValue());
					anamevaluepair1[2] = new NameValuePair("userId", userIdCookie.getValue());
					
					method = webProcessor.sendRequest(credentials,"GET", null, anamevaluepair1,authzServletPath+"/Authorise");
					
					statusCode = method.getStatusCode();
					
				} else {
					statusCode = HttpServletResponse.SC_UNAUTHORIZED;
				}
				
				if (statusCode == HttpServletResponse.SC_OK || statusCode == HttpServletResponse.SC_ACCEPTED) {
					logger.info("[DCTMAUTHORIZATIONPROCESS] User authorized");
					statusCode = HttpServletResponse.SC_OK;
				} else {
					logger.info("[DCTMAUTHORIZATIONPROCESS] User not authorized ");
					statusCode = HttpServletResponse.SC_UNAUTHORIZED;
				}
				return statusCode;
				
				// cas de la règle d'authentification (paramétrage de
				// l'administration du gsa)
			} else {
				logger.info("[DCTMAUTHORIZATIONPROCESS] Serving the document to a browser.");
				
				// /Protection
				if (requestCookies != null)
					length = requestCookies.length;
				
				// Protection
				if (responseCookies != null) {
					
					// Instantiate cookie array
					cookies = new Cookie[length + responseCookies.length];
					
					// Copy request cookies
					for (int i = 0; i < length; i++) {
						cookies[i] = requestCookies[i];
					}
					
					// Copy response cookies
					for (int i = 0; i < responseCookies.length; i++) {
						cookies[i + length] = responseCookies[i];
					}
					
				} else {
					
					// Copy reference
					cookies = requestCookies;
					
				}
				
				Cookie authWebtopcookie = buildAuthCookie(cookies,id);
				authWebtopcookie.setDomain(webtopDomain);
				
				TransformURL tu = new TransformURL(webtopServletPath,authzServletPath);
				url = tu.transform(request.getMethod(), url, userAgent);
				statusCode = HttpServletResponse.SC_OK;
				logger.debug("Redirecting web browser toward "+url + 
						"\nCookie added to the response: " + 
						"\n\t- " + authWebtopcookie.getName() + 
						"\n\t- " + authWebtopcookie.getValue() + 
						"\n\t- " + authWebtopcookie.getDomain() + 
						"\n\t- " + authWebtopcookie.getPath() + 
						"\n\t- " + authWebtopcookie.getSecure());
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

		for (int i = 0; i < cookies.length; i++) {
			if ((cookies[i].getName()).equals("gsa_webtop_JSESSIONID_"+id)) {
				logger.debug("gsa_webtop_JSESSIONID_"+id+" cookie found. "+cookies[i].getValue());
				tkz = new StringTokenizer(cookies[i].getValue(), "||");
				break;
			}
		}
		
		if (tkz==null) {//No Auth Cookie present
			return null;
		}

		Cookie extAuthcookie = null;
		
		if (tkz.countTokens()>4) {
			extAuthcookie = new Cookie(tkz.nextToken(),tkz.nextToken());
			
			extAuthcookie.setPath(tkz.nextToken());

			extAuthcookie.setDomain(tkz.nextToken());

			extAuthcookie.setSecure(new Boolean(tkz.nextToken()).booleanValue());
			
		} else { // SSO (Kerberos, SiteMinder, ...) system probably.
			extAuthcookie = new Cookie("JSESSIONID","NA");
			extAuthcookie.setPath("NA");
			extAuthcookie.setDomain("NA");
			extAuthcookie.setSecure(false);
		}
		return extAuthcookie;
	}

	private ValveConfiguration conf;
}
