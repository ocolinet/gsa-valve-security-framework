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
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.log4j.Logger;
import org.apache.xerces.parsers.DOMParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveRepositoryConfiguration;


public class DCTMAuthorizationProcessPaul implements AuthorizationProcessImpl {
	
	private static Logger logger = null;
	private WebProcessor  webProcessor = null;
	private Header[] headers = null;
	private HttpMethodBase method = null;
	private ValveConfiguration valveConf = null;
	
	public DCTMAuthorizationProcessPaul() {
		
		logger = Logger.getLogger(DCTMAuthorizationProcessPaul.class);
		logger.info("[DCTMAUTHORIZATIONPROCESS] Authorization process dans Constructeur");
		// Set HTTP headers
		headers = new Header[2];
		
		// Set User-Agent
		headers[0] = new Header("User-Agent", "Authorization Web Processor");
		
		
		
	}
	
	public void setWebProcessor(WebProcessor webProcessor) {
		this.webProcessor = webProcessor;
	}
        
        public void setCredentials (Credentials creds) {
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                                  
        }
	
	//public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] responseCookies, String url, Properties valveConfig, String id) throws HttpException, IOException {
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] responseCookies, String url, String id) throws HttpException, IOException {
		logger.info("[DCTMAUTHORIZATIONPROCESS] Authorization process");
	
                //CLAZARO: set config
                //valveConf = ValveConfiguration.getInstance();
                //CLAZARO: end set config
        
		logger.debug("fetching configuration for " + id);
		ValveRepositoryConfiguration repositoryConfig = valveConf.getRepository(id);
	
		String httpMethod=request.getMethod();
		logger.info("httpmethod vaut "+httpMethod);
	
		String webtopAuthorizeConfFilePath =null;
	
		//3 mandatory parameters.
		String webtopServletPath = null;
		String authzServletPath = null;
		String webtopDomain = null;
	
	
		if(webtopAuthorizeConfFilePath == null) {
			webtopAuthorizeConfFilePath = repositoryConfig.getParameterValue("webtopAuthorizationConfFilePath");
			logger.info("[DCTMAUTHORIZATIONPROCESS] chemin vers fichier config " + webtopAuthorizeConfFilePath);
		}
		
		
		
		if (valveConf == null) {
			logger.error("valveConfig is null");
			return 500;
		} else {
			if (this.valveConf.getRepository(id).getParameterValue("webtopServletPath") != null) {
				webtopServletPath = this.valveConf.getRepository(id).getParameterValue("webtopServletPath");
				logger.debug("valveConfig webtopServletPath is: " + webtopServletPath);
			} else {
				return 500;
			}
			if (this.valveConf.getRepository(id).getParameterValue("authzServletPath") != null) {
				authzServletPath = this.valveConf.getRepository(id).getParameterValue("authzServletPath");
				logger.debug("valveConfig authzServletPath is: " + authzServletPath);
			} else {
				return 500;
			}
			if (this.valveConf.getRepository(id).getParameterValue("webtopDomain") != null) {
				webtopDomain = this.valveConf.getRepository(id).getParameterValue("webtopDomain");
				logger.debug("valveConfig webtopDomain is: " + webtopDomain);
			} else {
				return 500;
			}
		}
		
		UsernamePasswordCredentials credentials	= null;
		String[] tabURL = url.split("/");
		
		
		logger.info("[DCTMAUTHORIZATIONPROCESS] Authorization process from the GSA ");
		webProcessor = new WebProcessor();
		logger.info("[DCTMAUTHORIZATIONPROCESS] Après web processor");
		

		Cookie[] requestCookies = null;
		Cookie[] cookies = null;
		//Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		int length = 0;
		
		String userAgent=request.getHeader("User-Agent");
		logger.info("[DCTMAUTHORIZATIONPROCESS] userAgent vaut "+userAgent);
		
		//Cache request cookies
		///Traitement générique des cookies
		
                //CLAZARO: add support to authCookies
                requestCookies = responseCookies;
                
		logger.info("[DCTMAUTHORIZATIONPROCESS] Après recup des cookies de la request");
		
		boolean webtopCookieok=false;
		

		//appel a TransformUrl : cas du crawling = appel à la servlet d'accès aux docs et redirection sur le document 
		if((userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise")!=-1)){	
			logger.info("[DCTMAUTHORIZATIONPROCESS] cas CRAWLING or AUTHENTICATION RULE");
			//TransformURL tu = new TransformURL(webtopServletPath,authzServletPath);
			//url = tu.transform(request.getMethod(), url, userAgent);
			url = TransformURLOld.transform(request.getMethod(),url,userAgent);
			logger.info("[DCTMAUTHORIZATIONPROCESS] url transformee vaut "+url);
			statusCode = HttpServletResponse.SC_OK;
			logger.info("[DCTMAUTHORIZATIONPROCESS] apres transformation d'url status code vaut ok");
			response.sendRedirect(url);
			return statusCode;
			
			///cas authorization	
		}else if(userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise")==-1 && userAgent.indexOf("RPT")==-1) {	 
			// create the webtop cookie
			
			logger.info("[DCTMAUTHORIZATIONPROCESS] cas Authorization");
//			Protection
			if (requestCookies != null) length = requestCookies.length;
			
			// Protection
			if (responseCookies != null) {
				
				
				// Instantiate cookie array
				cookies = new Cookie[length + responseCookies.length];
				logger.info("[DCTMAUTHORIZATIONPROCESS] Après recup des cookies de la response");
				// Copy request cookies
				for (int i = 0; i < length; i++) {
					cookies[i] = requestCookies[i];
				}
				logger.info("[DCTMAUTHORIZATIONPROCESS] Après insertion des cookies de la request dans le tableau Cookies");
				// Copy response cookies
				for (int i = 0; i < responseCookies.length; i++) {
					cookies[i + length] = responseCookies[i];
				}
				
				logger.info("[DCTMAUTHORIZATIONPROCESS] Après insertion des cookies de la response dans le tableau Cookies");
				
				
			} else {
				// Copy reference
				cookies = requestCookies;
				
			}
			

			logger.info("[DCTMAUTHORIZATIONPROCESS] Avant initialisation des cookies exAuth, userId et userDocBase");
			org.apache.commons.httpclient.Cookie extAuthcookie = null;
			org.apache.commons.httpclient.Cookie userIdCookie = null;
			org.apache.commons.httpclient.Cookie userDocBaseCookie = null;
			// Parse cookies
			logger.info("[DCTMAUTHORIZATIONPROCESS] Avant parsage des cookies");
			for (int i = 0; i < cookies.length; i++) {
				logger.info("[DCTMAUTHORIZATIONPROCESS] cookies trouvés");
				// Look for the external authentication cookies
				if ((cookies[i].getName()).equals("gsa_webtop_JSESSIONID")){
					
					webtopCookieok=true;
					logger.info("[DCTMAUTHORIZATIONPROCESS] gsa_webtop_cookie trouvé");
					// Instantiate cookie
					extAuthcookie = new org.apache.commons.httpclient.Cookie();
					
					StringTokenizer tkz = new StringTokenizer(cookies[i].getValue(), "||");
					
					// Read authentication cookie value
					extAuthcookie.setName(tkz.nextToken()); 
					extAuthcookie.setValue(tkz.nextToken());
					extAuthcookie.setPath(tkz.nextToken());
					//tester avec setPath à /
					extAuthcookie.setDomain(tkz.nextToken());
					extAuthcookie.setSecure(new Boolean(tkz.nextToken()).booleanValue());
					
					// Add cookie
					/// Déplacé dans Authorize
					webProcessor.addCookie(extAuthcookie);
					logger.info("[DCTMAUTHORIZATIONPROCESS] cookie ajouté à web process");
					// Log info
					if (logger.isDebugEnabled()) logger.info("Un-wrapping HTTP request cookie: " + extAuthcookie.getName() + " : " + extAuthcookie.getValue() 
							+ " : " + extAuthcookie.getPath() + " : " + extAuthcookie.getDomain() + " : " + extAuthcookie.getSecure());
					
				}
				
				if ((cookies[i].getName()).equals("userId")){
					userIdCookie = new org.apache.commons.httpclient.Cookie();
					userIdCookie.setValue(cookies[i].getValue());
					if (logger.isDebugEnabled()) logger.info("useridCookie vaut "+userIdCookie.getValue());
				}
				
				
				if ((cookies[i].getName()).equals("userDocBase")){
					userDocBaseCookie = new org.apache.commons.httpclient.Cookie();
					userDocBaseCookie.setValue(cookies[i].getValue());
					if (logger.isDebugEnabled()) logger.info("userDocBaseCookie vaut "+userDocBaseCookie.getValue());
				}
				
			}
			///fin traitement générique des cookies
			logger.info("[DCTMAUTHORIZATIONPROCESS] cookie ajouté à web process");
			// Log info
//			if (logger.isDebugEnabled()) logger.info("Un-wrapping HTTP request cookie: " + extAuthcookie.getName() + ":" + extAuthcookie.getValue() 
//					+ ":" + extAuthcookie.getPath() + ":" + extAuthcookie.getDomain() + ":" + extAuthcookie.getSecure());
			
			try {
				if (webtopCookieok==true){
					logger.info("[DCTMAUTHORIZATIONPROCESS] parsage du fichier xml " + webtopAuthorizeConfFilePath);
					DOMParser parser = new DOMParser();
					logger.info("[DCTMAUTHORIZATIONPROCESS] after DOMParser");
					///parser.parse(path_to_authorise_file);
					logger.info("[DCTMAUTHORIZATIONPROCESS] before Parse");
					parser.parse(webtopAuthorizeConfFilePath);
					logger.info("[DCTMAUTHORIZATIONPROCESS] after Parse");
					logger.info("[DCTMAUTHORIZATIONPROCESS] parsage du fichier xml " + webtopAuthorizeConfFilePath);
					Document document = parser.getDocument();
					logger.info("[DCTMAUTHORIZATIONPROCESS] after getDocument");
					NodeList nodes = document.getChildNodes().item(0).getChildNodes(),nodes2;
					Element e = null;
					Vector vector = new Vector();
					String type = null;
					String urltofetch = null;
					for(int i = 1 ; i< nodes.getLength(); i++){
						if(nodes.item(i).getNodeType() == Node.ELEMENT_NODE){
							e = (Element)nodes.item(i);
							if(e.getNodeName().equalsIgnoreCase("request")){
								
								logger.info("[DCTMAUTHORIZATIONPROCESS] nom de l'élément = "+e.getNodeName());
								i++;
								Hashtable<String, Header> hashtable = new Hashtable<String, Header>(0);
								Vector<NameValuePair> vector1 = new Vector<NameValuePair>(0);
								
								Header header;
								for(Enumeration enumeration = vector.elements(); enumeration.hasMoreElements(); hashtable.put(header.getName(), header))
									header = (Header)enumeration.nextElement();
								
								
								nodes2 = e.getChildNodes();
								Element element1 = null;
								
								for(int j = 0; j< nodes2.getLength();j++){
									if(nodes2.item(j).getNodeType() == Node.ELEMENT_NODE){
										element1 = (Element)nodes2.item(j);
										if(nodes2.item(j).getNodeName().equalsIgnoreCase("type"))
											type = nodes2.item(j).getFirstChild().getNodeValue();
										
										if(nodes2.item(j).getNodeName().equalsIgnoreCase("URL"))
											urltofetch = nodes2.item(j).getFirstChild().getNodeValue();
										if(nodes2.item(j).getNodeName().equalsIgnoreCase("header")){
											Header header1 = new Header(element1.getAttribute("name"), element1.getAttribute("value"));
											hashtable.put(header1.getName(), header1);
										}
										if(nodes2.item(j).getNodeName().equalsIgnoreCase("parameter"))
											vector1.add(new NameValuePair(element1.getAttribute("name"), element1.getAttribute("value")));
									}
									
								}
								
								logger.info("[DCTMAUTHORIZATIONPROCESS] NEW REQUEST");
								logger.info("[DCTMAUTHORIZATIONPROCESS] Url to fetch " + urltofetch);
								logger.info("[DCTMAUTHORIZATIONPROCESS] Request type " + type);
								logger.info("[DCTMAUTHORIZATIONPROCESS] Parameters " );
								Enumeration enumeration1 = vector1.elements();
								NameValuePair anamevaluepair1[] = new NameValuePair[vector1.size()+3];
								logger.info("\t[DCTMAUTHORIZATIONPROCESS] objectId vaut " + tabURL[tabURL.length-1]);
								anamevaluepair1 [hashtable.size()] = new NameValuePair("objectId",tabURL[tabURL.length-1]);
								///anamevaluepair1 [hashtable.size()+1] = new NameValuePair("dctm_docbase",docbase);
								logger.info("\t[DCTMAUTHORIZATIONPROCESS] dctm_docbase vaut " + tabURL[tabURL.length-3]);
								anamevaluepair1 [hashtable.size()+1] = new NameValuePair("dctm_docbase",tabURL[tabURL.length-3]);
								///anamevaluepair1 [hashtable.size()+2] = new NameValuePair("userId",cookieUserId.getValue());
								logger.info("\t[DCTMAUTHORIZATIONPROCESS] userId vaut " + userIdCookie.getValue());
								anamevaluepair1 [hashtable.size()+2] = new NameValuePair("userId",userIdCookie.getValue());
								logger.info("\t[DCTMAUTHORIZATIONPROCESS] " + anamevaluepair1[hashtable.size()].getName() + " : " + anamevaluepair1[hashtable.size()].getValue());
								logger.info("\t[DCTMAUTHORIZATIONPROCESS] " + anamevaluepair1[hashtable.size()+1].getName() + " : " + anamevaluepair1[hashtable.size()+1].getValue());
								logger.info("\t[DCTMAUTHORIZATIONPROCESS] " + anamevaluepair1[hashtable.size()+2].getName() + " : " + anamevaluepair1[hashtable.size()+2].getValue());
								for(int l = 0; enumeration1.hasMoreElements(); l++){
									anamevaluepair1[l] = (NameValuePair)enumeration1.nextElement();
									logger.info("\t[DCTMAUTHORIZATIONPROCESS] " + anamevaluepair1[l].getName() + " : " + anamevaluepair1[l].getValue());
								}
								
								enumeration1 = hashtable.elements();
								Header aheader1[] = new Header[hashtable.size()];
								logger.info("[DCTMAUTHORIZATIONPROCESS] headers " );
								
								for(int i1 = 0; enumeration1.hasMoreElements(); i1++){
									aheader1[i1] = (Header)enumeration1.nextElement();
									logger.info("\t[DCTMAUTHORIZATIONPROCESS] " +  aheader1[i1].getName() + " : " + aheader1[i1].getValue());
								}
								
								method = webProcessor.sendRequest(credentials,type,aheader1,anamevaluepair1,urltofetch);
								
							}
						}
						logger.info("[DCTMAUTHORIZATIONPROCESS] Response for the authorisation received for the URL : " + url);
						statusCode = method.getStatusCode();
					}
				}else{
					statusCode = HttpServletResponse.SC_UNAUTHORIZED;
				}
				
				if(statusCode == HttpServletResponse.SC_UNAUTHORIZED){
					logger.info("[DCTMAUTHORIZATIONPROCESS] User not authorized ");
					statusCode = HttpServletResponse.SC_UNAUTHORIZED;
				}else{
					logger.info("[DCTMAUTHORIZATIONPROCESS] User authorized");
					statusCode = HttpServletResponse.SC_OK;
				}
				return statusCode;
			} catch (SAXException e1) {
				logger.error(e1.getMessage());
			} catch (IOException e1) {
				logger.error(e1.getMessage());
			}catch (Exception e){
				e.printStackTrace();
			}
			
			return HttpServletResponse.SC_UNAUTHORIZED;
			//cas de la règle d'authentification (paramétrage de l'administration du gsa)
		}else{	
			logger.info("[DCTMAUTHORIZATIONPROCESS] cas clic sur un lien");
			
			///Protection
			if (requestCookies != null) length = requestCookies.length;
			
			// Protection
			if (responseCookies != null) {
				
				// Instantiate cookie array
				cookies = new Cookie[length + responseCookies.length];
				
				logger.info("[DCTMAUTHORIZATIONPROCESS] Après recup des cookies de la response");
				
				// Copy request cookies
				for (int i = 0; i < length; i++) {
					cookies[i] = requestCookies[i];
				}
				
				logger.info("[DCTMAUTHORIZATIONPROCESS] Après insertion des cookies de la request dans le tableau Cookies");
				
				
				// Copy response cookies
				for (int i = 0; i < responseCookies.length; i++) {
					cookies[i + length] = responseCookies[i];
				}
				
				logger.info("[DCTMAUTHORIZATIONPROCESS] Après insertion des cookies de la response dans le tableau Cookies");
				
				
			} else {
				
				// Copy reference
				cookies = requestCookies;
				
			}
			
			logger.info("[DCTMAUTHORIZATIONPROCESS] Avant logger set Level ");
			// Set logger level
			//logger.setLevel(Level.WARN);
			logger.info("[DCTMAUTHORIZATIONPROCESS] Avant initialisation des cookies exAuth, userId et userDocBase");
			
			Cookie authWebtopcookie = null;
			// Parse cookies
			logger.info("[DCTMAUTHORIZATIONPROCESS] Avant parsage des cookies");
			
			for (int i = 0; i < cookies.length; i++) {
				logger.info("[DCTMAUTHORIZATIONPROCESS] cookies trouvés");
				
				// Look for the external authentication cookies
				if ((cookies[i].getName()).startsWith("gsa_webtop_")){
					
					
					
					
					logger.info("[DCTMAUTHORIZATIONPROCESS] gsa_webtop_cookie trouvé");
					// Instantiate cookie
					
					StringTokenizer tkz = new StringTokenizer(cookies[i].getValue(), "||");
					authWebtopcookie = new Cookie(tkz.nextToken(),tkz.nextToken());
					// Read authentication cookie value
				
					///authWebtopcookie.setPath(request.getAttribute("authCookiePath").toString());
					String path=tkz.nextToken();
					logger.info("[DCTMAUTHORIZATIONPROCESS] path vaut "+path);
					authWebtopcookie.setPath(path);
					
					
					tkz.nextToken();
					///authWebtopcookie.setDomain(request.getAttribute("authCookieDomain").toString());
					logger.info("[DCTMAUTHORIZATIONPROCESS] domain vaut "+webtopDomain);
					authWebtopcookie.setDomain(webtopDomain);
			
					
					
					authWebtopcookie.setSecure(new Boolean(tkz.nextToken()).booleanValue());
					
					// Add cookie
					/// Déplacé dans Authorize
					
					logger.info("[DCTMAUTHORIZATIONPROCESS] cookie ajouté à web process");
					// Log info
					if (logger.isDebugEnabled()) logger.info("Un-wrapping HTTP request cookie:" + authWebtopcookie.getName() + ":" + authWebtopcookie.getValue() 
							+ ":" + authWebtopcookie.getPath() + ":" + authWebtopcookie.getDomain() + ":" + authWebtopcookie.getSecure());
					
				}
				
				
			}
			///fin traitement des cookies
//			
			
			
			//TransformURL tu = new TransformURL(webtopServletPath,authzServletPath);
			//url = tu.transform(request.getMethod(), url, userAgent);
			url = TransformURLOld.transform(request.getMethod(),url,userAgent);
			logger.info("[DCTMAUTHORIZATIONPROCESS] url transformee vaut "+url);
			statusCode = HttpServletResponse.SC_OK;
			logger.info("[DCTMAUTHORIZATIONPROCESS] apres transformation d'url status code vaut ok");
			response.addCookie(authWebtopcookie);
			response.sendRedirect(url);
			return statusCode;
			
		}		
		
	}
	
}
