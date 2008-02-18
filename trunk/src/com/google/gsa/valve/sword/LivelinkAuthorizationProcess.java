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
import java.util.Date;
import java.util.StringTokenizer;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.log4j.Logger;

import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.opentext.api.*;

import java.net.URL;

public class LivelinkAuthorizationProcess implements AuthorizationProcessImpl {
	
	private static Logger logger;
	private static ValveConfiguration conf;
        
        public void setCredentials (Credentials creds) {
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.conf = valveConf;
                                  
        }
	
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {	
		
                //CLAZARO: set config
                //conf = ValveConfiguration.getInstance();
                //CLAZARO: end set config
                
                if (logger == null) {
			logger = Logger.getLogger(this.getClass().getName());
		}
		
		if (conf == null) {
			logger.error("valveConfig is null. Exiting");
			return 401;
		}
		
		logger.info("[LIVELINKAUTHORIZATIONPROCESS] Authorization process from the GSA ");
		logger.info("[LIVELINKAUTHORIZATIONPROCESS] url to process : " + url);
		
		Cookie[] requestCookies = null;
		Cookie[] cookies = null;
		//Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		int length = 0;
		String userAgent=request.getHeader("User-Agent");
		//Cache request cookies
		///Traitement générique des cookies
		
        	//CLAZARO: add support to authCookies
                requestCookies = authCookies;
		
		URL myUrl=new URL(url);
		
		String myQuery=myUrl.getQuery();
		logger.info("[LIVELINKAUTHORIZATIONPROCESS] Query: "+myQuery);
		String tabParams[]=myQuery.split("&");
		logger.info("[LIVELINKAUTHORIZATIONPROCESS] Creating a NVPair with size : " + tabParams.length);
		NameValuePair theNVPair[] = new NameValuePair[tabParams.length];
		String tabSlices[];
		String objID="";
		int x=0;
		int intID=0;
		boolean found = false;
		for(x=0;x<tabParams.length;x++){
			logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Splitting " + tabParams[x] + " with '='");
			tabSlices=tabParams[x].split("=");
			theNVPair[x] = new NameValuePair(tabSlices[0],tabSlices[1]);
			logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Putting " + tabSlices[0] + " and " + tabSlices[1] + " in the NVPair " + x);
			if(tabParams[x].toLowerCase().startsWith("objid")){
				found = true;
				objID=tabSlices[1];
				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] objID vaut "+objID);
			}
		}
		if (found == false) {
			for(x=0;x<tabParams.length;x++){
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Splitting " + tabParams[x] + " with '='");
				tabSlices=tabParams[x].split("=");
				theNVPair[x] = new NameValuePair(tabSlices[0],tabSlices[1]);
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Putting " + tabSlices[0] + " and " + tabSlices[1] + " in the NVPair " + x);
				if(tabParams[x].toLowerCase().startsWith("nodeid")){
					found = true;
					objID=tabSlices[1];
					logger.info("[LIVELINKAUTHORIZATIONPROCESS] objID : "+objID);
				}
			}
		}
		
		intID=Integer.parseInt(objID.trim());
		
		
		Cookie[] responseCookies = null;

		if (requestCookies != null) length = requestCookies.length;
		
		// Protection
		if (responseCookies != null) {
			
			// Instantiate cookie array
			cookies = new Cookie[length + responseCookies.length];
			
			// Copy request cookies
			for (int i = 0; i < length; i++) {
				cookies[i] = requestCookies[i];
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] requestcookie " + requestCookies[i].getName());
			}
			
			// Copy response cookies
			for (int i = 0; i < responseCookies.length; i++) {
				cookies[i + length] = responseCookies[i];
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] responsecookie " + responseCookies[i].getName());
			}
			
		} else {
			
			// Copy reference
			cookies = requestCookies;
			
		}
		
		if(userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise")==-1 && userAgent.indexOf("RPT")==-1) {
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] CAS : AUTORISATION");
			
			org.apache.commons.httpclient.Cookie extAuthcookie = null;
			
			// Parse cookies
			
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] Avant parsage des cookies");
			for (int i = 0; i < cookies.length; i++) {
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] cookies trouvés");
				// Look for the external authentication cookies
				if ((cookies[i].getName()).equals("gsa_livelink_LLCookie_"+id)){
					
					
					logger.info("[LIVELINKAUTHORIZATIONPROCESS] gsa_livelink_cookie trouvé");
					// Instantiate cookie
					extAuthcookie = new org.apache.commons.httpclient.Cookie();
					
					StringTokenizer tkz = new StringTokenizer(cookies[i].getValue(), "||");
					
					extAuthcookie.setName(tkz.nextToken()); 
					extAuthcookie.setValue(tkz.nextToken());
					
//					Read authentication cookie value
					extAuthcookie.setPath(conf.getAuthCookiePath());
					extAuthcookie.setDomain(conf.getAuthCookieDomain());
					extAuthcookie.setSecure(new Boolean(tkz.nextToken()).booleanValue());
				}
				
			}
			///fin traitement générique des cookies
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] cookie ajouté à web process");
			// Log info
			if (logger.isDebugEnabled()) logger.info("[LIVELINKAUTHORIZATIONPROCESS] Un-wrapping HTTP request cookie: " + extAuthcookie.getName() + ":" + extAuthcookie.getValue() 
					+ ":" + extAuthcookie.getPath() + ":" + extAuthcookie.getDomain() + ":" + extAuthcookie.getSecure());
			
			
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] extAuthCookie vaut "+extAuthcookie);
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] intID vaut "+intID);
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] myUrl vaut "+myUrl);
			
			statusCode=checkUser(extAuthcookie,intID,myUrl, id);
			
			return statusCode;
		}else {
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] CASE : CRAWLING o SERVING for : "+objID);
			
			
			org.apache.commons.httpclient.Cookie extAuthcookie = null;
			
			if (null==(extAuthcookie=unWrappCook(cookies,extAuthcookie,id))) {
				return 401;
			}
			
//			UsernamePasswordCredentials credentials=null;
//			Header aheader1[] = new Header[0];
			HttpMethodBase wpResponse = null;

			WebProcessor webProcessor = new WebProcessor();
			webProcessor.addCookie(extAuthcookie);
			String targ = myUrl.getProtocol()+"://"+myUrl.getHost()+":"+(myUrl.getPort()==-1?80:myUrl.getPort())+myUrl.getPath();
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] CAS CRAWLING "+ objID +" ; redirecting to "+targ);
			if (logger.isDebugEnabled()) {
				for (int i=0;i<theNVPair.length ; i++) {
					logger.debug("[LIVELINKAUTHORIZATIONPROCESS] "+ theNVPair[i].getName() +" ; "+theNVPair[i].getValue());
				}
			}
			
			try {
				wpResponse = webProcessor.sendRequest(null,"GET",null,theNVPair,targ);
				statusCode = wpResponse.getStatusCode();
				logger.info("Got "+statusCode+" status code from Livelink server.");
			} catch (Exception e) {
				logger.error("Exception while accessing target address.",e);
			}
			
			webProcessor.clearCookies();
			webProcessor = null;
			
			String larep=wpResponse.getResponseBodyAsString();
			logger.debug("Is response null? "+larep==null);
			String contentType="";
			String stgContentLength="";
			int contentLength=0;
			contentType = wpResponse.getResponseHeader("Content-Type").getValue();
			logger.debug("[LIVELINKAUTHORIZATIONPROCESS] contentType de "+objID+" vaut "+contentType);
			Header hd=wpResponse.getResponseHeader("Content-Length");
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] stgContentLength==null : "+(hd==null));
			if (hd==null) {
				try {
					stgContentLength=Integer.toString(wpResponse.getResponseBody().length);
				} catch (NullPointerException e) {
					logger.error("Response body is null. Aborting...");
					response.sendError(500,"The document you are asking for is currently unavailable.");
					return 500;
				}
				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Emergency mode for content length retrieval ("+stgContentLength+").");
			} else {
				stgContentLength=hd.getValue();
			}
			String path=wpResponse.getPath();
			String [] tabpath=path.split("/");
			int longueurtab=tabpath.length;
			
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] array length :  "+longueurtab);
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] path : "+path);
			String lenom=tabpath[longueurtab-1];
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] name : "+lenom);
			contentLength=Integer.parseInt(stgContentLength.trim());
			
			response.setContentType(contentType);
			response.setContentLength(contentLength);
			response.setHeader("Content-Disposition","inline; filename=" + lenom);
			
			String error = LivelinkAuthorizationProcess.conf.getRepository(id).getParameterValue("livelinkErrorPage");
			
			if (error==null) {
				error = "<title>Livelink - Error</title>";
			}
			
			if (!contentType.startsWith("text/html") || error.toLowerCase().indexOf(larep.toLowerCase())==-1) {
				try {
					ServletOutputStream srvOut = response.getOutputStream();
					srvOut.print(larep);
					srvOut.flush();
					srvOut.close();
				} catch (Exception e) {
					logger.error("Exception thrown while writing on stream. Connection may have been reseted by peer.");
					statusCode = HttpServletResponse.SC_SERVICE_UNAVAILABLE;
				}
			} else {
				logger.error("Invalid response: "+larep);
				statusCode = 404;
			}
			
			return statusCode;
		}
	}
	
	
	private int checkUser (org.apache.commons.httpclient.Cookie authCook, int id, URL myURL, String confID){
		
		logger.info("[LIVELINKAUTHORIZATIONPROCESS] CHECKUSER");
		
		LLSession mySession = null;
		///EasyLAPI.Session mySession = null;
		int status;
		//LLValue rights = ( new LLValue() ).setAssocNotSet();
		
		LLValue config = ( new LLValue() ).setAssocNotSet();
		LLValue  objectInfo = ( new LLValue() ).setAssocNotSet();
		
		config.add( "HTTPS", LLValue.LL_TRUE);
		config.add( "VerifyServer", LLValue.LL_FALSE );
		config.add("DomainName",authCook.getDomain());
		
		
		try{
			int port = Integer.parseInt(LivelinkAuthorizationProcess.conf.getRepository(confID).getParameterValue("llAPIPort"));
			logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Trying to open session : " + myURL.getHost() + " ; port : " +  port + " : authCookie" + authCook.getValue().trim() + " ; domain : " + authCook.getDomain() + " ; path : " + authCook.getPath());
			mySession=new LLSession(myURL.getHost(), port, authCook.getValue().trim());
		}catch (Exception e){
			logger.error("[LIVELINKAUTHORIZATIONPROCESS] Exception... Aborting",e);
		}
		
		String myhost=mySession.getHost();
		logger.info("[LIVELINKAUTHORIZATIONPROCESS] myhost "+myhost);
		String mymess=mySession.getErrMsg();
		logger.info("[LIVELINKAUTHORIZATIONPROCESS] mymess "+mymess);
		
		
		try{
			LAPI_DOCUMENTS documents = new LAPI_DOCUMENTS(mySession);
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] documents vaut " + LAPI_DOCUMENTS.STATUS_INPROCESS);
			if(documents.GetObjectInfo(0,id,objectInfo)!= 0){
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] User is not authorised for the doc with id: " + id);
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Status Code: " + mySession.getStatus());
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Api Error: " + mySession.getApiError());
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Error Message: " + mySession.getErrMsg());
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Status Message: " + mySession.getStatusMessage());
				
				status=HttpServletResponse.SC_UNAUTHORIZED;
			}else{
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] User is authorised for the doc with id: " + id);
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Status Code: " + mySession.getStatus());
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Api Error: " + mySession.getApiError());
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Error Message: " + mySession.getErrMsg());
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] Status Message: " + mySession.getStatusMessage());
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] "+objectInfo.toString("Name"));
				status=HttpServletResponse.SC_OK;
			}
			
			
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] status : "+status);
			return status;
			
			
			
		}catch (Exception e){
			
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] Exception "+e.getMessage());
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] Status Code: " + mySession.getStatus());
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] Api Error: " + mySession.getApiError());
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] Error Message: " + mySession.getErrMsg());
			logger.info("[LIVELINKAUTHORIZATIONPROCESS] Status Message: " + mySession.getStatusMessage());
			
			return 401;
			
			
			
		}
		
		
		
		
		
	}
	
	private org.apache.commons.httpclient.Cookie unWrappCook(Cookie[] in, org.apache.commons.httpclient.Cookie out, String id) {
		for (int i = 0; i < in.length; i++) {
			
//			Look for the external authentication cookies
			if ((in[i].getName()).equals("gsa_livelink_LLCookie_"+id)){
				
				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] AuthN cookie Ok.");
				String garb = null;
				StringTokenizer tkz = new StringTokenizer(in[i].getValue(), "||");
				out = new org.apache.commons.httpclient.Cookie();
				garb = tkz.nextToken();
				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Setting name "+garb);
				out.setName(garb); 
				garb = tkz.nextToken();
//				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Setting value "+garb);
				out.setValue(garb);
				
				// Read authentication cookie value
				garb = tkz.nextToken();
				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Setting path "+garb);
				out.setPath(garb);
				garb = tkz.nextToken();
				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Setting domain "+garb);
				out.setDomain(garb);
				garb = tkz.nextToken();
				logger.debug("[LIVELINKAUTHORIZATIONPROCESS] Setting secure "+garb);
				out.setSecure(new Boolean(garb).booleanValue());
				out.setExpiryDate(new Date(System.currentTimeMillis()+1000000L));
				
				logger.info("[LIVELINKAUTHORIZATIONPROCESS] API Cookie set: " + out.getName());
				break;
			}
		}
		
		return out;
	}	
	
	
}

