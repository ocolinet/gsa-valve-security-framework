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
import java.io.InputStream;
import java.security.Principal;
import java.util.Date;
import java.util.Iterator;
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
import com.google.krb5.Krb5Credentials;
import com.opentext.api.*;

import java.net.URL;

public class LivelinkAuthorizationProcess implements AuthorizationProcessImpl {
	
	private Logger logger;
	private static ValveConfiguration conf;
	private boolean llKerb;
	private Credentials credz;
	
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {	
		
		if (logger == null) {
			logger = Logger.getLogger(this.getClass().getName());
		}
		
		if (conf == null) {
			logger.error("valveConfig is null. Exiting");
			return 401;
		} else {
			try 
			{
				boolean kerb = new Boolean(conf.getKrbConfig().isKerberos()).booleanValue();
				boolean additional = new Boolean(conf.getKrbConfig().isKrbAdditionalAuthN()).booleanValue();
				if (kerb && additional) {//additional without kerb makes no sense but let's let this protection
					//In this case we have to know if Dctm has its own AuthNProcess
					//or if the kerberos ticket would make it.
					String authN = LivelinkAuthorizationProcess.conf.getRepository(id).getAuthN();
					llKerb = !("com.google.gsa.valve.sword.LivelinkAuthenticationProcess".equals(authN));
				} else {
					llKerb = kerb;
				}
				
			} 
			catch (NullPointerException e)
			{
				logger.error("A mandatory configuration parameter is missing.",e);
			}
		}
		logger.info("Authorising Livelink on : " + url);

		//Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		String userAgent=request.getHeader("User-Agent");
		
		URL myUrl=new URL(url);
		
		String myQuery=myUrl.getQuery();
		logger.debug("Query: "+myQuery);
		String tabParams[]=myQuery.split("&");
		logger.debug("Creating a NVPair with size : " + tabParams.length);
		NameValuePair theNVPair[] = new NameValuePair[tabParams.length];
		String tabSlices[];
		String objID="";
		int x=0;
		int intID=0;
		boolean found = false;
		for(x=0;x<tabParams.length;x++){
			tabSlices=tabParams[x].split("=");
			theNVPair[x] = new NameValuePair(tabSlices[0],tabSlices[1]);
			if(tabParams[x].toLowerCase().startsWith("objid")){
				found = true;
				objID=tabSlices[1];
				logger.debug("objID vaut "+objID);
			}
		}
		if (found == false) {
			for(x=0;x<tabParams.length;x++){
				logger.debug("Splitting " + tabParams[x] + " with '='");
				tabSlices=tabParams[x].split("=");
				theNVPair[x] = new NameValuePair(tabSlices[0],tabSlices[1]);
				logger.debug("Putting " + tabSlices[0] + " and " + tabSlices[1] + " in the NVPair " + x);
				if(tabParams[x].toLowerCase().startsWith("nodeid")){
					found = true;
					objID=tabSlices[1];
					logger.debug("objID : "+objID);
				}
			}
		}
		
		intID=Integer.parseInt(objID.trim());

		
		if(userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise")==-1 && userAgent.indexOf("RPT")==-1) {
			logger.info("AUTHORIZATION CASE");
			
			org.apache.commons.httpclient.Cookie extAuthcookie = null;

			if (!llKerb) {
				for (int i = 0; i < authCookies.length; i++) {
					logger.debug("Cookies");
					if ((authCookies[i].getName()).equals("gsa_livelink_LLCookie_"+id)){
						logger.debug("Session cookie found");
						// Instantiate cookie
						extAuthcookie = new org.apache.commons.httpclient.Cookie();
						
						StringTokenizer tkz = new StringTokenizer(authCookies[i].getValue(), "||");
						
						extAuthcookie.setName(tkz.nextToken()); 
						extAuthcookie.setValue(tkz.nextToken());
						
	//					Read authentication cookie value
						extAuthcookie.setPath(conf.getAuthCookiePath());
						extAuthcookie.setDomain(conf.getAuthCookieDomain());
						extAuthcookie.setSecure(new Boolean(tkz.nextToken()).booleanValue());
						break;
					}
					
				}
				logger.debug("Un-wrapping HTTP request cookie: " + extAuthcookie.getName() + ":" + extAuthcookie.getValue() 
						+ ":" + extAuthcookie.getPath() + ":" + extAuthcookie.getDomain() + ":" + extAuthcookie.getSecure());
				
				if (extAuthcookie==null) {
					return 401;
				}

				logger.debug("intID = "+intID);
				logger.debug("myUrl = "+myUrl);
				
				statusCode=checkUser(extAuthcookie,intID,myUrl, id);
			} else {
				Iterator<Principal> i = this.credz.getCredential("krb5").getSubject().getPrincipals().iterator();
				if (!i.hasNext()) {
					logger.error("No principal found in the credential array.");
					return 401;
				}
				String userName = i.next().getName();
				if (userName.indexOf("@")!=-1) {
					userName = userName.substring(0,userName.indexOf("@"));
				}
				statusCode=checkUser(userName, intID,myUrl, id);
			}
			
			return statusCode;
		}else if (userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise")!=-1) {
			logger.info("CASE : CRAWLING for : "+objID);
			//For crawling, we write the result into the servlet output stream
			//as we have to parse the answered page to detect if we got the access denied page
			return answerInOutputStream(response, objID, myUrl, authCookies, theNVPair, id);
		} else {
			logger.info("CASE : Serving for : "+objID);
			String servingMode = LivelinkAuthorizationProcess.conf.getRepository(id).getParameterValue("ServingType");
			servingMode=servingMode==null?"webclient":servingMode.toLowerCase();
			servingMode = "webclient".equals(servingMode)?"webclient":"normal";
			logger.debug("Serving mode: "+servingMode);
			if ("webclient".equals(servingMode)) {
				String targ = myUrl.getProtocol()+"://"+myUrl.getHost()+":"+(myUrl.getPort()==-1?80:myUrl.getPort())+myUrl.getPath();
				if (!llKerb) {
					String cName = "gsa_livelink_LLCookie_"+id;
					for (int i=0 ; i<authCookies.length ; i++) {
						if (cName.equals(authCookies[i])) {
							logger.debug("Session cookie found");
							
							StringTokenizer tkz = new StringTokenizer(authCookies[i].getValue(), "||");
							// Instantiate cookie
							Cookie extAuthcookie = new Cookie(tkz.nextToken(),tkz.nextToken());
							
		//					Read authentication cookie value
							extAuthcookie.setPath(conf.getAuthCookiePath());
							extAuthcookie.setDomain(conf.getAuthCookieDomain());
							extAuthcookie.setSecure(new Boolean(tkz.nextToken()).booleanValue());
							response.addCookie(extAuthcookie);
							break;
						}
					}
				}
				response.sendRedirect(targ);
				return HttpServletResponse.SC_FOUND;
			} else {
				return answerInOutputStream(response, objID, myUrl, authCookies, theNVPair, id);
			}
		}
	}
	
	
	private int answerInOutputStream(HttpServletResponse response, String objID, URL myUrl, Cookie[] cookies, NameValuePair[] theNVPair, String id) throws IOException {
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		Krb5Credentials credentials = null;
		org.apache.commons.httpclient.Cookie extAuthcookie = null;			
		
		if (llKerb) {
			credentials = new Krb5Credentials ( LivelinkAuthorizationProcess.conf.getKrbConfig().getKrbconfig (), 
					LivelinkAuthorizationProcess.conf.getKrbConfig().getKrbini(), 
					credz.getCredential("krb5").getSubject());
		} else {
			if (null==(extAuthcookie=unWrappCook(cookies,extAuthcookie,id))) {
				return statusCode;
			}
		}
		
		HttpMethodBase wpResponse = null;
		WebProcessor webProcessor = new WebProcessor();
		if (extAuthcookie!=null) {
			webProcessor.addCookie(extAuthcookie);
		}
		String targ = myUrl.getProtocol()+"://"+myUrl.getHost()+":"+(myUrl.getPort()==-1?80:myUrl.getPort())+myUrl.getPath();
		if (logger.isDebugEnabled()) {
			for (int i=0;i<theNVPair.length ; i++) {
				logger.debug(""+ theNVPair[i].getName() +" ; "+theNVPair[i].getValue());
			}
		}

		String contentType="";
		String path="";
		InputStream larep= null;
		Header hd=null;
		try {
			wpResponse = webProcessor.sendRequest(credentials,"GET",null,theNVPair,targ);
			statusCode = wpResponse.getStatusCode();
			logger.debug("Got "+statusCode+" status code from Livelink server.");
			contentType = wpResponse.getResponseHeader("Content-Type").getValue();
			if (contentType==null || contentType.equals("")) {
				contentType = "application/octet-stream";
			}
			hd=wpResponse.getResponseHeader("Content-Length");
			path=wpResponse.getPath();
			larep=wpResponse.getResponseBodyAsStream();
		} catch (Exception e) {
			logger.error("Exception while accessing target address.",e);
			response.sendError(500,"The document you are asking for is currently unavailable.");
			return 500;
		}
		
		webProcessor.clearCookies();
		webProcessor = null;
		
		logger.debug("Is response null? "+larep==null);
		int contentLength=0;
		logger.debug("contentType : "+contentType);
		logger.debug("stgContentLength : "+((hd==null)?"null":contentLength));
		String stgContentLength=null;
		if (hd!=null) {
			stgContentLength=hd.getValue();
		}
		if (stgContentLength!=null) {
			contentLength=Integer.parseInt(stgContentLength.trim());
			response.setContentLength(contentLength);
		}
		String [] tabpath=path.split("/");
		int longueurtab=tabpath.length;
		
		logger.debug("array length :  "+longueurtab);
		String llAppName = myUrl.getPath().substring(1+myUrl.getPath().lastIndexOf("/"));
		logger.debug("path : "+path+" ("+llAppName+")");
		String lenom=tabpath[longueurtab-1];
		logger.debug("name : "+lenom);
		
		response.setContentType(contentType);
		if (!lenom.equals(llAppName)) {
			response.setHeader("Content-Disposition","inline; filename=" + lenom);
		}
		
		String error = LivelinkAuthorizationProcess.conf.getRepository(id).getParameterValue("livelinkErrorPage");
		
		if (error==null) {
			error = "<title>Livelink - Error</title>";
		}
		
		ServletOutputStream srvOut = null;
		try {
			srvOut = response.getOutputStream();
			byte[] b = new byte[32];
			int r = 0;
			while ((r=larep.read(b))>-1) {
				srvOut.write(b,0,r);
			}
		} catch (Exception e) {
			logger.error("Exception thrown while writing on stream. Connection may have been reset by peer.",e);
			statusCode = HttpServletResponse.SC_SERVICE_UNAVAILABLE;
		} finally {
			larep.close();
			srvOut.flush();
			srvOut.close();
		}
		
		return statusCode;
	}

	private int checkUser(String userName,
			int intID, URL myUrl, String id) {
		
		logger.info("CHECKUSER");
		
		LLSession mySession = null;
		///EasyLAPI.Session mySession = null;
		int status;
		//LLValue rights = ( new LLValue() ).setAssocNotSet();
		
		LLValue config = ( new LLValue() ).setAssocNotSet();
		LLValue  objectInfo = ( new LLValue() ).setAssocNotSet();
		
		config.add( "HTTPS", LLValue.LL_TRUE);
		config.add( "VerifyServer", LLValue.LL_FALSE );
		
		
		try{
			String su = LivelinkAuthorizationProcess.conf.getRepository(id).getParameterValue("SuperUser");
			String sup = LivelinkAuthorizationProcess.conf.getRepository(id).getParameterValue("SUPassword");
			String db = LivelinkAuthorizationProcess.conf.getRepository(id).getParameterValue("LLDBName");
			int port = Integer.parseInt(LivelinkAuthorizationProcess.conf.getRepository(id).getParameterValue("llAPIPort"));
			logger.debug("Trying to open session : " + myUrl.getHost() + " ; port : " +  port + " : su" + su);
			mySession=new LLSession(myUrl.getHost(), port, db, su,sup,null);
			mySession.ImpersonateUser(userName);
		}catch (Exception e){
			logger.error("Exception... Aborting",e);
		}
		
		String myhost=mySession.getHost();
		logger.debug("myhost "+myhost);
		String mymess=mySession.getErrMsg();
		logger.debug("mymess "+mymess);
		
		
		try{
			LAPI_DOCUMENTS documents = new LAPI_DOCUMENTS(mySession);
			logger.debug("documents : " + LAPI_DOCUMENTS.STATUS_INPROCESS);
			if(documents.GetObjectInfo(0,intID,objectInfo)!= 0){
				logger.info("User is not authorised for the doc with id: " + id);
				logger.debug("Status Code: " + mySession.getStatus());
				logger.debug("Api Error: " + mySession.getApiError());
				logger.debug("Error Message: " + mySession.getErrMsg());
				logger.debug("Status Message: " + mySession.getStatusMessage());
				
				status=HttpServletResponse.SC_UNAUTHORIZED;
			}else{
				logger.info("User is authorised for the doc with id: " + id);
				logger.debug("Status Code: " + mySession.getStatus());
				logger.debug("Api Error: " + mySession.getApiError());
				logger.debug("Error Message: " + mySession.getErrMsg());
				logger.debug("Status Message: " + mySession.getStatusMessage());
				logger.debug(""+objectInfo.toString("Name"));
				status=HttpServletResponse.SC_OK;
			}
			
			
			logger.info("status : "+status);
			return status;
			
			
			
		}catch (Exception e){
			
			logger.warn("Exception "+e.getMessage());
			logger.warn("Status Code: " + mySession.getStatus());
			logger.warn("Api Error: " + mySession.getApiError());
			logger.warn("Error Message: " + mySession.getErrMsg());
			logger.warn("Status Message: " + mySession.getStatusMessage());
			
			return 401;
		}	
	}

	private int checkUser (org.apache.commons.httpclient.Cookie authCook, int id, URL myURL, String confID){
		
		logger.info("CHECKUSER");
		
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
			logger.debug("Trying to open session : " + myURL.getHost() + " ; port : " +  port + " : authCookie" + authCook.getValue().trim() + " ; domain : " + authCook.getDomain() + " ; path : " + authCook.getPath());
			mySession=new LLSession(myURL.getHost(), port, authCook.getValue().trim());
		}catch (Exception e){
			logger.error("Exception... Aborting",e);
		}
		
		String myhost=mySession.getHost();
		logger.info("myhost "+myhost);
		String mymess=mySession.getErrMsg();
		logger.info("mymess "+mymess);
		
		
		try{
			LAPI_DOCUMENTS documents = new LAPI_DOCUMENTS(mySession);
			logger.info("documents vaut " + LAPI_DOCUMENTS.STATUS_INPROCESS);
			if(documents.GetObjectInfo(0,id,objectInfo)!= 0){
				logger.info("User is not authorised for the doc with id: " + id);
				logger.info("Status Code: " + mySession.getStatus());
				logger.info("Api Error: " + mySession.getApiError());
				logger.info("Error Message: " + mySession.getErrMsg());
				logger.info("Status Message: " + mySession.getStatusMessage());
				
				status=HttpServletResponse.SC_UNAUTHORIZED;
			}else{
				logger.info("User is authorised for the doc with id: " + id);
				logger.info("Status Code: " + mySession.getStatus());
				logger.info("Api Error: " + mySession.getApiError());
				logger.info("Error Message: " + mySession.getErrMsg());
				logger.info("Status Message: " + mySession.getStatusMessage());
				logger.info(""+objectInfo.toString("Name"));
				status=HttpServletResponse.SC_OK;
			}
			
			
			logger.info("status : "+status);
			return status;
			
			
			
		}catch (Exception e){
			
			logger.info("Exception "+e.getMessage());
			logger.info("Status Code: " + mySession.getStatus());
			logger.info("Api Error: " + mySession.getApiError());
			logger.info("Error Message: " + mySession.getErrMsg());
			logger.info("Status Message: " + mySession.getStatusMessage());
			
			return 401;
		}
	}
	
	private org.apache.commons.httpclient.Cookie unWrappCook(Cookie[] in, org.apache.commons.httpclient.Cookie out, String id) {
		for (int i = 0; i < in.length; i++) {
			
//			Look for the external authentication cookies
			if ((in[i].getName()).equals("gsa_livelink_LLCookie_"+id)){
				
				logger.debug("AuthN cookie Ok.");
				String garb = null;
				StringTokenizer tkz = new StringTokenizer(in[i].getValue(), "||");
				out = new org.apache.commons.httpclient.Cookie();
				garb = tkz.nextToken();
				logger.debug("Setting name "+garb);
				out.setName(garb); 
				garb = tkz.nextToken();
//				logger.debug("Setting value "+garb);
				out.setValue(garb);
				
				// Read authentication cookie value
				garb = tkz.nextToken();
				logger.debug("Setting path "+garb);
				out.setPath(garb);
				garb = tkz.nextToken();
				logger.debug("Setting domain "+garb);
				out.setDomain(garb);
				garb = tkz.nextToken();
				logger.debug("Setting secure "+garb);
				out.setSecure(new Boolean(garb).booleanValue());
				out.setExpiryDate(new Date(System.currentTimeMillis()+1000000L));
				
				logger.info("API Cookie set: " + out.getName());
				break;
			}
		}
		
		return out;
	}
	
	public void setValveConfiguration(ValveConfiguration valveConf) {
		LivelinkAuthorizationProcess.conf = valveConf;
	}

	public void setCredentials(Credentials creds) {
		this.credz = creds;
		
	}	
	
	
}

