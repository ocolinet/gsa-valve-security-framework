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

package com.google.gsa.valve.rootAuth;


import java.io.IOException;
import java.net.URLDecoder;
import java.util.Properties;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;
import org.apache.regexp.RE;
import org.apache.regexp.RESyntaxException;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.sessions.Sessions;
import com.google.gsa.sessions.UserSession;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveRepositoryConfiguration;
import com.google.gsa.valve.utils.URLUTF8Encoder;

import com.google.gsa.sessions.nonValidSessionException;

import com.google.krb5.Krb5Credentials;

import java.net.URL;

import javax.security.auth.Subject;


public class RootAuthorizationProcess implements AuthorizationProcessImpl {
	
	private Logger logger = null;
	private ValveConfiguration valveConf = null;
	
	private AuthorizationProcessImpl[] authorizationImplementations = null;
        
        private static final String KRB5_ID = "krb5";
        
	//Krb and session vars
	private boolean isKerberos = false;
        private boolean isSessionEnabled = false;
        private boolean sendCookies = true;
        private long sessionTimeout;
        private long maxSessionAge;
        private static final long SEC_IN_MIN = 60; 
        private UserSession userSession = null;
        private Sessions sessions = null;
        	         
        private String authCookieName = null;
        private Cookie gsaAuthCookie = null;        
        
        private static final String ENCODING = "UTF-8";	
	
	// Constructor
	public RootAuthorizationProcess() {
		
		// Invoke parent constructor
		super();

		
		logger = Logger.getLogger(RootAuthorizationProcess.class);
	
	}
        
        public void setCredentials (Credentials creds) {
            //do nothing
        }
	
	
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException, nonValidSessionException {
		
                logger.debug("Authorize");
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		boolean patternMatch = false;
                boolean rootIDExists = false;
	        String internalURL = null;
                
                //initialize vars
                userSession = null;
                isKerberos = false;
                isSessionEnabled = false;

                //Encoding support
                String newURL = null;
                
                try {
                    newURL = URLDecoder.decode(url, ENCODING);                                        
                }
                catch (IllegalArgumentException e) {
                    logger.error ("Illegal Argument when decoding/encoding URL");
                    newURL = url;
                }
                URLUTF8Encoder encoder = new URLUTF8Encoder ();
                url = encoder.encodeURL(new URL(newURL));
                
                //read vars
                if (valveConf != null) {
                    isSessionEnabled = new Boolean (valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
                    isKerberos = new Boolean (valveConf.getKrbConfig().isKerberos()).booleanValue();                    
                    if (isSessionEnabled) {
                        sendCookies = new Boolean (valveConf.getSessionConfig().getSendCookies()).booleanValue();
                    } else {
                        sendCookies = false;
                    }
                    authCookieName = valveConf.getAuthCookieName();
                    internalURL = valveConf.getLoginUrl();
                } else {
                    logger.error ("Configuration error: Config file is not present");
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Configuration error - Kerberos is not set properly");
                    return HttpServletResponse.SC_INTERNAL_SERVER_ERROR; 
                }

                //manage Session
                if ((isSessionEnabled)||(isKerberos)) {
                    //Session Support. Get Sessions instance            
                    sessions = Sessions.getInstance();
                }
                
                //set auth Cookie                                
                Cookie[] cookies = request.getCookies();                                                
                
                if (cookies != null) {
                    logger.debug("authCookieName is: "+authCookieName);
                    for (int i = 0; i < cookies.length; i++) {
                            logger.debug("Cookie found: "+cookies[i].getName()+"; value="+cookies[i].getValue());
                            if (cookies[i].getName().equals(authCookieName)) {
                                gsaAuthCookie = cookies[i];
                                logger.debug("Auth Cookie found!");
                                break;
                            }
                    }
                }
                
                //session support
                boolean isSessionValid = manageSessions ();
                if (!isSessionValid) {
                    //throw nonValidSessionException. This exception will be caught by the Valve filter and invalidate the access
                    throw new nonValidSessionException ("Non valid session");
                } 
                
                //setting auth cookies
                if ((!isSessionEnabled)||((isSessionEnabled)&&(sendCookies))) {
                    //send auth cookies as those coming straight from the browser
                    authCookies = request.getCookies();
                } else {
                    //auth cookies are those that are in the session
                    authCookies = userSession.getCookies();
                }
                
		logger.debug("Authz authorizing [" + url + "]");
		
		//Get a list of repositories configured
		String repositoriyIds[] = valveConf.getRepositoryIds();
		
		//Pattern of the host that has been confiogured that needs to be macthed to the URL that is being authorized.
		RE authZHost = null;
		
		//The host of the GSA, need to detect a request from this host and skip past it
		//RE queryHost = new RE(valveConf.getSearchHost()+"/search", RE.MATCH_CASEINDEPENDENT);
		RE queryHostRE = null;
		try {
			 queryHostRE = new RE("/search", RE.MATCH_CASEINDEPENDENT);
		} catch (RESyntaxException reSynTaxExp) {
			logger.error("Failed to created queryHost RE: " + reSynTaxExp.getMessage());
		}
		
		ValveRepositoryConfiguration repository = null;
		
		for(int i = 0; i < repositoriyIds.length; i++) {
			repository = valveConf.getRepository(repositoriyIds[i]);
			
			//Pattern for this repository that needs to be macthed
			try {
				authZHost = new RE(repository.getPattern(), RE.MATCH_CASEINDEPENDENT);
			} catch (RESyntaxException reSynTaxExp) {
				logger.error("Failed to created authZHost RE: " + reSynTaxExp.getMessage());
				logger.error("Pattern trying to use: " + repository.getPattern());
			}
			
			//Need the correct authZProcess implementation for this repository ID
			AuthorizationProcessImpl authZProcess = authorizationImplementations[i];
			
			if (queryHostRE.match(url)) {
				logger.debug("Query AuthZ");
				statusCode = HttpServletResponse.SC_OK;
				patternMatch = true;
			} else if (authZHost.match(url)) {
				//URL matches a pattern
				if (repository.getId().equals("root")) {
					//If this is a match for the root id then it's the internal host used to test valve/test.html, so should just return valid
					logger.debug("Internal AuthZ");
					statusCode = HttpServletResponse.SC_OK;
					patternMatch = true;
                                        rootIDExists = true;
				} else {
					logger.info("Authorizing with " + repository.getId());
					patternMatch = true;
                                        
                                        //Krb support
                                        try {
                                            logger.debug ("Check if it's Kerberos");
                                            if (isKerberos) {
                                                Subject krbTicket = doesKrbSubjectExist(userSession);
                                                if (krbTicket != null) {
                                                    Credentials creds = new Credentials ();
                                                    Credential krbCred = new Credential (KRB5_ID);
                                                    krbCred.setKrbSubject(krbTicket);
                                                    creds.add(krbCred);
                                                    //protection
                                                    if (authZProcess != null) {
                                                        authZProcess.setCredentials(creds);                                                
                                                    }

                                                } else {
                                                    logger.error("User does not have proper credentials [Krb]");
                                                    return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                                                }
                                            }
                                        }
                                        catch (Exception e) {
                                            logger.error("Error during Kerberos authZ treatment : "+e.getMessage(),e);
                                        }
                                        
					try {
					    String repoID = repository.getId();
                                            statusCode = authZProcess.authorize(request, response, authCookies, url, repoID);
					} catch (Exception e) {
						logger.error("Error during authorization: "+e.getMessage(),e);
					}
				}
				
			}
		}
		if (!patternMatch) {
                    //check if "root" repository was created in the config file
                    //if not: check if the URL is a Valve one. If so, return SC_OK
                    if (!rootIDExists) {
                        RE internalRE = new RE(new URL (internalURL).getHost(), RE.MATCH_CASEINDEPENDENT);
                        boolean samePorts = (((new URL (internalURL)).getPort()) == ((new URL (url)).getPort()));
                        if ((internalRE.match(url))&&(samePorts)) {
                            logger.debug("This is an internal URL");
                            statusCode = HttpServletResponse.SC_OK;
                        }
                    } else {
                        logger.error("No pattern has been defined for any repository for this URL");
                    }
		}
		return statusCode;
	}
	
	public void setValveConfiguration(ValveConfiguration valveConf) {
		
                //if (this.valveConf == null) {
                    logger.debug("Setting Valve Configuration");
                    
                    this.valveConf = valveConf;
                    
                    //Instantiate each of the repositories defined in the configuration
                    authorizationImplementations = new AuthorizationProcessImpl[valveConf.getRepositoryCount()];
                    
                    String repositoriyIds[] = valveConf.getRepositoryIds(); 
                            
                    ValveRepositoryConfiguration repository = null;
                    
                    logger.debug("Reading repositories");
                    
                    for(int i = 0; i < repositoriyIds.length; i++) {
                                    try {
                                            repository = valveConf.getRepository(repositoriyIds[i]);
                                            if (repository.getAuthZ() == null || repository.getAuthZ().equals("")) {
                                                    logger.info("No authZ defined for " + repository.getId());
                                            } else {
                                                    logger.debug("Initialising authorisation process for " + repository.getId());
                                                    String authZComponent = repository.getAuthZ();
                                                    logger.debug ("Authorization module is: "+authZComponent);
                                                    if (authZComponent != null) {
                                                        authorizationImplementations[i] = (AuthorizationProcessImpl) Class.forName(authZComponent).newInstance();
                                                        authorizationImplementations[i].setValveConfiguration(valveConf);
                                                    }
                                            }
                                    
                                    } catch (LinkageError le) {
                                            logger.error(repository.getId() + " - Can't instantiate class [AuthorizationProcess-LinkageError]: " + le.getMessage(),le);					
                                    } catch (InstantiationException ie) {
                                            logger.error(repository.getId() + " - Can't instantiate class [AuthorizationProcess-InstantiationException]: " + ie.getMessage(),ie);					
                                    } catch (IllegalAccessException iae) {
                                            logger.error(repository.getId() + " - Can't instantiate class [AuthorizationProcess-IllegalAccessException]: " + iae.getMessage(),iae);
                                    } catch (ClassNotFoundException cnfe) {
                                            logger.error(repository.getId() + " - Can't instantiate class [AuthorizationProcess-ClassNotFoundException]: " + cnfe.getMessage(),cnfe);
                                    } catch (Exception e) {
                                            logger.error(repository.getId() + " - Can't instantiate class [AuthorizationProcess-Exception]: " + e.getMessage(),e);
                                    }
                            }	
                    logger.debug(RootAuthorizationProcess.class.getName() + " initialiation complete");
                //}
	}
        
        //CLAZARO:Session methods
        public boolean manageSessions () {

            boolean validSession = true;
                            
            if ((isSessionEnabled)||(isKerberos)) {
                userSession = new UserSession();
                //check if the session is active
                logger.debug("The session is active or it just contains Kerberos access");
                String userID = gsaAuthCookie.getValue();
                logger.debug("the userID has been read: "+userID);
                boolean isSessionInvalid = sessions.isSessionInvalid(userID);
                logger.debug("Session invalidity checked: "+isSessionInvalid);                    
                if (isSessionInvalid) { 
                    logger.debug("the session is invalid");
                    boolean doesSessionStillExist = sessions.doesSessionExist(userID);
                    logger.debug("Session still exists: "+doesSessionStillExist);
                    if (doesSessionStillExist) {
                        logger.debug("the session does exists: let's delete it");
                        //delete Session
                        sessions.deleteSession(userID);
                    }
                                    
                    logger.debug("Setting session invalidity");
                    validSession = false;
                                    
                }//end session invalid
                                
                //look for the existing session
                userSession = sessions.getUserSession(gsaAuthCookie.getValue());
                if (userSession == null) {
                    logger.error ("User Session is not valid");
                    validSession = false;
                } else {                        
                    if (isSessionEnabled) {
                        //update the last access
                        updateLastAccessTime (userSession);
                        logger.debug("New last access time: "+userSession.getSessionLastAccessTime());
                        sessions.addSession(userID, userSession);      
                    }
                }
                                
            }
            return validSession;
        }
        
        public UserSession getUserSession () {
                        
            //look for the existing session
            return sessions.getUserSession(gsaAuthCookie.getValue());
            
        }
        
        public void deleteCookies (HttpServletRequest request, HttpServletResponse response) {

             // Retrieve cookies
             Cookie[] allCookies = request.getCookies();                        
             try {
                 // Protection
                 if (allCookies != null) {
                         
                         // Look for the authentication cookie
                         for (int i = 0; i < allCookies.length; i++) {
                                 
                                 logger.debug("Cookie: "+allCookies[i].getName());
                                 
                                 //look for all the cookies start with "gsa" and delete them
                                 if ((allCookies[i].getName()).startsWith("gsa")) {
                                         
                                         Cookie gsaCookie = new Cookie (allCookies[i].getName(), allCookies[i].getValue());
                                         
                                         gsaCookie.setMaxAge(0);                                    
                                         
                                         response.addCookie(gsaCookie);
         
                                         // Debug
                                         if (logger.isDebugEnabled()) logger.debug("GSA cookie: [" + gsaCookie.getName() + " has been deleted ]");
                                         
                                 } 
                         
                         }
         
                 }
             }
             catch (Exception e) {
                 logger.error("Error when deleting cookies: "+e.getMessage(),e);
             }
         }
         
         public String redirectUrl (String url, String loginUrl) {
             //redirect
             String redirectUrl = null;
             if (url != null) {
                 redirectUrl = loginUrl + "?returnPath=" + url;
             } else {
                 redirectUrl = loginUrl;
             }
             logger.debug("redirecting to "+redirectUrl);
             return redirectUrl;
         }
         
         public void updateLastAccessTime (UserSession userSession) {
             long currentTime = System.currentTimeMillis();
             logger.debug("Last access time: "+userSession.getSessionLastAccessTime());
             userSession.setSessionLastAccessTime(currentTime);
         }
         
        public Subject doesKrbSubjectExist (UserSession userSession) {
            
            Subject krbSubject = null;
            //get Krb ticket from session
            if (userSession == null) {
                logger.error("User session is null");                
            } else {                
                krbSubject = userSession.getKerberosCredentials();
            }
            return krbSubject;
        }
	
}
