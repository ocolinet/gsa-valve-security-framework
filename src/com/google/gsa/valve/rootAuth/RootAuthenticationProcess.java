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


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;
import org.apache.regexp.RE;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveRepositoryConfiguration;

import com.google.gsa.valve.modules.krb.KerberosAuthenticationProcess;

import java.util.Vector;

import javax.security.auth.Subject;


public class RootAuthenticationProcess implements AuthenticationProcessImpl {
	
	private Logger logger = null;

	private ValveConfiguration valveConf = null;
        
        //Support for Krb creds
        private String username = null;
        String password = null;
        private String timemills = null;
        private Subject userSubject = null;
           
        boolean isKerberos = false;      
        boolean isNegotiate = false;
        String loginUrl = null;
        private static final String KRB_AUTHN_PROCESS = "com.google.gsa.valve.modules.krb.KerberosAuthenticationProcess";
        private static final String KRB5_ID = "krb5";
        
        private Vector<Cookie> rootAuthCookies = new Vector<Cookie>();
        private Vector<Cookie> repositoryAuthCookies = new Vector<Cookie>();
	
	
	private AuthenticationProcessImpl[] authenticationImplementations = null;
	
	// Constructor
	public RootAuthenticationProcess() {
		
		// Invoke parent constructor
		super();
		
		// Instantiate logger
		logger = Logger.getLogger(RootAuthenticationProcess.class);
		
		logger.debug("Initializing " + RootAuthenticationProcess.class.getName());
		
		
	}
	
        
        //Krb methods
        public String getUsername() {
            return username;
        }
                                                                  
        public Subject getUserSubject() {
            return userSubject;
        }
                
        public void setIsNegotiate (boolean newIsNegotiate) {
            isNegotiate = newIsNegotiate;
        }
                
        public boolean getIsNegotiate () {
            return isNegotiate;
        }
        //End Krb methods
	
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
		
                // Initialize status code
		int rootStatusCode = HttpServletResponse.SC_UNAUTHORIZED;
		int repositoryAuthStatusCode = HttpServletResponse.SC_UNAUTHORIZED;
                //Check if authn is Ok in multiple repository
                boolean repositoryOKAuthN = false;
                
                //Main credentials
                Credential rootCred = null;
                Credential krb5Cred = null;
                
                //clear authCookies
                authCookies.clear();
		
		boolean rootAuthNDefined = false;
		logger.debug("AuthN authenticate [" + url + "]");
	
                 //Read vars
                 if (valveConf != null) {                    
                     isKerberos = new Boolean (valveConf.getKrbConfig().isKerberos()).booleanValue();
                     if (isKerberos) {
                        isNegotiate = new Boolean (valveConf.getKrbConfig().isNegotiate()).booleanValue();
                     }
                     loginUrl = valveConf.getLoginUrl();
                 } else {
                     logger.error ("Configuration error: Config file is not present");
                     response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Configuration error - Kerberos is not set properly");
                     return HttpServletResponse.SC_INTERNAL_SERVER_ERROR; 
                 }
                                
                //ValveHost: it's the same URL as the login page, without 
                String valveHost = loginUrl.substring(0, loginUrl.lastIndexOf("/")+1);
                	
		//RE internal = new RE(valveConf.getValveHost(), RE.MATCH_CASEINDEPENDENT );
                RE internal = new RE(valveHost, RE.MATCH_CASEINDEPENDENT );

		// The host and URL of the GSA for the search
		//TODO add support for multiple GSA's
		//RE query = new RE(valveConf.getSearchHost() + "/search", RE.MATCH_CASEINDEPENDENT);
		RE query = new RE("/search", RE.MATCH_CASEINDEPENDENT);

		
		String[] repositoryIDs = valveConf.getRepositoryIds();
		
		//Request has come from the same host as the valve, so must be the login authenticate
		if (internal.match(url)) {
			for (int i = 0; i < authenticationImplementations.length; i++) {
				AuthenticationProcessImpl authProcess = authenticationImplementations[i];
				ValveRepositoryConfiguration repositoryConfig = null;                                                                
				
				//Get the config for this class, check the class name
				for(int j = 0; j < repositoryIDs.length; j++){
					if (valveConf.getRepository(repositoryIDs[j]).getAuthN().equals(authProcess.getClass().getName())) {
						repositoryConfig = valveConf.getRepository(repositoryIDs[j]);
					}
				}
				logger.debug("Authenticating ID: " + repositoryConfig.getId());
				if (repositoryConfig.getId().equals("root")) {
				    //Root should be used for main authentication against an identity repository (LDAP, DB, ..)
                                    //and should not be used as a content repository that contains documents
					try {
                                                //add support to cookie array
                                                rootAuthCookies.clear();
						rootStatusCode = authProcess.authenticate(request, response, rootAuthCookies, url, creds, "root");
						logger.info("Repository authentication - " + repositoryConfig.getId() + " completed. Response was " + rootStatusCode);
						if (rootStatusCode == HttpServletResponse.SC_UNAUTHORIZED) {
							logger.error("Root AuthN failed");
						} else {
                                                    //CLAZARO: add support to cookie array
                                                    if (rootStatusCode == HttpServletResponse.SC_OK) {
                                                        logger.debug ("Root AuthN is SC_OK (200)");
                                                        if (!rootAuthCookies.isEmpty()) {
                                                            logger.debug ("Root AuthN returns cookies");
                                                            for (int j=0; j < rootAuthCookies.size(); j++) {
                                                                logger.debug ("Root Cookie found: "+rootAuthCookies.elementAt(j).getName()+":"+rootAuthCookies.elementAt(j).getValue());
                                                                authCookies.add(rootAuthCookies.elementAt(j));
                                                            }
                                                        } else {
                                                            logger.debug ("Root AuthN does NOT return cookies");
                                                        }
                                                    }
                                                }
                                              
						//If no repository is defined called root then rootStatusCode must be set to OK
						// This flag is used to indicate that a root repository has been defined.
						rootAuthNDefined = true;
						//
					} catch (Exception e) {
						logger.debug("Exception with authentication for ID: " + repositoryConfig.getId() + " - " + e.getMessage());
						rootAuthNDefined = true;
					}
				} else {
					try {
                                                //Krb settings
                                                boolean isKrbAuthNProcess = false;
                                                if (isKerberos) {
                                                    //setIsNegotiate: delete it
                                                    //authProcess.setIsNegotiate(isNegotiate); 
                                                    //check if it's a Kerberos AuthN process
                                                    logger.debug("authProcess class is: "+authProcess.getClass().getName());
                                                    if (authProcess.getClass().getName().equals (KRB_AUTHN_PROCESS)) {
                                                        logger.debug("It is Kerberos authentication process");
                                                        isKrbAuthNProcess = true;
                                                    }
                                                }
 
                                                //add support to cookie array
                                                repositoryAuthCookies.clear();
                                                
                                                logger.debug("Let's do the authentication");
                                                
						repositoryAuthStatusCode = authProcess.authenticate(request, response, repositoryAuthCookies, url, creds, repositoryConfig.getId());
                                                
                                                //Krb support
                                                //check if authn is Kerberos                                                 
                                                if (isKerberos) {                                                    
                                                    //check if Krb5Cred has been already defined
                                                    logger.debug("It's Kerberos");                                                    
                                                    if (krb5Cred == null) {
                                                        logger.debug("Kerberos credentials are not null");
                                                        if (isKrbAuthNProcess) {         
                                                            logger.debug("Kerberos authN process");
                                                            //check if the response is OK                                                            
                                                            if (repositoryAuthStatusCode == HttpServletResponse.SC_OK) {
                                                                logger.debug("Response is Ok");
                                                                //It's Kerberos: set Krb creds  
                                                                if (creds.getCredential (KRB5_ID)!=null) {
                                                                    logger.error ("Krb Creds found");
                                                                    krb5Cred = creds.getCredential (KRB5_ID); 
                                                                } else {
                                                                    logger.error ("Krb Creds do not found");
                                                                }
                                                            }  
                                                        }                                                        
                                                    }
                                                }
                                                
                                                //add support to cookie array
                                                if (repositoryAuthStatusCode == HttpServletResponse.SC_OK) {
                                                    logger.debug ("Repository AuthN ["+repositoryConfig.getId()+"] is SC_OK (200)");
                                                    //check if multiple repository is set to valid
                                                     if (repositoryOKAuthN == false) {
                                                         repositoryOKAuthN = true;
                                                     }
                                                    //check if cookie array is not empty and consume it
                                                    if (!repositoryAuthCookies.isEmpty()) {
                                                        logger.debug ("Repository AuthN ["+repositoryConfig.getId()+"] returns "+repositoryAuthCookies.size()+" cookies");
                                                        for (int j=0; j < repositoryAuthCookies.size(); j++) {
                                                            logger.debug ("Repository Cookie found: "+repositoryAuthCookies.elementAt(j).getName()+":"+repositoryAuthCookies.elementAt(j).getValue());
                                                            authCookies.add(repositoryAuthCookies.elementAt(j));
                                                        }
                                                    } else {
                                                        logger.debug ("Repository AuthN ["+repositoryConfig.getId()+"] does NOT return cookies");
                                                    }
                                                }
                                                
                                                //end Krb support
						logger.info("Repository authentication - " + repositoryConfig.getId() + " completed. Response was " + repositoryAuthStatusCode);
					} catch (Exception e) {
						logger.debug("Exception with authentication for ID: " + repositoryConfig.getId() + " - " + e.getMessage());
					}
				}                                                            
			}
		} else if (query.match(url)) {

			logger.debug("Query pattern [" + url + "]");
			
			// Don't do anything in here
			rootStatusCode = HttpServletResponse.SC_OK;

		} else {

			logger.error("No pattern defined for URL: " + url + ". It should not have been possible to get here!");
			
			// Protection
			rootStatusCode = HttpServletResponse.SC_UNAUTHORIZED;
			
		}
                
                //add support to multiple repositories
		if ((!rootAuthNDefined)&&(repositoryOKAuthN)) {
			//If no root repository has been defined then rootStatusCode has to be set valid, to OK
			rootStatusCode = HttpServletResponse.SC_OK;
		}
		
		// Return status code
		logger.debug("RootAuthN Complete - Status Code: " + rootStatusCode);
                		
		return rootStatusCode;
	
		
	}            

	public void setValveConfiguration(ValveConfiguration valveConf) {
		
		this.valveConf = valveConf;
		
		//Instantiate each of the repositories defined in the configuration
		authenticationImplementations = new AuthenticationProcessImpl[valveConf.getRepositoryCount()];
		
		String repositoriyIds[] = valveConf.getRepositoryIds(); 
			
		ValveRepositoryConfiguration repository = null;
		for(int i = 0; i < repositoriyIds.length; i++) {
				try {
					repository = valveConf.getRepository(repositoriyIds[i]);
				
					logger.info("Initialising authentication process for " + repository.getId());
					authenticationImplementations[i] = (AuthenticationProcessImpl) Class.forName(repository.getAuthN()).newInstance();
					authenticationImplementations[i].setValveConfiguration(valveConf);
				
				} catch (LinkageError le) {
					logger.error(repository.getId() + " - Can't instantiate class [AuthenticationProcess-LinkageError]: " + le.getMessage(),le);					
				} catch (InstantiationException ie) {
					logger.error(repository.getId() + " - Can't instantiate class [AuthenticationProcess-InstantiationException]: " + ie.getMessage(),ie);					
				} catch (IllegalAccessException iae) {
					logger.error(repository.getId() + " - Can't instantiate class [AuthenticationProcess-IllegalAccessException]: " + iae.getMessage(),iae);
				} catch (ClassNotFoundException cnfe) {
					logger.error(repository.getId() + " - Can't instantiate class [AuthenticationProcess-ClassNotFoundException]: " + cnfe.getMessage(),cnfe);
				} catch (Exception e) {
					logger.error(repository.getId() + " - Can't instantiate class [AuthenticationProcess-Exception]: " + e.getMessage(),e);
				}
			}	
		logger.debug(RootAuthenticationProcess.class.getName() + " initialised");
	}
	
}