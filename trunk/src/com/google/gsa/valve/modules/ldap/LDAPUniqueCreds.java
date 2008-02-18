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

package com.google.gsa.valve.modules.ldap;


import java.io.IOException;
import java.util.Properties;

import javax.naming.directory.DirContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.util.Vector;

public class LDAPUniqueCreds implements AuthenticationProcessImpl{

    private Logger logger = null;	
    private ValveConfiguration valveConf = null;
    
    //LDAP vars parameters
    private String ldapBaseuser = null;
    private String ldapHost = null;
    private String ldapDomain = null;
    private String rdnAttr = null;
	
    
    // Number of auth cookies expected for this Authentication class, used as a check validation check
    private static final int NB_AUTH_COOKIES = 1;
    
	public LDAPUniqueCreds() {
		logger = Logger.getLogger(LDAPUniqueCreds.class);
		
	}
	
	
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }
	
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
		
        logger.debug("LDAP Unique Credentials Start");
        
        Cookie[] cookies = null;
        
        // Cookie counter
        int nbCookies = 0;
        
        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
        
        // Read cookies
        cookies = request.getCookies();
        
        Cookie ldapUniqueCookie = null;

        
        //In this sample a single cookie is created after a succussfull authenitcation, gsa_sample_sessionID
        //First check if it exisits, if it does that assume still authenticated and return
        

        // Protection
        if (cookies != null) {
                        
                // Check if the authentication process already happened by looking at the existing cookies      
                for (int i = 0; i < cookies.length; i++) {

                        // Check cookie name
                        if ((cookies[i].getName()).equals("gsa_ad_auth") ) {
                                
                                ldapUniqueCookie = cookies[i];
                                
                                // Increment counter
                                nbCookies++;                                                                    
                        }                               
                }                       
        }
        
        //First read the u/p the credentails store, in this case using the same as the root login
        logger.debug("LDAPUniqueCreds: trying to get creds from repository ID: "+id);
        Credential cred = null;
        try {
            cred = creds.getCredential(id);
        } catch (NullPointerException npe) {
            logger.error("NPE while reading credentials of ID: " + id);
        }        
        if (cred == null) {
            cred = creds.getCredential("root");
            if (cred != null) {
                logger.info("LDAPUniqueCreds: credential ID used is \"root\"");
            } else {
                logger.error ("LDAPUniqueCreds: No credentials available for "+id);
            }
        }
        
        
        // Protection

        if (nbCookies == NB_AUTH_COOKIES) {
                
                logger.debug("Already Authenticated");
                
                //add cookie
                authCookies.add(ldapUniqueCookie);
                                
                // Set status code
                statusCode = HttpServletResponse.SC_OK;

                // Return
                return statusCode;
                
        }
        
        
        //If the required cookie was not found need to authenticate.
        logger.debug("Authenticating");
        try {                           
            
        
            
            //read values from config file (if any)
            readLDAPParameters (id);
            
            //Check if the LDAP credentials are OK                      
            logger.debug("Base user is: "+ldapBaseuser);
            Ldap ldapconn = new Ldap (ldapHost, cred.getUsername(), cred.getPassword(), ldapBaseuser, ldapDomain, rdnAttr);
            
            try {
            	logger.debug("Connection to LDAP");
                DirContext ctx = ldapconn.openConnection();
                if (ctx == null) {
                    //Just send a comment  
                    logger.debug("The user("+cred.getUsername()+")/password doesn't match");
                    ldapconn.closeConnection(ctx);
                    return (HttpServletResponse.SC_UNAUTHORIZED);
                }
                           
                logger.debug ("User properly authenticated against the LDAP");
            
                //Close the connection
                ldapconn.closeConnection(ctx);
                    
                } catch (Exception ex)  {
                    logger.error("LDAP connection problem during user access: "+ex.getMessage(),ex);
                    return (HttpServletResponse.SC_UNAUTHORIZED);
                } finally  {
                }
                                    
                
                Cookie extAuthCookie = null;
                
                extAuthCookie = settingCookie ();
                   
                 //add sendCookies support
                 boolean isSessionEnabled = new Boolean (valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
                 boolean sendCookies = false;
                 if (isSessionEnabled) {
                    sendCookies = new Boolean (valveConf.getSessionConfig().getSendCookies()).booleanValue();
                 }
                 if ((!isSessionEnabled)||((isSessionEnabled)&&(sendCookies))) {
                     response.addCookie(extAuthCookie);
                 }
                
                //add cookie to the array
                authCookies.add (extAuthCookie);
                
                //This would be set to OK or 401 in a real AuthN module
                statusCode = HttpServletResponse.SC_OK;
        
        } catch(Exception e) {

                // Log error
                logger.error("Sample authentication failure: " + e.getMessage(),e);


                // Update status code
                statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                
        }


        // Debug
        logger.debug("Sample Authentication completed (" + statusCode + ")");

        // Return status code
        return statusCode;
		
	}
        
        public Cookie settingCookie () {
            // Instantiate a new cookie
            Cookie extAuthCookie = new Cookie("gsa_ad_auth", "true");
            String authCookieDomain = null;
            String authCookiePath = null;
                                    
            // Cache cookie properties
            authCookieDomain = valveConf.getAuthCookieDomain();
            authCookiePath = valveConf.getAuthCookiePath();
                                    
            // Set extra cookie parameters
            extAuthCookie.setDomain(authCookieDomain);
            extAuthCookie.setPath(authCookiePath);
                    
            // Log info
            logger.debug("Adding cookie: " + extAuthCookie.getName() + ":" + extAuthCookie.getValue() 
                            + ":" + extAuthCookie.getPath() + ":" + extAuthCookie.getDomain() + ":" + extAuthCookie.getSecure());
            
            return extAuthCookie;                     
        }
        
        public void readLDAPParameters (String id) {
            if (valveConf != null) {
                
                //Reading LDAP vars from configfile                
                ldapBaseuser = valveConf.getRepository(id).getParameterValue("ldapBaseuser");
                if ((ldapBaseuser != null)&&(ldapBaseuser=="")) {
                    ldapBaseuser = null;
                }
                ldapHost = valveConf.getRepository(id).getParameterValue("ldapHost");
                if ((ldapHost != null)&&(ldapHost=="")) {
                    ldapHost = null;
                }
                ldapDomain = valveConf.getRepository(id).getParameterValue("ldapDomain");
                if ((ldapDomain != null)&&(ldapDomain=="")) {
                    ldapDomain = null;
                }
                rdnAttr = valveConf.getRepository(id).getParameterValue("rdnAttr");
                if ((rdnAttr != null)&&(rdnAttr=="")) {
                    rdnAttr = null;
                }
                
            }
        }
	
}

