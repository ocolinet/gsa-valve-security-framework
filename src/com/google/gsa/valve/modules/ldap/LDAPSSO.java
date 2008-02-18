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
import com.google.gsa.valve.configuration.ValveRepositoryConfiguration;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.httpclient.UsernamePasswordCredentials;

public class LDAPSSO implements AuthenticationProcessImpl{

    private Logger logger = null;
    private ValveConfiguration valveConf = null;
    
    //Hastable and Vector that contains authentication LDAP attributes
    private Vector<String> repositories = new Vector<String>();
    private Map<String, LDAPAttrRepository> ldapAttributes = new HashMap<String, LDAPAttrRepository>(); 
    
    //LDAP vars parameters
    private String ldapBaseuser = null;
    private String ldapHost = null;
    private String ldapDomain = null;
    private String rdnAttr = null;
    
    // Number of auth cookies expected for this Authentication class, used as a check validation check
    private static final int NB_AUTH_COOKIES = 1;
    private static final String SSO_COOKIE_NAME = "gsa_ldap_auth";
    
	public LDAPSSO() {
		logger = Logger.getLogger(LDAPSSO.class);
		
	}
        
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
	
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;
                             
        }
	
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
		
        logger.debug("Start LDAPSSO AuthN process");        
               
        //protection
        repositories.clear();
        ldapAttributes.clear();
        
        //Insert LDAP attributes from the config file
        getLDAPAttributes (id);
        
        //First read the u/p the credentails store, in this case using the same as the root login
        logger.debug("LDAPSSO: trying to get creds from repository ID: "+id);
        Credential cred = null;
        try {
            cred = creds.getCredential(id);
        } catch (NullPointerException npe) {
            logger.error("NPE while reading credentials of ID: " + id);
        }        
        if (cred == null) {
            cred = creds.getCredential("root");
            if (cred != null) {
                logger.info("LDAPSSO: credential ID used is \"root\"");
            } else {
                logger.error ("LDAPSSO: No credentials available for "+id);
            }
        }
        
        Cookie[] cookies = null;
        
        // Cookie counter
        int nbCookies = 0;
        
        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
        
        // Read cookies
        cookies = request.getCookies();

        Cookie ldapSSOCookie = null;
        
        //In this sample a single cookie is created after a succussfull authenitcation, gsa_sample_sessionID
        //First check if it exisits, if it does that assume still authenticated and return
        

        // Protection
        if (cookies != null) {
                        
                // Check if the authentication process already happened by looking at the existing cookies      
                for (int i = 0; i < cookies.length; i++) {

                        // Check cookie name
                        if ((cookies[i].getName()).equals(SSO_COOKIE_NAME) ) {
                
                                // Increment counter
                                nbCookies++;                                    
                                
                                ldapSSOCookie = cookies[i];                                                                
                                
                        }                               
                }                       
        }
        
        // Protection

        if (nbCookies == NB_AUTH_COOKIES) {
                
                logger.debug("Already Authenticated");
                
                //add cookie
                authCookies.add(ldapSSOCookie);
                                
                // Set status code
                statusCode = HttpServletResponse.SC_OK;

                // Return
                return statusCode;
                
        }
        
        
        //If the required cookie was not found need to authenticate.
        logger.info("Authenticating root user with LDAP");
        try {                        
               
            //Check if the LDAP credentials are OK                    	
            Ldap ldapconn = new Ldap (ldapHost, cred.getUsername(), cred.getPassword(), ldapBaseuser, ldapDomain, rdnAttr);
            try {
            	logger.debug("Connecting to LDAP");
                DirContext ctx = ldapconn.openConnection();
                if (ctx == null) {
                    //Just send a comment  
                    logger.debug("The user("+cred.getUsername()+")/password doesn't match");
                    ldapconn.closeConnection(ctx);
                    return (HttpServletResponse.SC_UNAUTHORIZED);
                }
            
                
                //Fetching credentials
                logger.debug("Fetching credentials from the LDAP");
                
                fetchingCredentials (ldapconn,ctx,cred.getUsername(),creds);            
            
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
                 logger.debug("Setting session");
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
                logger.error("LDAP SSO authentication failure: " + e.getMessage(),e);


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
            Cookie extAuthCookie = new Cookie(SSO_COOKIE_NAME, "true");
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
        
        public void getLDAPAttributes (String id) {
        
            logger.debug("Getting LDAP Attributes");
                                                
            ValveRepositoryConfiguration repositoryConfig = valveConf.getRepository(id);
            
            if (repositoryConfig != null) {
                
                //Reading LDAP vars from configfile     
                
                logger.debug("Reading LDAP Attributes from config file");
                                        
                ldapBaseuser = repositoryConfig.getParameterValue("ldapBaseuser");
                if ((ldapBaseuser != null)&&(ldapBaseuser=="")) {
                    ldapBaseuser = null;
                }
                ldapHost = repositoryConfig.getParameterValue("ldapHost");
                if ((ldapHost != null)&&(ldapHost=="")) {
                    ldapHost = null;
                }
                ldapDomain = repositoryConfig.getParameterValue("ldapDomain");
                if ((ldapDomain != null)&&(ldapDomain=="")) {
                    ldapDomain = null;
                }
                rdnAttr = repositoryConfig.getParameterValue("rdnAttr");
                if ((rdnAttr != null)&&(rdnAttr=="")) {
                    rdnAttr = null;
                }
                
                //Getting attributes username and password for all the credentials
                logger.debug("Getting LDAP username and password attributes per each repository");
                boolean attributeExist = true;
                int index = 1;
                while (attributeExist) {
                    String idAttr = "id" + index;
                    logger.debug("ID is : "+idAttr);
                    if (repositoryConfig.getParameterValue(idAttr) != null) {
                        String userNameAttr = "username" + index;
                        String passwordAttr = "password" + index;                        
                        if ((repositoryConfig.getParameterValue(userNameAttr) != null)&&(repositoryConfig.getParameterValue(passwordAttr) != null)) {
                            logger.debug("Adding LDAP attributes for: "+repositoryConfig.getParameterValue(idAttr));
                            LDAPAttrRepository attrRepository =  new LDAPAttrRepository (repositoryConfig.getParameterValue(userNameAttr), repositoryConfig.getParameterValue(passwordAttr));
                            ldapAttributes.put(repositoryConfig.getParameterValue(idAttr), attrRepository);
                            repositories.add (repositoryConfig.getParameterValue(idAttr));
                        } else {
                            logger.error ("LDAP attribute username or password for repository number "+index+" ["+repositoryConfig.getParameterValue(idAttr)+"] does NOT exist in the config file. Review configuration");
                        }
                    } else {
                        attributeExist = false;
                    }
                    index++;
                }
            }
                    
        }
        
        public void fetchingCredentials (Ldap ldapconn, DirContext ctx, String username, Credentials creds) {
            
            for (int i=0; i<repositories.size();i++) {
                String id = repositories.elementAt(i);
                logger.debug("ID ["+id+"] found at position #"+i);
                
                LDAPAttrRepository attrRepository = ldapAttributes.get(id);
                
                //fetch credentials
                 try {
                     //Get User's DN
                     String userDName = ldapconn.getDN(username,ctx);
                                          
                     logger.info("fetching credentials for ("+id+")");
                     String usernameAttr = ldapconn.getAttributeByDN(attrRepository.getUsernameAttr(),userDName,ctx);
                     String passwordAttr = null;
                     if (!usernameAttr.equals(null)) {
                         logger.debug("UserName id["+id+"]: " + usernameAttr);
                         passwordAttr = ldapconn.getAttributeByDN(attrRepository.getPasswordAttr(),userDName,ctx);                            
                     }
                             
                     
                     //add the DCTM credentials into the "creds" object
                     logger.debug("LDAP credentials were acquired OK. Adding them into the credential container");
                     Credential credAttr = new Credential (id);
                     credAttr.setUsername(usernameAttr);
                     credAttr.setPassword(passwordAttr);
                     creds.add(credAttr);
                 }
                 catch (Exception e) {
                     logger.error ("Exception fetching LDAP attributes: "+e.getMessage(),e);
                 }
                
            }
                        
        }
        
        public class LDAPAttrRepository {
            
            String usernameAttr = null;
            String passwordAttr = null;
            
            public LDAPAttrRepository(String usernameAttr, String passwordAttr) {
                setUsernameAttr (usernameAttr);                    
                setPasswordAttr (passwordAttr);
            }
            
            public String getUsernameAttr() {
                return usernameAttr;
            }

            public void setUsernameAttr(String usernameAttr) {
                this.usernameAttr = usernameAttr;
            }
            
            public String getPasswordAttr() {
                return passwordAttr;
            }

            public void setPasswordAttr(String passwordAttr) {
                this.passwordAttr = passwordAttr;
            }            
            
        }

}
