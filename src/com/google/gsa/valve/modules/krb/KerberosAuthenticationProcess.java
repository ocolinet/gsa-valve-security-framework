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

package com.google.gsa.valve.modules.krb;

import com.google.gsa.AuthenticationProcessImpl;

import com.google.gsa.Credential;
import com.google.gsa.Credentials;

import com.google.gsa.krb5.GssSpNegoAuth;

import com.google.gsa.krb5.GssSpNegoServer;

import java.io.IOException;

import java.util.Properties;

import javax.security.auth.Subject;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;

import com.google.gsa.sessions.UserIDEncoder;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.krb5.Krb5Credentials;

import com.google.krb5.NegotiateCallbackHandler;

import com.sun.security.auth.module.Krb5LoginModule;

import java.security.Principal;

import java.util.Date;
import java.util.Enumeration;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import java.util.Vector;

import javax.security.auth.login.LoginException;

import org.apache.commons.httpclient.UsernamePasswordCredentials;

import org.ietf.jgss.GSSCredential;

public class KerberosAuthenticationProcess implements AuthenticationProcessImpl { 

    //Vars
    private final static String COOKIE_NAME = "gsa_krb5_auth";
    private Logger logger = null;
    
    //Config
    private ValveConfiguration valveConf;
    
    //KRB vars
    private String krbconfig = null;
    private String krbini = null;
    
    //User vars
    private String username = null;
    private String timemills = null;
    private String id = null;
    private Subject userSubject = null;
    
    //KRB vars
    private GssSpNegoAuth spnegoAuth = null;
    private GssSpNegoServer spnegoServer = null;
    private Krb5Credentials credentials = null;
    private GSSCredential serverCreds = null;
    private Subject serverSubject = null;
    private String challenge = null;
    
    //KRB headers
    private final static String HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";      
    private final static String HEADER_AUTHORIZATION = "authorization";
    private final static String NEG_TOKEN = "Negotiate";
    
    private Cookie gsaKrbAuthCookie = null;
    
    private final static String GSA_CRAWLER_USER = "gsa-crawler";
    
    //Var that tells the default Credential ID for Kerberos
    private static final String KRB5_ID = "krb5";
    
    //This indicates if we are using Negotiation or just reuse username and passwords
    private boolean isNegotiate = false; 
    
    
    public KerberosAuthenticationProcess(boolean isNegotiate) {
    
        this.isNegotiate = isNegotiate;
    
        //Instantiate logger
        logger = Logger.getLogger(KerberosAuthenticationProcess.class);                 
        
    }
    
    public KerberosAuthenticationProcess() {
    
        isNegotiate = false;
        
        //Instantiate logger
        logger = Logger.getLogger(KerberosAuthenticationProcess.class);                 
        
    }
    
    public String getUsername() {
        return username;
    }
    
    public String getTimemills() {
        return timemills;
    }
    
    public String getId() {
        return id;
    }
    
    public Subject getUserSubject() {
        return userSubject;
    }
        
    public void setValveConfiguration(ValveConfiguration valveConf) {
        this.valveConf = valveConf;
                    
    }
                      
    public int authenticate (HttpServletRequest request, HttpServletResponse response, Vector<Cookie> authCookies, String url, Credentials creds, String id) throws HttpException, IOException {
        
        //Vars             
        int responseCode = HttpServletResponse.SC_UNAUTHORIZED;
        Cookie[] cookies = null;
        int nbCookies = 0;
        
        // Read cookies
        cookies = request.getCookies();
        
        Cookie krbCookie = null;
        
        //check if the authn cookie already exists
         if (cookies != null) {
                         
                 // Check if the authentication process already happened by looking at the existing cookies      
                 for (int i = 0; i < cookies.length; i++) {
         
                         // Check cookie name
                         if ((cookies[i].getName()).equals(COOKIE_NAME) ) {
                                 
                                 // Increment counter
                                 nbCookies++;  
                                 krbCookie = cookies[i];
                                 break;
                         }                               
                 }                       
         }
         
         // Protection         
         if (nbCookies > 0) {
                 
                 logger.debug("Already Authenticated");
                 
                 //add authn cookie
                 authCookies.add (krbCookie);
                                                  
                 // Set status code
                 responseCode = HttpServletResponse.SC_OK;

                 // Return
                 return responseCode;
                 
         }
         
        //Protection
        logger.debug("Checking if user already has Krb credentials. If so, return OK");
        
        try {
            if (creds != null) {
                if (creds.getCredential(KRB5_ID) != null) {
                    if (creds.getCredential(KRB5_ID).getSubject()!=null) {
                        //user Kerberos subject already created, so user is authenticated
                         
                        // Set status code
                        responseCode = HttpServletResponse.SC_OK;
        
                        // Return
                        return responseCode;
                    }
                }
            }
        }
        catch (NullPointerException e) {
            logger.debug("Krb subject does not exist. Continue with the process...");
        }
        
        
        try {
            logger.debug("Getting credentials");
            //Get Krb config files            
            krbconfig = valveConf.getKrbConfig().getKrbconfig();
            logger.debug ("Krb config file: "+krbconfig);
            krbini = valveConf.getKrbConfig().getKrbini();
            logger.debug ("Krb ini file: "+krbini);
            
            if ((isNegotiate)&&(serverSubject == null)) {
            
                try  {
                                            
                    initializeKerberos ();
                
                } catch (Exception ex)  {
                    logger.error ("Exception during Server Kerberos config initialization: "+ex.getMessage(),ex);
                } finally  {
                }                        
            
            }
            
            
            //Get user credentials
            //First read the u/p the credentails store, in this case using the same as the root login
            Credential userNamePwdCred = null;                                                                                
              
            if (isNegotiate) {
                logger.debug("KerbAuth: IsNegotiate");
                responseCode = authNegotiate (request, response);
            } else {
                logger.debug("KerbAuth: NOT IsNegotiate with id: "+id);                                
                
                
            try {
                logger.debug("HttpKrb: trying to get creds from repository id: "+id);
                userNamePwdCred = creds.getCredential(id);
            } catch (NullPointerException npe) {
                logger.error("NPE while reading credentials of ID: " + id);
            }            
            if (userNamePwdCred == null) {                         
                logger.debug("HttpKrb: trying to get creds from repository \"root\"");
                userNamePwdCred = creds.getCredential("root");                
            }
                
                //Execute Authentication method with username and password
                responseCode = authUsernamePassword (userNamePwdCred);   
            }                

            
            if (responseCode == HttpServletResponse.SC_OK) {
                //create cookie
                createCookie (request, response);
                //add cookie to the cookie array
                authCookies.add(gsaKrbAuthCookie);
                //add Krb credentials
                Credential krb5Cred = new Credential (KRB5_ID);
                krb5Cred.setKrbSubject(getUserSubject());
                krb5Cred.setUsername(getUsername());
                creds.add(krb5Cred);
            }
            
        } catch (Exception e) {
            logger.debug("Error creating Credentials: "+e.getMessage());
            e.printStackTrace();
            responseCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;            
        }
        
        return responseCode;
    }
    
    
    public int authUsernamePassword (Credential userCred) {
        
        int result = HttpServletResponse.SC_UNAUTHORIZED;
        
        Krb5LoginModule login = null;
        userSubject = new Subject ();
        
        logger.debug("authUsernamePassword: using username and password");
        
        try {
            
            //Create config objects and pass the credentials      
            Map state = new HashMap();
            UsernamePasswordCredentials usrpwdCred = new UsernamePasswordCredentials (userCred.getUsername(), userCred.getPassword());
            state.put("javax.security.auth.login.name", usrpwdCred.getUserName());
            state.put("javax.security.auth.login.password", usrpwdCred.getPassword().toCharArray());
            state.put("java.security.krb5.conf", krbini);
            
            if (logger.isDebugEnabled()) {
                logger.debug ("Username: "+usrpwdCred.getUserName());
            }
            
            Map option = new HashMap();
            String isDebug = "false";            
            if (logger.isDebugEnabled()) {
                isDebug = "true";
            }
            option.put("debug", isDebug);
            option.put("tryFirstPass", "true");
            option.put("useTicketCache", "false");
            option.put("doNotPrompt", "false");
            option.put("storePass", "false");
            option.put("forwardable", "true");                                                                                              
            
            login = new Krb5LoginModule();
            login.initialize(userSubject, new NegotiateCallbackHandler(), state, option);                                                                                                    
         
            if(login.login()){
                login.commit();
                logger.debug ("Login commit");
                if (id == null) {
                    username = usrpwdCred.getUserName();
                    id = username;
                }
                logger.debug("username is ... "+id);
                result = HttpServletResponse.SC_OK;
            } 
        }
        catch (LoginException e) {
            logger.error ("LoginException while creating id: "+e.getMessage(),e);
            result = HttpServletResponse.SC_UNAUTHORIZED;
        }
        catch (Exception e) {
            e.printStackTrace();
            logger.error ("Exception while creating id: "+e.getMessage(),e);
            result = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        
        return result;
        
    }
    
    public int authNegotiate (HttpServletRequest request, HttpServletResponse response) {
        //Implement Kerberos negotiatiation and authentication
        
        int result = HttpServletResponse.SC_UNAUTHORIZED;
        
         //read Authorization header
         boolean isAuthorization = false;
         
         //reset challenge
         challenge = null;
         
         Enumeration headerNames = request.getHeaderNames();
         while(headerNames.hasMoreElements()) {
             String headerName = (String)headerNames.nextElement();
             if (headerName.toLowerCase().equals(HEADER_AUTHORIZATION)) {
                 isAuthorization = true;
                 challenge = request.getHeader(headerName);
                 logger.debug ("Authorization header read: "+challenge);
                 break;
             }                  
         }

         // Instantiate the authentication process class
          try {
              
              //Check if the header sent by the client is Authorization or not
              if (!isAuthorization) {
                  logger.debug ("Sending.... "+HEADER_WWW_AUTHENTICATE);
                  
                  response.addHeader(HEADER_WWW_AUTHENTICATE, NEG_TOKEN);                  
                                         
                  // Return
                  return HttpServletResponse.SC_UNAUTHORIZED; 
              } else {
                  if (challenge == null) {
                      
                      // Log error
                      logger.error("The browser did not send the challenge properly");
                      
                      // Return
                      return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                      
                  }
              }

              //Check if serverCreds and subject are properly set                    
              if ((serverCreds==null)||(serverSubject==null)) {
                  
                  // Log error
                  logger.error("The GSA authentication servlet cannot get Server credentials");
                  
                  // Return
                  return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
              }                                        
              
              //Initialize Spnego server
              spnegoServer = new GssSpNegoServer (serverCreds, spnegoAuth.getManager(), serverSubject);
              
              boolean isComplete = false;
              
              try  {
                  isComplete = spnegoServer.processSpNego(challenge);
                  logger.debug("isComplete? "+isComplete);
                  
                  if (!isComplete) {
                      logger.debug ("Sending.... "+HEADER_WWW_AUTHENTICATE);
                      // Raise error
                      response.addHeader(HEADER_WWW_AUTHENTICATE, NEG_TOKEN+" "+spnegoServer.getResponseToken());
                      
                      
                      return HttpServletResponse.SC_UNAUTHORIZED;
                  } else {
                      if (spnegoServer.isFailed()) {
                          logger.error ("Error during the negotiation process");
                          
                          return HttpServletResponse.SC_UNAUTHORIZED;
                      } else { //Negotiation result is OK
                        
                        //Add cookies before returning
                                                                
                         //Get client subject
                         userSubject = spnegoServer.getClientSubject();                                                                            
                         
                         //Preparing Unique id
                         username = getPrincipalStr(userSubject);
                         id = username;
                         
                         logger.debug("username is ... "+id);                         
                         
                         result = HttpServletResponse.SC_OK;
                          
                      }
                  }
                  
              } catch (Exception ex)  {
                  logger.error ("Exception during the negotiation: "+ex.getMessage(),ex);
                  return HttpServletResponse.SC_UNAUTHORIZED;
              } finally  {
              }                                
                                                      
         } catch (Exception e) {
         
              // Log error
              logger.error("Exception during the negotiation: "+e.getMessage(),e);                                       
              
              return HttpServletResponse.SC_UNAUTHORIZED;
         }
         
         return result;
    }
    
    public void initializeKerberos () {
        //Read Krb ticket and instantiate                     
        setKrbCredentials (new Krb5Credentials (krbconfig,krbini,krbconfig));
        spnegoAuth = new GssSpNegoAuth (credentials);
        spnegoAuth.createServerCreds();
        serverSubject = spnegoAuth.getSubject();
        serverCreds = spnegoAuth.getServerCreds();
    
        // Debug
        if (logger.isDebugEnabled()) { 
            logger.debug("AuthenticationKerb initialize");
        }
    }
    
    public void setKrbCredentials (Krb5Credentials credentials) {
        this.credentials = credentials;
    }
    
    public boolean getIsNegotiate () {
        return isNegotiate;
    }
    
    public void setIsNegotiate (boolean isNegotiate) {
        logger.debug("IsNegotiate: " + isNegotiate);
        this.isNegotiate = isNegotiate;
    }
        
    public String getKrbini () {
        return krbini;
    }
    
    public void setKrbini (String krbini) {
        logger.debug("krbini: " + krbini);
        this.krbini = krbini;
    }
    
    public String getKrbconfig () {
        return krbconfig;
    }
    
    public void setKrbconfig (String krbconfig) {
        logger.debug("krbconfig: " + krbconfig);
        this.krbconfig = krbconfig;
    }
            
    
    public String getTimeStr () {
        Date date = new Date ();
        long mills = date.getTime();
        return new String (new Long(mills).toString());
    }
    
    public String getPrincipalStr (Subject subject) {        
        
        String principal = null;        
        
        logger.debug("Getting principal from Subject");
        try {
            Set principals = subject.getPrincipals();
            if (!principals.isEmpty()) {
                logger.debug ("Subject contains at least one Principal");
                Iterator it = principals.iterator();
                if (it.hasNext()) {                    
                    Principal ppal = (Principal)it.next(); 
                    principal = ppal.getName().substring(0,ppal.getName().indexOf("@"));
                    logger.debug ("Getting the first principal: "+principal);
                }
            }
        }
        catch (Exception e) {
            logger.error ("Error retrieving the client's Principal from the Subject: "+e.getMessage(),e);
        }
        return principal;
    }
    
    public void createCookie (HttpServletRequest request, HttpServletResponse response) {                
        
        logger.debug("Creating the Kerberos Authn cookie");
        
        try {
            // Instantiate authentication cookie with default value
            gsaKrbAuthCookie = new Cookie(COOKIE_NAME, (new UserIDEncoder()).getID(getUsername(), System.currentTimeMillis()));
                                                 
            // Set cookie domain
            gsaKrbAuthCookie.setDomain(valveConf.getAuthCookieDomain());
            
            // Set cookie path
            gsaKrbAuthCookie.setPath(valveConf.getAuthCookiePath());
            
            // Debug
            if (logger.isDebugEnabled()) logger.debug("Kerb Auth cookie set");
            
            
            //CLAZARO: add sendCookies support
            boolean isSessionEnabled = new Boolean (valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
            boolean sendCookies = false;
            if (isSessionEnabled) {
                sendCookies = new Boolean (valveConf.getSessionConfig().getSendCookies()).booleanValue();
            }
            if ((!isSessionEnabled)||((isSessionEnabled)&&(sendCookies))) {
                response.addCookie(gsaKrbAuthCookie);
            }

        }
        catch (Exception e) {
            logger.error("Error creating the cookie for kerberos: "+e.getMessage(),e);
        }
    }
    
    
}
