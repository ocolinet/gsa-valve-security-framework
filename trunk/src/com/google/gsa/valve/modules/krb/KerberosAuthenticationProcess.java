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

import java.net.URLEncoder;

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

/**
 * This class manages the authentication process for Kerberos protected 
 * content sources. It creates an HTTP connection to any Kerberized URL 
 * that is passed to the authenticate method. If the authentication 
 * process is succesful, a 200 (OK) error message is returned, and if there 
 * is any other error is sent back as well.
 * <p>
 * Once the process has finished successfully, a cookie is created with an  
 * encoded information that includes the username to be reused if this is 
 * needed in any other Authn/AuthZ module. It also populates the credentials 
 * vector with the user's Kerberos credential ("krb5") that the caller 
 * process should reuse when authorizing. An important consideration is the 
 * Kerberos tickets are usually max aged. So take that into account if you 
 * want to reused the ticket for authorization.
 * <p>
 * The Kerberos getting process could be done in two different ways (this is 
 * specified in the isNegotiate var):
 * <ul>
 *     <li>
 *       <b>Username/Password</b>: the Kerberos ticket is created using the 
 *       user credentials passed to the authorize() method. This can be done 
 *       just in the default Kerberos domain.
 *     </li>
 *     <li>
 *       <b>Negotiation</b>: the Kerberos ticket is got based on an HTTP 
 *       negotiation process between the browser and the frontend server that 
 *       instances this class-
 *     </li>
 *    </ul>
 *
 *@see KerberosAuthorizationProcess
 * 
 */
public class KerberosAuthenticationProcess implements AuthenticationProcessImpl {

    //Vars
    private static final String COOKIE_NAME = "gsa_krb5_auth";
    private static Logger logger = null;

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
    private static final String HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String HEADER_AUTHORIZATION = "authorization";
    private static final String NEG_TOKEN = "Negotiate";

    private Cookie gsaKrbAuthCookie = null;

    //Var that tells the default Credential ID for Kerberos
    private static final String KRB5_ID = "krb5";

    //This indicates if we are using Negotiation or just reuse username and passwords
    private boolean isNegotiate = false;

    //Cookie Max Age
    private int authMaxAge = -1;

    //Encoding
    private static final String encoder = "UTF-8";


    /**
     * Class constructor
     * <p>
     * Sets if it's a negotiation process or not
     * 
     * @param isNegotiate
     */
    public KerberosAuthenticationProcess(boolean isNegotiate) {

        this.isNegotiate = isNegotiate;

        //Instantiate logger
        logger = Logger.getLogger(KerberosAuthenticationProcess.class);

    }

    /**
     * Class constructor - default
     * <p>
     * It automatically sets the Negotiation process to false.
     * 
     */
    public KerberosAuthenticationProcess() {

        isNegotiate = false;

        //Instantiate logger
        logger = Logger.getLogger(KerberosAuthenticationProcess.class);

    }

    /**
     * Gets the username got during the negotiation process
     * 
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the time stamp
     * 
     * @return the time stamp (mills)
     */
    public String getTimemills() {
        return timemills;
    }

    /**
     * Gets the credential id
     * 
     * @return the credential id
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the user subject that contains the Kerberos ticket as a result of 
     * a succesful authentication process
     * 
     * @return the user subject
     */
    public Subject getUserSubject() {
        return userSubject;
    }

    /**
     * Sets the Valve Configuration instance to read the parameters 
     * from there
     * 
     * @param valveConf the Valve configuration instance
     */
    public void setValveConfiguration(ValveConfiguration valveConf) {
        this.valveConf = valveConf;
    }


    /**
     * This is the main method that does the Kerberos authentication and 
     * should be invoked by the classes that would like to open a new 
     * authentication process against a Kerberized protected source.
     * <p>
     * It behaves differently if the it's set up as a Negotiation process or 
     * the Kerberos credentials are got from the username and password 
     * credentials. It reads "isNegotiate" var and invokes the proper method 
     * that manages Kerberos authentication specifically for each method.
     * <p>
     * If the Kerberos authentication result is OK, a cookie is created with an  
     * encoded information that includes the username to be reused if this is 
     * needed in any other Authn/AuthZ module. It also populates the credentials 
     * vector with the user's Kerberos credential ("krb5") that the caller 
     * process should reuse when authorizing.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param authCookies vector that contains the authentication cookies
     * @param url the document url
     * @param creds an array of credentials for all external sources
     * @param id the default credential id to be retrieved from creds
        
     * @return the HTTP error code
        
     * @throws HttpException
     * @throws IOException
     */
    public int authenticate(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Vector<Cookie> authCookies, String url, 
                            Credentials creds, String id) throws HttpException, 
                                                                 IOException {

        //Vars             
        int responseCode = HttpServletResponse.SC_UNAUTHORIZED;
        Cookie[] cookies = null;

        // Read cookies
        cookies = request.getCookies();

        //Protection
        logger.debug("Checking if user already has Krb credentials. If so, return OK");

        try {
            if (creds != null) {
                if (creds.getCredential(KRB5_ID) != null) {

                    logger.debug("Credential found: " + KRB5_ID);


                    if (creds.getCredential(KRB5_ID).getSubject() != null) {

                        //user Kerberos subject already created, so user is authenticated                        
                        logger.debug("Kerberos subject already exists. Returning...");

                        // Set status code
                        responseCode = HttpServletResponse.SC_OK;

                        // Return
                        return responseCode;
                    }
                }
            }
        } catch (NullPointerException e) {
            logger.debug("Krb subject does not exist. Continue with the process...");
        }

        try {
            authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());
        } catch (NumberFormatException nfe) {
            logger.error("Configuration error: chack the configuration file as the number set for authMaxAge is not OK:");
        }


        try {
            logger.debug("Getting credentials");
            //Get Krb config files            
            krbconfig = valveConf.getKrbConfig().getKrbconfig();
            logger.debug("Krb config file: " + krbconfig);
            krbini = valveConf.getKrbConfig().getKrbini();
            logger.debug("Krb ini file: " + krbini);

            if ((isNegotiate) && (serverSubject == null)) {

                try {

                    initializeKerberos();

                } catch (Exception ex) {
                    logger.error("Exception during Server Kerberos config initialization: " + 
                                 ex.getMessage(), ex);
                } finally {
                }

            }


            //Get user credentials
            //First read the u/p the credentails store, in this case using the same as the root login
            Credential userNamePwdCred = null;

            if (isNegotiate) {
                logger.debug("KerbAuth: IsNegotiate");
                responseCode = authNegotiate(request, response);
            } else {
                logger.debug("KerbAuth: It's NOT IsNegotiate with id: " + id);

                try {
                    logger.debug("HttpKrb: trying to get creds from repository id: " + 
                                 id);
                    userNamePwdCred = creds.getCredential(id);
                } catch (NullPointerException npe) {
                    logger.error("NPE while reading credentials of ID: " + id);
                }

                if (userNamePwdCred == null) {
                    logger.debug("HttpKrb: trying to get creds from repository \"root\"");
                    userNamePwdCred = creds.getCredential("root");
                }

                //Execute Authentication method with username and password
                responseCode = authUsernamePassword(userNamePwdCred);
            }


            if (responseCode == HttpServletResponse.SC_OK) {
                //create cookie
                createCookie(request, response);
                //add cookie to the cookie array
                authCookies.add(gsaKrbAuthCookie);
                //add Krb credentials
                Credential krb5Cred = new Credential(KRB5_ID);
                krb5Cred.setKrbSubject(getUserSubject());
                krb5Cred.setUsername(getUsername());
                creds.add(krb5Cred);
            }

        } catch (Exception e) {
            logger.debug("Error creating Credentials: " + e.getMessage());
            e.printStackTrace();
            responseCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        return responseCode;
    }

    /**
     * It does the Kerberos authentication when it has to be done through 
     * username and password. It looks in the default Kerberos domain defined 
     * in the Kerberos config file (krb5.ini or krb5.conf) if there is a valid 
     * user with those credentials. If so, it gets his/her Kerberos ticket.
     * 
     * @param userCred username and password credentials
     *
     * @return the method result in HTTP error format
     */
    public int authUsernamePassword(Credential userCred) {

        int result = HttpServletResponse.SC_UNAUTHORIZED;

        Krb5LoginModule login = null;
        userSubject = new Subject();

        logger.debug("authUsernamePassword: using username and password");

        try {

            //Create config objects and pass the credentials      
            Map state = new HashMap();
            UsernamePasswordCredentials usrpwdCred = 
                new UsernamePasswordCredentials(userCred.getUsername(), 
                                                userCred.getPassword());
            state.put("javax.security.auth.login.name", 
                      usrpwdCred.getUserName());
            state.put("javax.security.auth.login.password", 
                      usrpwdCred.getPassword().toCharArray());
            state.put("java.security.krb5.conf", krbini);

            if (logger.isDebugEnabled()) {
                logger.debug("Username: " + usrpwdCred.getUserName());
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
            login.initialize(userSubject, new NegotiateCallbackHandler(), 
                             state, option);

            if (login.login()) {
                login.commit();
                logger.debug("Login commit");
                if (id == null) {
                    username = usrpwdCred.getUserName();
                    id = username;
                }
                logger.debug("username is ... " + id);
                result = HttpServletResponse.SC_OK;
            }
        } catch (LoginException e) {
            logger.error("LoginException while creating id: " + e.getMessage(), 
                         e);
            result = HttpServletResponse.SC_UNAUTHORIZED;
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Exception while creating id: " + e.getMessage(), e);
            result = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        return result;

    }

    /**
     *  It does the Kerberos authentication using the negotiation way. It 
     *  establishes a negotiation with the browser sending HTTP error messages.
     *  
     * @param request HTTP request
     * @param response HTTP response
     * 
     * @return the method result in HTTP error format
     */
    public int authNegotiate(HttpServletRequest request, 
                             HttpServletResponse response) {
        //Implement Kerberos negotiatiation and authentication

        int result = HttpServletResponse.SC_UNAUTHORIZED;

        //read Authorization header
        boolean isAuthorization = false;

        //reset challenge
        challenge = null;

        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = (String)headerNames.nextElement();
            if (headerName.toLowerCase().equals(HEADER_AUTHORIZATION)) {
                isAuthorization = true;
                challenge = request.getHeader(headerName);
                logger.debug("Authorization header read: " + challenge);
                break;
            }
        }

        // Instantiate the authentication process class
        try {

            //Check if the header sent by the client is Authorization or not
            if (!isAuthorization) {
                logger.debug("Sending.... " + HEADER_WWW_AUTHENTICATE);

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
            if ((serverCreds == null) || (serverSubject == null)) {

                // Log error
                logger.error("The GSA authentication servlet cannot get Server credentials");

                // Return
                return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            }

            //Initialize Spnego server
            spnegoServer = 
                    new GssSpNegoServer(serverCreds, spnegoAuth.getManager(), 
                                        serverSubject);

            boolean isComplete = false;

            try {
                isComplete = spnegoServer.processSpNego(challenge);
                logger.debug("isComplete? " + isComplete);

                if (!isComplete) {
                    logger.debug("Sending.... " + HEADER_WWW_AUTHENTICATE);
                    // Raise error
                    response.addHeader(HEADER_WWW_AUTHENTICATE, 
                                       NEG_TOKEN + " " + 
                                       spnegoServer.getResponseToken());


                    return HttpServletResponse.SC_UNAUTHORIZED;
                } else {
                    if (spnegoServer.isFailed()) {
                        logger.error("Error during the negotiation process");

                        return HttpServletResponse.SC_UNAUTHORIZED;
                    } else { //Negotiation result is OK

                        //Add cookies before returning

                        //Get client subject
                        userSubject = spnegoServer.getClientSubject();

                        //Preparing Unique id
                        username = getPrincipalStr(userSubject);
                        id = username;

                        logger.debug("username is ... " + id);

                        result = HttpServletResponse.SC_OK;

                    }
                }

            } catch (Exception ex) {
                logger.error("Exception during the negotiation: " + 
                             ex.getMessage(), ex);
                return HttpServletResponse.SC_UNAUTHORIZED;
            } finally {
            }

        } catch (Exception e) {

            // Log error
            logger.error("Exception during the negotiation: " + e.getMessage(), 
                         e);

            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        return result;
    }

    /**
     * Initializes Kerberos server configuration
     * 
     */
    public void initializeKerberos() {
        //Read Krb ticket and instantiate                     
        setKrbCredentials(new Krb5Credentials(krbconfig, krbini, krbconfig));
        spnegoAuth = new GssSpNegoAuth(credentials);
        spnegoAuth.createServerCreds();
        serverSubject = spnegoAuth.getSubject();
        serverCreds = spnegoAuth.getServerCreds();

        // Debug
        if (logger.isDebugEnabled()) {
            logger.debug("AuthenticationKerb initialize");
        }
    }

    /**
     * Sets Kerberos credentials
     * 
     * @param credentials Kerberos credentials
     */
    public void setKrbCredentials(Krb5Credentials credentials) {
        this.credentials = credentials;
    }

    /**
     * Gets if the Kerberos authentication process is configured as 
     * Negotiate or not
     * 
     * @return boolean - "true" if it's a Kerberos negotiation process
     */
    public boolean getIsNegotiate() {
        return isNegotiate;
    }

    /**
     * Sets if it's a Kerberos negotiation process or not
     * 
     * @param isNegotiate if it's a Kerberos negotiation process
     */
    public void setIsNegotiate(boolean isNegotiate) {
        logger.debug("IsNegotiate: " + isNegotiate);
        this.isNegotiate = isNegotiate;
    }

    /**
     * Gets the Kerberos config file location (krb5.ini or krb5.conf)
     * 
     * @return the system's kerberos config file path
     */
    public String getKrbini() {
        return krbini;
    }

    /**
     * Sets the Kerberos config file location (krb5.ini or krb5.conf)
     * 
     * @param krbini the system's kerberos config file path
     */
    public void setKrbini(String krbini) {
        logger.debug("krbini: " + krbini);
        this.krbini = krbini;
    }

    /**
     * Gets the Kerberos Java config file location. It contains the Java 
     * parameters needed when Kerberos negotiation is in place
     * 
     * @return the kerberos Java config file path
     */
    public String getKrbconfig() {
        return krbconfig;
    }

    /**
     * Sets the Kerberos Java config file location
     * 
     * @param krbconfig the kerberos Java config file path
     */
    public void setKrbconfig(String krbconfig) {
        logger.debug("krbconfig: " + krbconfig);
        this.krbconfig = krbconfig;
    }

    /**
     * Gets the current time in String format
     * 
     * @return the current time
     */
    public String getTimeStr() {
        Date date = new Date();
        long mills = date.getTime();
        return new String(new Long(mills).toString());
    }

    /**
     * Gets the main principal from the user subject got as a result 
     * of the Kerberos authentication process
     * 
     * @param subject user subject
     * 
     * @return the user principal
     */
    public static String getPrincipalStr(Subject subject) {

        String principal = null;

        logger.debug("Getting principal from Subject");
        try {
            Set principals = subject.getPrincipals();
            if (!principals.isEmpty()) {
                logger.debug("Subject contains at least one Principal");
                Iterator it = principals.iterator();
                if (it.hasNext()) {
                    Principal ppal = (Principal)it.next();
                    principal = 
                            ppal.getName().substring(0, ppal.getName().indexOf("@"));
                    logger.debug("Getting the first principal: " + principal);
                }
            }
        } catch (Exception e) {
            logger.error("Error retrieving the client's Principal from the Subject: " + 
                         e.getMessage(), e);
        }
        return principal;
    }

    /**
     * Creates the authentication cookie sent back to the caller as a 
     * result of a successful Kerberos authentication process
     * 
     * @param request HTTP request
     * @param response HTTP response
     */
    public void createCookie(HttpServletRequest request, 
                             HttpServletResponse response) {

        logger.debug("Creating the Kerberos Authn cookie");

        //Cookie value
        String krbCookie = null;
        try {

            //Get the Base64-encoded ID for the Cookie
            String krbIDBase64Encoded = 
                (new UserIDEncoder()).getID(getUsername(), 
                                            System.currentTimeMillis());
            //URL encode the value of the cookie before adding
            krbCookie = URLEncoder.encode(krbIDBase64Encoded, encoder);

            if (krbCookie == null) {
                krbCookie = "";
            }

        } catch (Exception ex) {
            logger.error("Error when setting the Krb cookie value: " + 
                         ex.getMessage(), ex);
            krbCookie = "";
        }

        // Instantiate authentication cookie with default value
        gsaKrbAuthCookie = new Cookie(COOKIE_NAME, krbCookie);

        // Set cookie domain
        gsaKrbAuthCookie.setDomain(valveConf.getAuthCookieDomain());

        // Set cookie path
        gsaKrbAuthCookie.setPath(valveConf.getAuthCookiePath());

        // Set cookie max age
        gsaKrbAuthCookie.setMaxAge(authMaxAge);

        // Debug
        if (logger.isDebugEnabled())
            logger.debug("Kerb Auth cookie set");


        //add sendCookies support
        boolean isSessionEnabled = 
            new Boolean(valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
        boolean sendCookies = false;
        if (isSessionEnabled) {
            sendCookies = 
                    new Boolean(valveConf.getSessionConfig().getSendCookies()).booleanValue();
        }
        if ((!isSessionEnabled) || ((isSessionEnabled) && (sendCookies))) {
            response.addCookie(gsaKrbAuthCookie);
        }

    }


}
