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


package com.google.gsa;

import com.google.gsa.sessions.SessionTimer;

import com.google.gsa.valve.modules.krb.KerberosAuthenticationProcess;

import com.google.gsa.sessions.Sessions;
import com.google.gsa.sessions.UserIDEncoder;
import com.google.gsa.sessions.UserSession;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveConfigurationException;
import com.google.gsa.valve.configuration.ValveConfigurationInstance;
import com.google.gsa.valve.saml.SAMLArtifactProcessor;
import com.google.gsa.valve.saml.authn.SAMLAuthN;
import com.google.gsa.valve.utils.ValveUtils;

import java.io.IOException;

import java.io.UnsupportedEncodingException;

import java.net.URLEncoder;

import java.security.Principal;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import java.util.Set;

import java.util.Vector;

import javax.naming.NamingException;

import javax.security.auth.Subject;

import javax.servlet.*;
import javax.servlet.http.*;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;

/**
 * This is the main authentication servlet when a silent kerberos tickets are 
 * being used to get user credentials. It implements the whole authentication 
 * process when the user is authenticated using his/her kerberos ticket obtained 
 * silently during the browser connection. This ticket is collected up, 
 * included in the authentication credentials and starts the global 
 * authentication process for the user.
 * <p>
 * It invokes the root authentication process to garantee the user is 
 * authenticated in all the backend repositories. It supports both the SAML 
 * and the Forms Based interface.
 * <p>
 * If the overall process result is an unauthorized, a 401 error message is 
 * sent back to the user's browser.
 * <p>
 * It also handles crawling when Forms Based authentication has been set.
 * 
 */
public class Kerberos extends HttpServlet {

    //logger
    private static Logger logger = null;

    private String userAgent = null;

    private Credentials creds = null;

    //Cookie vars
    private String authCookieDomain = null;
    private String authCookiePath = null;
    private String authCookieName = null;
    private int authMaxAge = 300;
    private String refererCookieName = null;
    private Cookie gsaRefererCookie = null;
    private Cookie gsaAuthCookie = null;

    //user session vars
    private UserSession userSession = null;
    SessionTimer sessionTimer;
    long maxSessionAge;
    long sessionTimeout;
    long sessionCleanup;
    boolean isSessionEnabled = false;

    //Non Krb AuthN vars
    private String authenticationProcessClsName = null;
    private AuthenticationProcessImpl authenticationProcessCls = null;

    //Kerberos AuthN and AuthZ classes
    private KerberosAuthenticationProcess krbAuthN = 
        new KerberosAuthenticationProcess();

    //Kerberos Subject Map
    private static Map<String, Subject> krbSubjects = 
        new HashMap<String, Subject>();

    private static String gsaValveConfigPath = null;
    private ValveConfiguration valveConf;

    //Krb vars
    boolean KrbUsrPwdCrawler = false;
    boolean KrbAdditionalAuthN = false;
    String KrbLoginUrl = null;
    String KrbUsrPwdCrawlerUrl = null;
    String loginUrl = null;
    boolean isKerberos = false;
    boolean isNegotiate = false;
    //Var that tells the default Credential ID for Kerberos
    private static final String KRB5_ID = "krb5";

    private static final String GSA_CRAWLER_USER = "gsa-crawler";
    private static final String GSA_CRAWLING_CONTENT = "(Enterprise";

    private static final String KRB_COOKIE_NAME = "gsa_krb5_auth";

    //Session Cookie arrays
    private Vector<Cookie> krbCookies = new Vector<Cookie>();
    private Vector<Cookie> nonKrbCookies = new Vector<Cookie>();

    //encoding
    private static String encoder = "UTF-8";

    //SAML
    boolean isSAML = false;
    String refererSAML = null;
    String relayState = null;
    String samlRequest = null;

    static {

        // Instantiate logger
        logger = Logger.getLogger(Kerberos.class);

    }

    /**
     * Init method
     * 
     * @param config servlet config
     * 
     * @throws ServletException
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    /**
     * Servlet's doGet: processes a doGet request. Calls doPost.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * 
     * @throws ServletException 
     * @throws IOException
     */
    public void doGet(HttpServletRequest request, 
                      HttpServletResponse response) throws ServletException, 
                                                           IOException {

        doPost(request, response);

    }

    /**
     * Servlet's doPost: processes a POST request. Controls the overall 
     * kerberos silent authentication process. It supports both the Security 
     * Framework's SAML and Forms Based interface.
     * <p>
     * You can find more information on the Security Framework's Kerberos guide 
     * about the scenarios implemented here
     * 
     * @param request HTTP request
     * @param response HTTP response
     * 
     * @throws ServletException
     * @throws IOException
     */
    public void doPost(HttpServletRequest request, 
                       HttpServletResponse response) throws ServletException, 
                                                            IOException {

        logger.debug("Kerberos servlet");

        if (gsaValveConfigPath == null) {
            if (request.getAttribute("gsaValveConfigPath") == null) {
                //Read parameter from config file: SAML
                gsaValveConfigPath = readValveConfigPath();
            } else {
                gsaValveConfigPath = 
                        request.getAttribute("gsaValveConfigPath").toString();
            }
        }

        logger.debug("Valve Config Path is: " + gsaValveConfigPath);

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        //Initialize cookies vars
        gsaRefererCookie = null;
        gsaAuthCookie = null;

        //clear cookies
        krbCookies.clear();
        nonKrbCookies.clear();

        //Session ID vars definition
        String sessionID = null;
        String encodedSessionID = null;

        //Create the credentials store
        try {
            this.valveConf = 
                    ValveConfigurationInstance.getValveConfig(gsaValveConfigPath);
        } catch (ValveConfigurationException e) {
            logger.error("Valve Config instantiation error: " + e);
        }

        logger.debug("Creating the credentials store");
        creds = new Credentials();
        String username = null;

        //Setting Valve parameters
        logger.debug("Setting Valve params");
        setValveParams(request);

        //Protection
        if ((!isKerberos) || (!isNegotiate)) {
            logger.error("Configuration error: if you want to use Kerberos silent AuthN, isKerberos and isNegotiate config vars have to be set to true");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                               "Configuration error - Kerberos is not set properly");
            return;
        }

        Cookie cookies[] = null;

        // Retrieve cookies
        cookies = request.getCookies();

        // Protection: look for auth and referer cookies
        if (cookies != null) {

            // Look for the referer cookie
            for (int i = 0; i < cookies.length; i++) {

                // Look for the referer cookie
                if ((cookies[i].getName()).equals(refererCookieName)) {

                    // Cache cookie
                    gsaRefererCookie = cookies[i];

                    logger.debug("Referer cookie already exists: " + 
                                 gsaRefererCookie.getValue());


                } else {
                    // Look for the auth cookie
                    if ((cookies[i].getName()).equals(authCookieName)) {

                        // Cache cookie
                        gsaAuthCookie = cookies[i];

                        logger.debug("Auth cookie already exists: " + 
                                     gsaAuthCookie.getValue());

                    }
                }

                if ((gsaRefererCookie != null) && (gsaAuthCookie != null)) {
                    // Exit
                    break;
                }

            }

        }

        // Protection
        if (!isSAML) {
            if (gsaRefererCookie == null) {

                // Raise error
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                                   "The GSA authentication servlet couldn't read the referer cookie");

                // Log error
                logger.error("The GSA authentication servlet couldn't read the referer cookie, pls. check the cookie domain value");

                // Return
                return;

            }
        } else {
            //SAML

            //Get SAML Params
            relayState = request.getParameter("RelayState");
            samlRequest = request.getParameter("SAMLRequest");
            //String relayStateCookie = valveConf.getSAMLConfig().getRelayStateCookie();
            boolean noParams = false;
            boolean cookieExist = true;

            //Protection
            if ((relayState == null) || (relayState.equals(""))) {
                noParams = true;
            } else {
                if ((samlRequest == null) || (samlRequest.equals(""))) {
                    noParams = true;
                }
            }

            createRefererCookie();

            //if ((noParams)&&(!cookieExist)) {
            if (noParams) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, 
                                   "Invalid request");
                return;
            }
        }

        logger.debug("Let's validate if gsaAuthCookie is present");

        if (gsaAuthCookie != null) {

            if (!isSAML) {
                //redirect
                String redirect = gsaRefererCookie.getValue();

                logger.debug("redirect is " + redirect);
                //redirect only if the URL is different than the login one                    
                if (!redirect.equals(loginUrl)) {

                    //user properly authenticated
                    logger.debug("The user was properly authenticated. Lets redirect to..." + 
                                 redirect);

                    // Redirect
                    response.sendRedirect(redirect);

                } else {
                    logger.debug("It's the login URL. No redirect");
                }
            } else {
                logger.debug("As this is SAML. Let's obviate the previous authentication cookie");
                gsaAuthCookie = null;
            }
        }

        userSession = new UserSession();

        Sessions sessions = Sessions.getInstance();
        sessions.setMaxSessionAgeMinutes(maxSessionAge);
        sessions.setSessionTimeoutMinutes(sessionTimeout);

        if (gsaAuthCookie == null) {

            logger.debug("gsaAuthCookie does not exist");

            isNegotiate = true;

            // Read User-Agent header
            userAgent = request.getHeader("User-Agent");

            logger.debug("userAgent is... " + userAgent);

            //check if user is gsa-crawler
            if (userAgent.startsWith(GSA_CRAWLER_USER)) {

                logger.debug("User is " + GSA_CRAWLER_USER);

                //check if user is gsa-crawler and have to authenticate it thru a form                                  
                if (KrbUsrPwdCrawler) {

                    logger.debug("gsa-crawler has to access thru username and password");

                    //check if crawler already provided credentials

                    if (request.getParameter("UserIDKrb") == null) {

                        //the login page have to be filled in by the admin user before reaching here. Return error
                        logger.error("The login page [" + KrbUsrPwdCrawlerUrl + 
                                     "] has to be invoked and its credentials fields filled in before reaching here");
                        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                                           "It means the GSA Valve Kerberos configuration is not done properly or you just forgot to fill in the Kerberos credentials in the login page");
                        return;

                    } else {

                        //user already submits credentials
                        logger.debug("Crawler has already sent credentials");
                        //set isNegotiate equal false (it authenticates the user thru username and pwd credentials)                                                                                    
                        isNegotiate = false;

                        //set Crawler credentials
                        setCrawlerCredentials(request, KrbAdditionalAuthN);

                        //authenticate user
                        statusCode = 
                                krbAuthentication(request, response, krbCookies, 
                                                  gsaRefererCookie.getValue(), 
                                                  creds, isNegotiate);

                        // Protection: check status code
                        if (statusCode != HttpServletResponse.SC_OK) {

                            // Raise error
                            response.sendError(statusCode, 
                                               "Authentication process failed!");

                            // Debug
                            if (logger.isDebugEnabled())
                                logger.debug("Krb Authentication process failed with code: " + 
                                             statusCode);

                            if (statusCode == 
                                HttpServletResponse.SC_UNAUTHORIZED) {
                                logger.debug("Note: this 401 could not be an error as sending 401 could be part of the Negotiation process");
                            }

                            // Return
                            return;

                        }

                        //check if the additional authN method is available. If so, start authN with these creds as well
                        //N: modification for always lanching the root authN process. Comment out the following line
                        //if (KrbAdditionalAuthN) {

                        statusCode = 
                                nonKrbAuthentication(request, response, nonKrbCookies, 
                                                     gsaRefererCookie.getValue(), 
                                                     creds);

                        //check if the status code is indeterminate
                        if (statusCode == -1) {
                            //the process could not determinate the authorization
                            //as there is no pattern that matches with any repository
                            statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                        }

                        // Protection: check status code
                        if (statusCode != HttpServletResponse.SC_OK) {

                            // Raise error
                            response.sendError(statusCode, 
                                               "Authentication process failed!");

                            // Debug
                            if (logger.isDebugEnabled())
                                logger.debug("Non Krb Authentication process failed with code: " + 
                                             statusCode);

                            // Return
                            return;

                        }

                        //}

                    }
                } else { // end KrbUsrPwdCrawler is set. 
                    //If KrbUsrPwdCrawler is not set to true, then do nothing (assume content is feeded)
                    //just send back the error as a configuration one (we shouldn't configure Froms-based crawling)
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                                       "Configuration error. Review your configuration as you can not define this rule if it's not set properly (see doc on how to set it up using Kerberos config attributes)");
                    return;
                }

            } else { //User is not Crawler

                logger.debug("User is NOT crawler");

                //check if we have double AuthN or not
                if (!KrbAdditionalAuthN) {

                    logger.debug("Krb silent authN only");

                    //set isNegotiate equal true (it authenticates the user thru kerberos ticket)                                                                                    
                    isNegotiate = true;
                    
                    String refererCookieValue = null;
                    if (gsaRefererCookie != null) {
                        refererCookieValue = new String (gsaRefererCookie.getValue());
                    }
                    
                    //authenticate user
                    statusCode = 
                            krbAuthentication(request, response, krbCookies, 
                                              refererCookieValue, 
                                              creds, isNegotiate);

                    // Protection: check status code
                    if (statusCode != HttpServletResponse.SC_OK) {

                        // Raise error
                        response.sendError(statusCode, 
                                           "Authentication process failed!");

                        // Debug
                        if (logger.isDebugEnabled())
                            logger.debug("Krb Authentication process failed with code: " + 
                                         statusCode);

                        if (statusCode == 
                            HttpServletResponse.SC_UNAUTHORIZED) {
                            logger.debug("Note: this 401 could not be an error as sending 401 could be part of the Negotiation process");
                        }

                        // Return
                        return;

                    } else {

                        boolean doesKrbSubjectExist = lookForKrbCreds();

                        if (!doesKrbSubjectExist) {
                            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                                               "Credentials not valid. Try to close your browser and try it again");

                            // Log error
                            logger.error("Kerberos Subject is not present when authenticating");

                            // Return
                            return;
                        }

                        //N: call rootAuthN once we have the Kerberos creds
                        //N: Begin update
                        if (!KrbAdditionalAuthN) {
                            statusCode = 
                                    nonKrbAuthentication(request, response, 
                                                         nonKrbCookies, 
                                                         refererCookieValue, 
                                                         creds);

                            //check if the status code is indeterminate
                            if (statusCode == -1) {
                                //the process could not determinate the authorization
                                //as there is no pattern that matches with any repository
                                statusCode = 
                                        HttpServletResponse.SC_UNAUTHORIZED;
                            }

                            // Protection: check status code
                            if (statusCode != HttpServletResponse.SC_OK) {

                                // Raise error
                                response.sendError(statusCode, 
                                                   "Authentication process failed!");

                                // Debug
                                if (logger.isDebugEnabled())
                                    logger.debug("Non Krb Authentication process failed with code: " + 
                                                 statusCode);

                                // Return
                                return;
                            }

                        }
                        //N:End update

                    }


                } else { //Double AuthN required. So that apart from the Krb silent authN, we authN the user as well thru username and pwd

                    logger.debug("Krb and Forms based AuthN mechanisms");

                    //check if Krb credentials are already set
                    Cookie gsaKrbCookie = getCookie(request, KRB_COOKIE_NAME);

                    //if (gsaKrbCookie != null) { //Kerberos cookie set
                    if (!isKrbProcess(gsaKrbCookie)) { //Kerberos cookie set    

                        logger.debug("Krb cookie is set. Krb AuthN already in place");

                        Subject krbSubj = 
                            getKrbSubject(gsaKrbCookie.getValue());

                        //Protection
                        if (krbSubj == 
                            null) { // couldn't localize the subject. 

                            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                                               "Credentials not valid. Try to close your browser and try it again");

                            // Log error
                            logger.error("Kerberos Subject is not present when authenticating");

                            // Return
                            return;
                        } else {

                            logger.debug("The Krb subject exists. This is the Forms based AuthN part");

                            //check if parameters are present
                            if (request.getParameter("UserIDKrb") == null) {

                                logger.debug("Login page has not been already invoked");

                                String redirectUrl = contructKrbLoginURL();

                                logger.debug("Redirecting to...." + 
                                             redirectUrl);

                                //redirect to the login page
                                response.sendRedirect(response.encodeRedirectURL(redirectUrl));

                                // Return
                                return;

                            } else {

                                //user already submits credentials
                                logger.debug("User has already sent credentials");

                                createCredsDoubleAuthN(request, krbSubj);

                                logger.debug("User Credentials created. Let's authenticate the user without Krb");

                                statusCode = 
                                        nonKrbAuthentication(request, response, 
                                                             nonKrbCookies, 
                                                             gsaRefererCookie.getValue(), 
                                                             creds);

                                //check if the status code is indeterminate
                                if (statusCode == -1) {
                                    //the process could not determinate the authorization
                                    //as there is no pattern that matches with any repository
                                    statusCode = 
                                            HttpServletResponse.SC_UNAUTHORIZED;
                                }

                                // Protection: check status code
                                if (statusCode != HttpServletResponse.SC_OK) {

                                    // Raise error
                                    response.sendError(statusCode, 
                                                       "Authentication process failed!");

                                    // Debug
                                    if (logger.isDebugEnabled())
                                        logger.debug("Non Krb Authentication process failed with code: " + 
                                                     statusCode);

                                    // Return
                                    return;


                                }
                                boolean resultDelete = 
                                    deleteKrbSubject(gsaKrbCookie.getValue());
                                if (!resultDelete) {
                                    logger.error("Not KrbSubj found when deleting it");
                                }

                            }
                        }

                    } else { //Krb cookie does not exist
                        logger.debug("Krb cookie does not exist. Let's silently authenticate the user thru Krb firstly");
                        logger.debug("Krb silent authN only");

                        //set isNegotiate equal true (it authenticates the user thru kerberos ticket)                                                                                    
                        isNegotiate = true;

                        //authenticate user
                        statusCode = 
                                krbAuthentication(request, response, krbCookies, 
                                                  gsaRefererCookie.getValue(), 
                                                  creds, isNegotiate);

                        // Protection: check status code
                        if (statusCode != HttpServletResponse.SC_OK) {

                            // Raise error
                            response.sendError(statusCode, 
                                               "Authentication process failed!");

                            // Debug
                            if (logger.isDebugEnabled())
                                logger.debug("Krb Authentication process failed with code: " + 
                                             statusCode);

                            if (statusCode == 
                                HttpServletResponse.SC_UNAUTHORIZED) {
                                logger.debug("Note: this 401 could not be an error as sending 401 could be part of the Negotiation process");
                            }

                            // Return
                            return;

                        } else {
                            Cookie krbCookie = krbCookies.elementAt(0);
                            String krbAuthCookieValue = krbCookie.getValue();

                            logger.debug("Krb cookie value: " + 
                                         krbAuthCookieValue);
                            if (krbAuthCookieValue == null) {
                                logger.error("Krb cookie not present");
                                // Raise error
                                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                                                   "Kerberos cookie not present");
                                // Return
                                return;
                            } else {
                                addKrbCookie(response, krbCookie);
                                addKrbSubject(krbAuthCookieValue, 
                                              krbAuthN.getUserSubject());
                                logger.debug("The User Krb identity is already present. Let's authenticate the user thru username/password");
                                //redirect to Login page
                                String redirectUrl = contructKrbLoginURL();
                                response.sendRedirect(response.encodeRedirectURL(redirectUrl));
                                logger.debug("Redirect to.... " + redirectUrl);
                                return;
                            }

                        }

                    }

                }
            }

            logger.debug("Krb and/or Forms based AuthN OK. Let's create the session");

            //set username and cookies
            username = creds.getCredential(KRB5_ID).getUsername();

            //creation time var
            long creationTime = System.currentTimeMillis();

            //Setting session values
            sessionID = UserIDEncoder.getID(username, creationTime);
            encodedSessionID = URLEncoder.encode(sessionID, encoder);

            logger.debug("Krb Username is... " + username);

            // setSession                                               
            boolean sessionOk = 
                settingSession(username, creationTime, encodedSessionID);

            logger.debug("Session is .... " + sessionOk);

            if (!sessionOk) {
                //SAML
                statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                response.setStatus(statusCode);

                // Log error
                logger.error("Kerberos Subject has not been created properly");

                // Return
                return;
            } else {
                //Store Session in the Session Map
                sessions.addSession(sessionID, userSession);

                sessions.setMaxSessionAgeMinutes(maxSessionAge);

                if (isSessionEnabled) {
                    sessions.setSessionTimeoutMinutes(sessionTimeout);
                } else {
                    sessions.setSessionTimeoutMinutes(-1);
                }

                logger.debug("User Session created");

                // Add internal authentication cookie
                response.addCookie(gsaAuthCookie);

                logger.debug("Auth cookie added");

                // Debug
                if (logger.isDebugEnabled())
                    logger.debug("Authentication process successful");


                if (!isSAML) {
                    // Debug
                    if (logger.isDebugEnabled())
                        logger.debug("Redirecting user to: " + 
                                     gsaRefererCookie.getValue());

                    // Redirect
                    response.sendRedirect(gsaRefererCookie.getValue());
                } else {
                    redirectingSAML(response, cookies, sessionID);
                }


            }

        } //end of AuthN cases

    }

    /**
     * Sets the crawler credentials recovered during the crawling process
     * 
     * @param request HTTP request
     * @param KrbAdditionalAuthN if there is an additional authentication process
     */
    public void setCrawlerCredentials(HttpServletRequest request, 
                                      boolean KrbAdditionalAuthN) {
        // Read HTTP request parameters
        String username = request.getParameter("UserIDKrb");
        String password = request.getParameter("PasswordKrb");
        Credential krb5Cred = new Credential(KRB5_ID);
        Credential rootCred = new Credential("root");
        krb5Cred.setUsername(username);
        krb5Cred.setPassword(password);
        creds = new Credentials();
        if (KrbAdditionalAuthN) {
            username = request.getParameter("UserID");
            password = request.getParameter("Password");
            rootCred = new Credential("root");
            rootCred.setUsername(username);
            rootCred.setPassword(password);
            creds.add(rootCred);
            creds.add(krb5Cred);
        } else {
            creds.add(krb5Cred);
        }
    }


    /**
     * It invokes the kerberos authentication class to validate the 
     * authentication process
     * 
     * @param request HTTP request
     * @param response HTTP response 
     * @param krbAuthCookies authentication cookies
     * @param url document url
     * @param creds credentials
     * @param isNegotiate if it's a negotiate process
     * 
     * @return HTTP error code
     */
    public int krbAuthentication(HttpServletRequest request, 
                                 HttpServletResponse response, 
                                 Vector<Cookie> krbAuthCookies, String url, 
                                 Credentials creds, boolean isNegotiate) {

        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
        logger.debug("krbAuthentication: Krb authentication process");
        try {
            krbAuthN.setIsNegotiate(isNegotiate);
            krbAuthN.setValveConfiguration(valveConf);
            statusCode = 
                    krbAuthN.authenticate(request, response, krbAuthCookies, 
                                          url, creds, KRB5_ID);
        } catch (HttpException e) {
            logger.error("Http error during Kerberos authentication " + e);
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        } catch (IOException e) {
            logger.error("I/O error during Kerberos authentication " + e);
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
        logger.debug("Krb Auth - Status code is... " + statusCode);
        return statusCode;
    }

    /**
     * It invokes the additional non-Kerberos authentication process
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param nonKrbAuthCookies authentication cookies
     * @param url document url
     * @param creds credentials
     * 
     * @return HTTP error code
     */
    public int nonKrbAuthentication(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    Vector<Cookie> nonKrbAuthCookies, 
                                    String url, Credentials creds) {

        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        // Instantiate the authentication process class
        try {

            // Instantiate the authorization process class
            authenticationProcessCls = 
                    (AuthenticationProcessImpl)Class.forName(authenticationProcessClsName).newInstance();


        } catch (InstantiationException e) {

            // Log error
            logger.error("InstantiationException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");

            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            // Return
            return statusCode;

        } catch (IllegalAccessException e) {

            // Log error
            logger.error("IllegalAccessException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");

            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            // Return
            return statusCode;

        } catch (ClassNotFoundException e) {

            // Log error
            logger.error("ClassNotFoundException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");
            logger.error("Cannot find class: " + authenticationProcessClsName);

            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            // Return
            return statusCode;

        }

        try {
            logger.debug("Lets authenticate the user");
            // Execute the authentication process in here 
            authenticationProcessCls.setValveConfiguration(valveConf);
            statusCode = 
                    authenticationProcessCls.authenticate(request, response, 
                                                          nonKrbAuthCookies, 
                                                          url, creds, "root");


            logger.debug("Non Krb Auth - Status code is... " + statusCode);

        } catch (Exception e) {

            // Debug
            logger.error("Authentication process raised exception: " + 
                         e.getMessage(), e);

        }

        return statusCode;

    }

    /**
     * Setting the authentication cookie and the user session
     * 
     * @param username username
     * @param creationTime creation time
     * @param encodedSessionID encoded session id
     * 
     * @return if the setting process was successful
     */
    public boolean settingSession(String username, long creationTime, 
                                  String encodedSessionID) {

        boolean result = false;

        logger.debug("Creating auth cookie with value: " + encodedSessionID);

        // Instantiate authentication cookie with default value
        gsaAuthCookie = new Cookie(authCookieName, encodedSessionID);

        // Set cookie domain
        gsaAuthCookie.setDomain(authCookieDomain);

        // Set cookie path
        gsaAuthCookie.setPath(authCookiePath);

        // Set expiration time
        gsaAuthCookie.setMaxAge(authMaxAge);


        logger.debug("Creating Session");

        userSession.setUserName(username);
        userSession.setSessionCreationTime(creationTime);
        userSession.setSessionLastAccessTime(creationTime);
        userSession.setUserCredentials(creds);

        //Cookies
        settingSessionCookies();

        if (krbAuthN.getUserSubject() != null) {
            logger.debug("Kerberos Subject exists");

            userSession.setKerberosCredentials(krbAuthN.getUserSubject());

            result = true;

        } else {
            // Log error
            logger.error("Kerberos Subject has not been created properly");

            // Return
            return result;

        }

        return result;
    }

    /**
     * Sets the kerberos and non-kerberos authentication cookies
     * 
     */
    private void settingSessionCookies() {
        int numKrb = 0;
        int numNonKrb = 0;
        int authCookie = 1;

        Cookie[] totalCookies;

        //check number of cookies
        if (!krbCookies.isEmpty()) {
            numKrb = krbCookies.size();
            logger.debug("numKrb: " + numKrb);
        }
        if (!nonKrbCookies.isEmpty()) {
            numNonKrb = nonKrbCookies.size();
            logger.debug("numNonKrb: " + numNonKrb);
        }

        //setting Cookies
        int numCookies = numKrb + numNonKrb + authCookie;

        logger.debug("numCookies: " + numCookies);

        totalCookies = new Cookie[numCookies];

        //setting authCookie
        logger.debug("Inserting authCoookie at totalCookie");
        totalCookies[0] = gsaAuthCookie;
        int index = 1;
        //getting Krb cookies
        if (numKrb > 0) {
            int krbIndex = 0;
            for (int i = index; i < (numKrb + 1); i++) {
                logger.debug("Inserting totalCookie [i=" + (i) + "]");
                logger.debug("with cookie: " + krbCookies.elementAt(krbIndex));
                totalCookies[i] = krbCookies.elementAt(krbIndex);
                krbIndex++;
                index++;
            }
        }
        //getting nonKrb cookies
        if (numNonKrb > 0) {
            int nonKrbIndex = 0;
            for (int j = index; j < numCookies; j++) {
                logger.debug("Inserting totalCookie [j=" + (j) + "]: ");
                logger.debug("with cookie: " + 
                             nonKrbCookies.elementAt(nonKrbIndex));
                totalCookies[j] = nonKrbCookies.elementAt(nonKrbIndex);
                nonKrbIndex++;
            }
        }

        userSession.setCookies(totalCookies);
    }

    /**
     * Gets a cookie from the request
     * 
     * @param request HTTP request
     * @param cookieName cookie name
     * 
     * @return cookie (if it exists)
     */
    private Cookie getCookie(HttpServletRequest request, String cookieName) {

        Cookie cookie = null;
        Cookie[] cookies = null;

        // Retrieve cookies from the request
        cookies = request.getCookies();

        // Protection: look for auth and referer cookies
        if (cookies != null) {

            // Look for the referer cookie
            for (int i = 0; i < cookies.length; i++) {

                // Look for the referer cookie
                if ((cookies[i].getName()).equals(cookieName)) {

                    // Cache cookie
                    cookie = cookies[i];

                    logger.debug("Cookie already exists: " + 
                                 cookie.getValue());

                    // Exit
                    break;
                }

            }

        }

        return cookie;

    }

    /**
     * Add a new cookie to the response
     * 
     * @param response HTTP response
     * @param krbCookie cookie
     */
    private void addKrbCookie(HttpServletResponse response, Cookie krbCookie) {
        boolean sendCookies = true;
        if (valveConf.getSessionConfig().isSessionEnabled().equals("true")) {
            if (valveConf.getSessionConfig().getSendCookies().equals("false")) {
                sendCookies = false;
            }
        }
        if (!sendCookies) {
            //add Krb cookie into the response
            response.addCookie(krbCookie);
        }
    }

    /**
     * Adds a new Kerberos subject into the vector
     * 
     * @param key subject key
     * @param sub subject
     */
    private void addKrbSubject(String key, Subject sub) {
        krbSubjects.put(key, sub);
    }

    /**
     * Gets a kerberos subject from the vector
     * 
     * @param key subject key
     * 
     * @return subject
     */
    private Subject getKrbSubject(String key) {
        Subject sub = null;
        if (krbSubjects != null) {
            sub = krbSubjects.get(key);
        }
        return sub;
    }

    /**
     * Deletes a Kerberos subject
     * 
     * @param key subject key
     * 
     * @return if the subject was deleted
     */
    private boolean deleteKrbSubject(String key) {
        Subject sub = null;
        boolean result = false;
        if (krbSubjects != null) {
            sub = krbSubjects.remove(key);
            if (sub != null) {
                result = true;
            }
        }
        return result;
    }

    /**
     * Looks for Kerberos credentials in the credentials
     * 
     * @return
     */
    private boolean lookForKrbCreds() {
        //check if Krb subject is Ok
        boolean krbCredFound = false;
        if (creds.getCredential(KRB5_ID) != null) {
            Subject krbSubject = creds.getCredential(KRB5_ID).getSubject();
            if (krbSubject != null) {
                krbCredFound = true;
                //set new Krb cred
                creds.getCredential(KRB5_ID).setKrbSubject(krbSubject);
            }
        }
        return krbCredFound;
    }

    /**
     * Creates credentials for managing double authentication
     * 
     * @param request HTTP request
     * @param krbSubject user subject
     */
    private void createCredsDoubleAuthN(HttpServletRequest request, 
                                        Subject krbSubject) {
        //set creds
        String username = request.getParameter("UserIDKrb");
        String password = request.getParameter("PasswordKrb");

        //Add krb creds
        Credential krb5Cred = new Credential(KRB5_ID);
        krb5Cred.setKrbSubject(krbSubject);
        krb5Cred.setUsername(getPrincipalFromSubject(krbSubject));
        creds.add(krb5Cred);

        //Add root creds
        Credential rootCred = new Credential("root");
        rootCred.setUsername(username);
        rootCred.setPassword(password);
        //add them to creds
        creds.add(rootCred);

    }

    /**
     * Gets the principal from the subject
     * 
     * @param subject user subject
     * 
     * @return principal
     */
    public String getPrincipalFromSubject(Subject subject) {

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
     * Sets Valve configuration parameters
     * 
     * @param request HTTP request
     */
    public void setValveParams(HttpServletRequest request) {

        // Read HTTP request attributes
        try {
            authCookieName = valveConf.getAuthCookieName();
            logger.debug("authCookieName: " + authCookieName);
            refererCookieName = valveConf.getRefererCookieName();
            logger.debug("refererCookieName: " + refererCookieName);

            authCookieDomain = valveConf.getAuthCookieDomain();
            authCookiePath = valveConf.getAuthCookiePath();
            try {
                authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());
            } catch (NumberFormatException nfe) {
            }
            authenticationProcessClsName = 
                    valveConf.getAuthenticationProcessImpl();
            KrbLoginUrl = valveConf.getKrbConfig().getKrbLoginUrl();
            KrbUsrPwdCrawlerUrl = 
                    valveConf.getKrbConfig().getKrbUsrPwdCrawlerUrl();
            loginUrl = valveConf.getLoginUrl();

            //Set Kerberos and Session vars
            maxSessionAge = 
                    (new Long(valveConf.getSessionConfig().getMaxSessionAge())).longValue();
            sessionTimeout = 
                    (new Long(valveConf.getSessionConfig().getSessionTimeout())).longValue();
            sessionCleanup = 
                    (new Long(valveConf.getSessionConfig().getSessionCleanup())).longValue();

            //Is it SAML
            if (valveConf.getSAMLConfig().isSAML().equals("true")) {
                isSAML = true;
            }

            //Is it Kerberos?
            if (valveConf.getKrbConfig().isKerberos().equals("true")) {
                isKerberos = true;
                //Is it Negotiate?
                if (valveConf.getKrbConfig().isNegotiate().equals("true")) {
                    isNegotiate = true;
                } else {
                    isNegotiate = false;
                }
            } else {
                isKerberos = false;
            }

            //Set Session Vars
            if (valveConf.getSessionConfig().isSessionEnabled().equals("true")) {
                isSessionEnabled = true;
            } else {
                isSessionEnabled = false;
            }


            if (valveConf.getKrbConfig().isKrbUsrPwdCrawler().equals("true")) {
                KrbUsrPwdCrawler = true;
            } else {
                KrbUsrPwdCrawler = false;
            }

            if (valveConf.getKrbConfig().isKrbAdditionalAuthN().equals("true")) {
                KrbAdditionalAuthN = true;
            } else {
                KrbAdditionalAuthN = false;
            }

            //Session support: cleanup process
            if ((isSessionEnabled) || (isKerberos)) {
                logger.debug("Getting sessionTimer instance");
                sessionTimer = 
                        SessionTimer.getInstance(isSessionEnabled, isKerberos, 
                                                 sessionCleanup);
                sessionTimer.setTimer();
            }

        } catch (Exception e) {
            logger.error("Exception reading Configuration parameters: " + 
                         e.getMessage(), e);
        }
    }

    /**
     * Reads the valve configuration path
     * 
     * @return
     */
    public String readValveConfigPath() {

        String valveConfigPath = null;

        try {
            //Get Config
            javax.naming.Context ctx = new javax.naming.InitialContext();
            javax.naming.Context env = 
                (javax.naming.Context)ctx.lookup("java:comp/env");

            //Get gsaValveConfigPath
            valveConfigPath = (String)env.lookup("gsaValveConfigPath");
        } catch (NamingException e) {
            logger.debug("Error when reading the Valve Config Path " + e);
        }

        return valveConfigPath;
    }

    /**
     * Creates the referer cookie
     * 
     */
    public void createRefererCookie() {
        // Instantiate authentication cookie with default value
        gsaRefererCookie = 
                new Cookie(refererCookieName, valveConf.getTestFormsCrawlUrl());

        // Set cookie domain
        gsaRefererCookie.setDomain(authCookieDomain);

        // Set cookie path
        gsaRefererCookie.setPath(authCookiePath);

        // Set expiration time
        gsaRefererCookie.setMaxAge(authMaxAge);
    }

    /**
     * Redirects the user back to the client's URL that checks the SAML 
     * authentication process
     * 
     * @param response HTTP response
     * @param cookies authentication cookies
     * @param sessionID session identifier
     * 
     * @throws IOException
     */
    public void redirectingSAML(HttpServletResponse response, Cookie[] cookies, 
                                String sessionID) throws IOException {
        //create the artifact
        long maxArtifactAge = 
            new Long(valveConf.getSAMLConfig().getMaxArtifactAge()).longValue();
        //Instead of using the username, we'll use the session id
        String artifact = 
            SAMLArtifactProcessor.getInstance(maxArtifactAge).storeArtifact(sessionID);

        //Create the referer var                    
        refererSAML = 
                ValveUtils.getGSAHost("", valveConf, cookies, valveConf.getRefererCookieName());

        //redirect to the GSA's Artifact consumer
        SAMLAuthN samlAuthN = new SAMLAuthN();
        String redirectURL = null;
        try {
            redirectURL = 
                    samlAuthN.redirectLocation(refererSAML, relayState, artifact);
        } catch (UnsupportedEncodingException e) {
            logger.error("Error when creating the SAML redirecting URL: " + e);
        }
        logger.debug("SAML:Redirecting to " + redirectURL);
        response.sendRedirect(redirectURL);
    }

    /**
     * Constructs the SAML URL for Kerberos authentication
     * 
     * @return SAML URL for Kerberos authentication
     */
    public String contructKrbLoginURL() {

        String loginURL = null;

        try {
            boolean isSAML = 
                new Boolean(valveConf.getSAMLConfig().isSAML()).booleanValue();

            if (!isSAML) {
                loginURL = KrbLoginUrl;
            } else {
                loginURL = 
                        KrbLoginUrl + "?SAMLRequest=" + URLEncoder.encode(samlRequest, 
                                                                          encoder) + 
                        "&RelayState=" + 
                        URLEncoder.encode(relayState, encoder);
            }

        } catch (Exception ex) {
            logger.error("Error during Kerberos Login URL construction: " + 
                         ex);
        }

        return loginURL;

    }

    /**
     * Checks if it's a Kerberos process when there is double authentication 
     * process.
     * 
     * @param krbCookie kerberos authentication cookie
     * 
     * @return boolean - if it's Kerberos processing point
     */
    public boolean isKrbProcess(Cookie krbCookie) {

        boolean isKrbProcess = false;

        try {
            if ((krbCookie != null) && (!isSAML)) {
                isKrbProcess = false;
            } else {
                if (!isSAML) {
                    //Krb cookie exists for Forms based authentication
                    isKrbProcess = true;
                } else {
                    //is SAML
                    if (krbCookie == null) {
                        //Krb cookie does not exist. First authentication process
                        //Lets process Krb authn
                        isKrbProcess = true;
                    } else {
                        //check if this is part of first authentication process
                        //or it's part of a reauthenication one (so that the krb cookie already exists)
                        Subject krbSubj = getKrbSubject(krbCookie.getValue());

                        if (krbSubj == null) {
                            //the Krb process has not been launched yet
                            isKrbProcess = true;
                        } else {
                            //the Krb process was already launched
                            isKrbProcess = false;
                        }

                    }
                }
            }

        } catch (Exception ex) {
            logger.error("Error during checking if it's Kerberos process: " + 
                         ex);
            isKrbProcess = false;
        }

        return isKrbProcess;

    }

}
