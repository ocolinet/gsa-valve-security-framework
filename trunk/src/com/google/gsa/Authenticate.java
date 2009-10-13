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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import com.google.gsa.sessions.SessionTimer;

import com.google.gsa.sessions.Sessions;
import com.google.gsa.sessions.UserIDEncoder;
import com.google.gsa.sessions.UserSession;

import com.google.gsa.valve.configuration.ValveConfiguration;

import com.google.gsa.valve.configuration.ValveConfigurationException;
import com.google.gsa.valve.configuration.ValveConfigurationInstance;
import com.google.gsa.valve.errormgmt.ErrorManagement;

import com.google.gsa.valve.saml.SAMLArtifactProcessor;
import com.google.gsa.valve.saml.authn.SAMLAuthN;
import com.google.gsa.valve.utils.ValveUtils;

import java.net.URLEncoder;

import java.util.Vector;

import org.apache.log4j.Logger;

import javax.security.auth.Subject;


/**
 * This is the main authentication servlet when a login form is being used to 
 * get user credentials. It implements the whole authentication process when 
 * the username and password is collected up and starts the global authentication 
 * process for the user.
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
public class Authenticate extends HttpServlet {

    private static final long serialVersionUID = -8944353938289271212L;

    private static Logger logger = null;

    private ValveConfiguration valveConf;

    //Vars for Krb support
    private boolean isKerberos = false;

    //Session Management Var
    private boolean isSessionEnabled = false;
    long maxSessionAge;
    long sessionTimeout;
    long sessionCleanup;
    SessionTimer sessionTimer;

    public static final long SEC_IN_MIN = 60;

    private static final String KRB5_ID = "krb5";
    
    //authn process class name
    String authenticationProcessClsName = null;     

    //Cookie vars            
    String authCookieDomain = null;
    String authCookiePath = null;
    String authCookieName = null;
    int authMaxAge = 300;
    String refererCookieName = null;    

    ErrorManagement errorMngmt = null;

    //Encoding
    static String encoder = "UTF-8";

    //SAML
    boolean isSAML = false;
    String refererSAML = null;
    String relayState = null;
    String samlRequest = null;


    static {

        // Instantiate logger
        logger = Logger.getLogger(Authenticate.class);

    }

    /**
     * Servlet's doPost: processes the POST request coming from the login form
     * 
     * @param request
     * @param response
     * @throws IOException
     * @throws ServletException
     */
    public void doPost(HttpServletRequest request, 
                       HttpServletResponse response) throws IOException, 
                                                            ServletException {

        logger.debug("Authenticate: doPost");

        // Read XML config file pointer                
        String gsaValveConfigPath = null;

        //SAML
        if (request.getAttribute("gsaValveConfigPath") == null) {
            //Get Parameter instead of attribute: SAML
            gsaValveConfigPath = 
                    request.getParameter("gsaValveConfigPath").toString();
        } else {
            gsaValveConfigPath = 
                    request.getAttribute("gsaValveConfigPath").toString();
        }


        logger.debug("Config file: " + gsaValveConfigPath);

        //Create the credentials store
        try {
            this.valveConf = 
                    ValveConfigurationInstance.getValveConfig(gsaValveConfigPath);
        } catch (ValveConfigurationException e) {
            logger.error("Valve Config instantiation error: " + e);
        }

        //credentials                
        Credentials creds = new Credentials();
        String username = null;
        
        //GSA Authn cookie
        Cookie gsaAuthCookie = null;

        //authCookies vector
        Vector<Cookie> authCookies = new Vector<Cookie>();
        
        //AuthN process instance        
        AuthenticationProcessImpl authenticationProcessCls = null;

        logger.debug("Authenticate servlet Start");

        //Read config vars from file
        boolean isConfigOK = setValveParams(request);
        logger.debug("Checking if vars were read properly");
        //protect
        if (!isConfigOK) {
            logger.error("Configuration is not OK. Check your config file but either you are trying to use Kerberos Negotiation (use the Kerberized frontend instead)" + 
                         "or Kerberos is active but Session does not (they have to be as well). Please review documentation before proceeding");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                               "Bad configuration. Contact application administrator");
            return;
        }

        //Session ID vars definition
        String sessionID = null;
        String encodedSessionID = null;

        Cookie cookies[] = null;
        Cookie gsaRefererCookie = null;

        // Retrieve cookies
        cookies = request.getCookies();
        logger.debug(cookies.length + " cookies found before authenticating");
        // Protection
        if (cookies != null) {

            // Look for the referer cookie
            for (int i = 0; i < cookies.length; i++) {
                logger.trace(cookies[i].getName() + ":" + 
                             cookies[i].getValue());
                // Look for the referer cookie
                if ((cookies[i].getName()).equals(refererCookieName)) {

                    // Cache cookie
                    gsaRefererCookie = cookies[i];

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
            boolean noParams = false;

            //Protection
            if ((relayState == null) || (relayState.equals(""))) {
                noParams = true;
            } else {
                if ((samlRequest == null) || (samlRequest.equals(""))) {
                    noParams = true;
                }
            }

            if (noParams) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, 
                                   "Invalid request");
                return;
            }

        }

        //Setting root credentials coming from the login form
        username = settingRootCredentials(creds, request);
        logger.debug("Username is: " + username);

        // Instantiate the authentication process class
        try {

            // Instantiate the authorization process class
            authenticationProcessCls = 
                    (AuthenticationProcessImpl)Class.forName(authenticationProcessClsName).newInstance();

            authenticationProcessCls.setValveConfiguration(valveConf);


        } catch (InstantiationException e) {

            // Log error
            logger.error("InstantiationException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");

            // Return
            return;

        } catch (IllegalAccessException e) {

            // Log error
            logger.error("IllegalAccessException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");

            // Return
            return;

        } catch (ClassNotFoundException e) {

            // Log error
            logger.error("ClassNotFoundException - Authentication servlet parameter [authenticationProcessImpl] has not been set correctly");
            logger.error("Cannot find class: " + authenticationProcessClsName);

            // Return
            return;

        }

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        //creation time var
        long creationTime = System.currentTimeMillis();

        //Instantiate authentication cookie with creation time
        //SET a value for the USERID
        sessionID = UserIDEncoder.getID(username, creationTime);
        encodedSessionID = URLEncoder.encode(sessionID, encoder);
        gsaAuthCookie = new Cookie(authCookieName, encodedSessionID);

        // Set cookie domain
        gsaAuthCookie.setDomain(authCookieDomain);

        // Set cookie path
        gsaAuthCookie.setPath(authCookiePath);

        // Set expiration time
        gsaAuthCookie.setMaxAge(authMaxAge);

        try {

            // Execute the authentication process in here
            if (!isSAML) {
                statusCode = 
                        authenticationProcessCls.authenticate(request, response, 
                                                              authCookies, 
                                                              gsaRefererCookie.getValue(), 
                                                              creds, null);
            } else {
                statusCode = 
                        authenticationProcessCls.authenticate(request, response, 
                                                              authCookies, 
                                                              valveConf.getTestFormsCrawlUrl(), 
                                                              creds, null);
            }

        } catch (Exception e) {

            // Debug
            logger.error("Authentication process raised exception: " + 
                         e.getMessage(), e);

        }

        // Protection
        if (statusCode != HttpServletResponse.SC_OK) {

            //Send personalized error message (if any)
            try {
                //create the instance if it does not exist
                if (errorMngmt == null) {
                    errorMngmt = 
                            new ErrorManagement(valveConf.getErrorLocation());
                }

                //protection
                if (errorMngmt != null) {
                    errorMngmt.showHTMLError(response, 
                                             errorMngmt.processError(statusCode));
                }

            } catch (ValveConfigurationException e) {
                logger.error("Configuration error: " + e);
            }

            // Raise error
            response.setStatus(statusCode);

            // Debug
            if (logger.isDebugEnabled())
                logger.debug("Authentication process failed");

            // Return
            return;

        }

        //Session support
        if (isSessionEnabled) {

            logger.error("Session is enabled");
            UserSession userSession = new UserSession();
            userSession.setUserName(username);
            userSession.setSessionCreationTime(creationTime);
            userSession.setSessionLastAccessTime(creationTime);

            //Manage Cookies
            //add Auth Cookie to the authCookies vector
            authCookies.add(gsaAuthCookie);
            //add cookies to session
            userSession.setCookies(setCookieArray(authCookies));
            //add creds                    
            userSession.setUserCredentials(creds);

            if (isKerberos) {

                //get credentials
                boolean nonValidCred = getKrbCredentials(creds, userSession);

                if (nonValidCred) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, 
                                       "Credentials not valid");

                    // Log error
                    logger.error("Kerberos Subject has not been created properly");

                    // Return
                    return;
                }

            }

            //Store Session in the Session Map
            Sessions sessions = Sessions.getInstance();
            //Setting session times
            sessions.setMaxSessionAgeMinutes(maxSessionAge);
            sessions.setSessionTimeoutMinutes(sessionTimeout);
            sessions.addSession(sessionID, userSession);

            logger.debug("User Session created");
        }

        // Add internal authentication cookie
        response.addCookie(gsaAuthCookie);

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
            //create the artifact
            long maxArtifactAge = 
                new Long(valveConf.getSAMLConfig().getMaxArtifactAge()).longValue();
            //Instead of using the username, we'll use the session id
            String artifact = 
                SAMLArtifactProcessor.getInstance(maxArtifactAge).storeArtifact(sessionID);

            //Create the referer var

            //redirect to the GSA's Artifact consumer
            try {
                refererSAML =
                    ValveUtils.getGSAHost("", valveConf, cookies, valveConf.getRefererCookieName());            
                SAMLAuthN samlAuthN = new SAMLAuthN();
                String redirectURL = 
                    samlAuthN.redirectLocation(refererSAML, relayState, artifact);
                logger.debug("SAML:Redirecting to " + redirectURL);
                response.sendRedirect(redirectURL);
            } catch (ValveConfigurationException e) {
                logger.error ("Configuration error: "+ e.getMessage(),e);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }

    }

    /**
     * Servlet's doGet: processes a GET request (only valid for kerberos 
     * requests)
     * 
     * @param request HTTP request
     * @param response HTTP response
     * 
     * @throws IOException
     * @throws ServletException
     */
    public void doGet(HttpServletRequest request, 
                      HttpServletResponse response) throws IOException, 
                                                           ServletException {

        //Add support for Kerberos    
        if ((request.getAttribute("isKerberos")).toString().equals("true")) {

            doPost(request, response);

        } else {

            // Raise error
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                               "The GSA Authenticate servlet does not accept GET requests!");
        }

    }

    /**
     * Transforms a Cookie vector into a cookie array
     * 
     * @param authCookies cookie vector
     * 
     * @return cookie array
     */
    public Cookie[] setCookieArray(Vector<Cookie> authCookies) {
        Cookie[] arrayCookie = null;
        if (!authCookies.isEmpty()) {
            logger.debug("Cookie array is not null. Contains " + 
                         authCookies.size() + " entries");
            arrayCookie = new Cookie[authCookies.size()];
            for (int i = 0; i < authCookies.size(); i++) {
                logger.debug("Cookie [" + i + "]: " + 
                             authCookies.elementAt(i).getName() + ":" + 
                             authCookies.elementAt(i).getValue());
                arrayCookie[i] = authCookies.elementAt(i);
            }
        }
        return arrayCookie;
    }

    /**
     * Gets Kerberos credentials from the user session
     * 
     * @param creds credentials
     * @param userSession user session
     * 
     * @return boolean - if Krb credentials exists
     */
    public boolean getKrbCredentials(Credentials creds, 
                                     UserSession userSession) {
        boolean nonValidCred = true;
        try {
            if (creds.getCredential(KRB5_ID) != null) {
                Subject krbSubject = creds.getCredential(KRB5_ID).getSubject();
                if (krbSubject != null) {
                    logger.error("Kerberos Subject exists");

                    userSession.setKerberosCredentials(krbSubject);

                    nonValidCred = false;
                }

            }
        } catch (Exception e) {
            logger.error("Error getting Krb credentials: " + e.getMessage(), 
                         e);
            nonValidCred = true;
        }
        return nonValidCred;
    }

    /**
     * Sets the Valve configuration parameters
     * 
     * @param request HTTP request
     * 
     * @return boolean - if config is OK
     */
    public boolean setValveParams(HttpServletRequest request) {

        boolean isConfigOK = true;
        // Read HTTP request attributes
        logger.debug("Reading configuration vars");
        try {

            authCookieName = valveConf.getAuthCookieName();
            logger.debug("authCookieName: " + authCookieName);
            //refererCookieName = (request.getAttribute("refererCookie")).toString();
            refererCookieName = valveConf.getRefererCookieName();
            logger.debug("refererCookieName: " + refererCookieName);

            authCookieDomain = valveConf.getAuthCookieDomain();
            authCookiePath = valveConf.getAuthCookiePath();
            try {
                authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());
            } catch (NumberFormatException nfe) {
                logger.error ("Invalid authMaxAge value in the config: "
                              + nfe.getMessage());
                logger.error ("Setting authMaxAge to -1...");
                authMaxAge = -1;
            }
            authenticationProcessClsName = 
                    valveConf.getAuthenticationProcessImpl();

            //Is it SAML
            if (valveConf.getSAMLConfig().isSAML().equals("true")) {
                isSAML = true;
            }

            //Is it Kerberos?
            if (valveConf.getKrbConfig().isKerberos().equals("true")) {
                isKerberos = true;
                maxSessionAge = 
                        (new Long(valveConf.getSessionConfig().getMaxSessionAge())).longValue();
                //Is it Negotiate?
                if (valveConf.getKrbConfig().isNegotiate().equals("true")) {
                    //Negotiation can not be used. Use Kerberos frontend instead
                    isConfigOK = false;
                } else {
                    if (valveConf.getSessionConfig().isSessionEnabled().equals("false")) {
                        //Session has to be enabled if Kerberos is used
                        isConfigOK = false;
                    }
                }
            } else {
                isKerberos = false;
            }

            //Set Session Vars
            if (valveConf.getSessionConfig().isSessionEnabled().equals("true")) {
                isSessionEnabled = true;
                //Set Kerberos and Session vars
                maxSessionAge = 
                        (new Long(valveConf.getSessionConfig().getMaxSessionAge())).longValue();
                sessionTimeout = 
                        (new Long(valveConf.getSessionConfig().getSessionTimeout())).longValue();
                sessionCleanup = 
                        (new Long(valveConf.getSessionConfig().getSessionCleanup())).longValue();
            } else {
                isSessionEnabled = false;
            }

            //if ((isSessionEnabled)||(isKerberos)) {
            if (isSessionEnabled) {
                logger.debug("Getting sessionTimer instance");
                sessionTimer = 
                        SessionTimer.getInstance(isSessionEnabled, isKerberos, 
                                                 sessionCleanup);
                sessionTimer.setTimer();
            }
        } catch (NullPointerException e) {
            logger.error("Null pointer exception when setting config vars: " + 
                         e.getMessage(), e);
            isConfigOK = false;
        } catch (Exception e) {
            logger.error("Exception when setting config vars: " + 
                         e.getMessage(), e);
            isConfigOK = false;
        }

        return isConfigOK;
    }

    /**
     * Setting root credentials that are coming in the HTTP request
     * 
     * @param creds credentials
     * @param request HTTP request 
     * 
     * @return username
     */
    public String settingRootCredentials(Credentials creds, 
                                         HttpServletRequest request) {

        String username = null;
        try {
            // Read HTTP request parameters
            username = request.getParameter("UserID");
            logger.debug("Adding credentials for root to credentials store");
            Credential rootCred = new Credential("root");
            rootCred.setUsername(username);
            rootCred.setPassword(request.getParameter("Password"));
            creds.add(rootCred);
        } catch (Exception e) {
            logger.error("Error when getting credentials from parameters");
        }

        return username;

    }

}
