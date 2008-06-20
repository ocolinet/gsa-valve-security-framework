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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;
import org.apache.regexp.RE;
import org.apache.regexp.RESyntaxException;

import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.sessions.Sessions;
import com.google.gsa.sessions.UserSession;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveRepositoryConfiguration;
import com.google.gsa.valve.utils.URLUTF8Encoder;

import com.google.gsa.sessions.nonValidSessionException;

import java.io.UnsupportedEncodingException;

import java.net.URL;

import java.util.Vector;


/**
 * This is the default class that drives the authorization process based on the 
 * repositories declared in the config file, where the individual authorization 
 * class is included there as well.
 * <p>
 * The name of the authentication classes that need to be processed are included 
 * in a vector that is reused multiple times to check if URL patterns with any 
 * of them. If there is any URL pattern defined in the config file that 
 * matches with the url sent to the authorize() method, a new authorization 
 * class of that kind is created.
 * <p>
 * At the end, it collects the error message coming from the specific 
 * authorization class' authorize() method. If there is any problem during 
 * the processing, it's returned as well.
 * 
 * @see RootAuthenticationProcess
 * 
 */
public class RootAuthorizationProcess implements AuthorizationProcessImpl {

    //logger	
    private Logger logger = null;

    //Valve configuration
    private ValveConfiguration valveConf = null;

    private static Vector<ValveRepositoryConfiguration> repositoryConfigurations = 
        null;

    //Krb and session vars
    private static boolean isKerberos = false;
    private static boolean isSessionEnabled = false;
    private static boolean isSAML = false;
    private static boolean sendCookies = true;
    private static int sessionVarsSet = -1;

    private static String authCookieName = null;
    private static String internalURL = null;

    private Sessions sessions = null;

    private static final String ENCODING = "UTF-8";


    /**
     * Class constructor
     * 
     */
    public RootAuthorizationProcess() {

        // Invoke parent constructor
        super();

        logger = Logger.getLogger(RootAuthorizationProcess.class);

    }

    /**
     * Sets user credentials
     * 
     * @param creds
     */
    public void setCredentials(Credentials creds) {
        //do nothing
    }


    /**
     * 
     * This is the default root authorize method that manages the whole 
     * authorization lifecycle when accessing the backend repositories.
     * <p>
     * Based on the information included in the config file, it uses that 
     * information to manage the authorization process. If there is any URL 
     * pattern defined in the config file that matches with the url sent to 
     * the authorize() method, a new authorization class of that kind is created.
     * <p>
     * At the end, it collects the error message coming from the specific 
     * authorization class' authorize() method. If there is any problem during 
     * the processing, it's returned as well.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param authCookies vector that contains the authentication cookies
     * @param url the document url
     * @param id the default credential id
     * 
     * @return the HTTP error code
     * 
     * @throws HttpException
     * @throws IOException
     */
    public int authorize(HttpServletRequest request, 
                         HttpServletResponse response, Cookie[] authCookies, 
                         String url, String id) throws HttpException, 
                                                       IOException, 
                                                       nonValidSessionException {

        logger.debug("Authorize");

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
        boolean patternMatch = false;
        boolean rootIDExists = false;

        //UserSession
        UserSession userSession = null;

        //GSA cookie
        Cookie gsaAuthCookie = null;

        //Encoding support
        String newURL = null;

        //Try to avoid the double encoding problem
        try {
            newURL = URLDecoder.decode(url, ENCODING);
        } catch (IllegalArgumentException e) {
            logger.error("Illegal Argument when decoding/encoding URL");
            newURL = url;
        }
        URLUTF8Encoder encoder = new URLUTF8Encoder();
        url = encoder.encodeURL(new URL(newURL));

        //read vars
        if (valveConf != null) {
            //Set config vars
            setValveConf();

        } else {
            logger.error("Configuration error: Config file is not present");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                               "Configuration error - Kerberos is not set properly");
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        //set auth Cookie                                
        Cookie[] cookies = request.getCookies();

        //SAML
        if (cookies == null) {
            cookies = authCookies;
        }

        if (cookies != null) {
            logger.debug("authCookieName is: " + authCookieName);
            for (int i = 0; i < cookies.length; i++) {
                logger.debug("Cookie found: " + cookies[i].getName() + 
                             "; value=" + cookies[i].getValue());
                if (cookies[i].getName().equals(authCookieName)) {
                    gsaAuthCookie = cookies[i];
                    logger.debug("Auth Cookie found!");
                    break;
                }
            }
        }

        //manage Sessions                
        if (isSessionEnabled) {
            logger.debug("Session is enabled. Getting session instance");
            try {

                //Session Support. Get Sessions instance            
                sessions = Sessions.getInstance();

                //Get user session
                userSession = manageSessions(gsaAuthCookie);

            } catch (nonValidSessionException nVS) {
                //throw Exception
                throw nVS;
            } catch (Exception e) {
                logger.error("Error when geting session: " + e.getMessage(), 
                             e);
            }

        }


        //setting auth cookies
        if ((!isSessionEnabled) || 
            ((isSessionEnabled) && (sendCookies) && (!isSAML))) {
            //send auth cookies as those coming straight from the browser
            authCookies = request.getCookies();
        } else {
            //auth cookies are those that are in the session
            authCookies = userSession.getCookies();
        }

        logger.debug("Authz authorizing [" + url + "]");


        //protection
        if (repositoryConfigurations == null) {
            logger.error("Authorization Repository Vector has not been initialized");
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        //Pattern of the host that has been confiogured that needs to be macthed to the URL that is being authorized.
        RE authZHost = null;

        //The host of the GSA, need to detect a request from this host and skip past it
        RE queryHostRE = null;
        try {
            queryHostRE = new RE("/search", RE.MATCH_CASEINDEPENDENT);
        } catch (RESyntaxException reSynTaxExp) {
            logger.error("Failed to created queryHost RE: " + 
                         reSynTaxExp.getMessage());
        }

        ValveRepositoryConfiguration repository = null;

        logger.debug("Repository length: " + repositoryConfigurations.size());

        for (int i = 0; i < repositoryConfigurations.size(); i++) {

            repository = repositoryConfigurations.elementAt(i);

            logger.debug("Repository ID: " + repository.getId());

            //Pattern for this repository that needs to be macthed
            try {
                authZHost = 
                        new RE(repository.getPattern(), RE.MATCH_CASEINDEPENDENT);
            } catch (RESyntaxException reSynTaxExp) {
                logger.error("Failed to created authZHost RE: " + 
                             reSynTaxExp.getMessage());
                logger.error("Pattern trying to use: " + 
                             repository.getPattern());
            }


            if (queryHostRE.match(url)) {
                logger.debug("Query AuthZ");
                statusCode = HttpServletResponse.SC_OK;
                patternMatch = true;
            } else {
                if (authZHost.match(url)) {

                    //Need the correct authZProcess implementation for this repository ID
                    AuthorizationProcessImpl authZProcess = 
                        getAuthorizationProcess(repository);

                    if (authZProcess != null) {
                        //URL matches a pattern
                        if (repository.getId().equals("root")) {
                            //If this is a match for the root id then it's the internal host used to test valve/test.html, so should just return valid
                            logger.debug("Internal AuthZ");
                            statusCode = HttpServletResponse.SC_OK;
                            patternMatch = true;
                            rootIDExists = true;
                        } else {
                            logger.info("Authorizing with " + 
                                        repository.getId());
                            patternMatch = true;

                            //Add credentials
                            try {
                                addCredentials(authZProcess, userSession);
                            } catch (Exception e) {
                                logger.error("Error during Kerberos authZ treatment : " + 
                                             e.getMessage(), e);
                            }

                            try {
                                String repoID = repository.getId();
                                statusCode = 
                                        authZProcess.authorize(request, response, 
                                                               authCookies, 
                                                               url, repoID);
                                //If statusCode is UNAUTHORIZED, then the process has to stop here
                                if (statusCode == 
                                    HttpServletResponse.SC_UNAUTHORIZED) {
                                    break;
                                }
                            } catch (Exception e) {
                                logger.error("Error during authorization: " + 
                                             e.getMessage(), e);
                            }
                        }
                    } else {
                        logger.debug("The URL matches with the pattern defined for repository " + 
                                     "[" + repository.getId() + 
                                     "] but could not instantiate the class");
                    }
                }

            }

        }
        if (!patternMatch) {
            //check if "root" repository was created in the config file
            //if not: check if the URL is a Valve one. If so, return SC_OK
            if (!rootIDExists) {
                RE internalRE = 
                    new RE(new URL(internalURL).getHost(), RE.MATCH_CASEINDEPENDENT);
                boolean samePorts = 
                    (((new URL(internalURL)).getPort()) == ((new URL(url)).getPort()));
                if ((internalRE.match(url)) && (samePorts)) {
                    logger.debug("This is an internal URL");
                    statusCode = HttpServletResponse.SC_OK;
                } else {
                    logger.debug("No pattern has been defined at any repository for this URL");
                    //Set Status Code equal to "-1", so we do know there was no pattern found
                    statusCode = -1;
                }
            } else {
                logger.debug("No pattern has been defined at any repository for this URL");
                //Set Status Code equal to "-1", so we do know there was no pattern found
                statusCode = -1;
            }
        }

        //protection
        userSession = null;

        return statusCode;
    }

    /**
     * Gets the authorization process instance needed to process the request
     * 
     * @param repository the repository configuration information
     * 
     * @return the authorization class 
     */
    private AuthorizationProcessImpl getAuthorizationProcess(ValveRepositoryConfiguration repository) {

        AuthorizationProcessImpl authProcess = null;

        //protection
        if (repository != null) {

            try {

                String authZComponent = repository.getAuthZ();
                logger.debug("Authorization module is: " + authZComponent);

                if (authZComponent != null) {
                    authProcess = 
                            (AuthorizationProcessImpl)Class.forName(authZComponent).newInstance();
                    authProcess.setValveConfiguration(valveConf);
                } else {
                    logger.debug("This repository[" + repository.getId() + 
                                 "] does not cointain any Authorization class");
                }

            } catch (LinkageError le) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthorizationProcess-LinkageError]: " + 
                             le.getMessage(), le);
                authProcess = null;
            } catch (InstantiationException ie) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthorizationProcess-InstantiationException]: " + 
                             ie.getMessage(), ie);
                authProcess = null;
            } catch (IllegalAccessException iae) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthorizationProcess-IllegalAccessException]: " + 
                             iae.getMessage(), iae);
                authProcess = null;
            } catch (ClassNotFoundException cnfe) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthorizationProcess-ClassNotFoundException]: " + 
                             cnfe.getMessage(), cnfe);
                authProcess = null;
            } catch (Exception e) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthorizationProcess-Exception]: " + 
                             e.getMessage(), e);
                authProcess = null;
            }
        }

        return authProcess;
    }

    /**
     * Sets the Valve Configuration instance to read the parameters 
     * from there
     * 
     * @param valveConf the Valve configuration instance
     */
    public void setValveConfiguration(ValveConfiguration valveConf) {

        //if (this.valveConf == null) {
        logger.debug("Setting Valve Configuration");

        this.valveConf = valveConf;

        if (repositoryConfigurations == null) {
            setRepositoryConfigurations();
        }
        //}
    }

    /**
     * Sets the vector that contains all the authorization class names 
     * in order to process it more efficiently.
     * 
     */
    private void setRepositoryConfigurations() {

        //Instantiate each of the repositories defined in the configuration

        repositoryConfigurations = new Vector<ValveRepositoryConfiguration>();

        String repositoryIds[] = valveConf.getRepositoryIds();

        ValveRepositoryConfiguration repository = null;

        logger.debug("Reading repositories");

        for (int i = 0; i < repositoryIds.length; i++) {
            try {
                repository = valveConf.getRepository(repositoryIds[i]);
                if (repository.getAuthZ() == null || 
                    repository.getAuthZ().equals("")) {
                    logger.info("No authZ defined for " + repository.getId());
                } else {
                    logger.debug("Authorisation process for [" + 
                                 repository.getId() + "] found");
                    repositoryConfigurations.add(repository);
                }

            } catch (Exception e) {
                logger.error("Error during Authorization Vector creation: " + 
                             e.getMessage(), e);
            }
        }
        logger.debug("Authorization vector has been created");
    }


    /**
     * Sends the credentials store in the session to the backend application
     * 
     * @param authZProcess authorization process instance
     * @param userSession user session
     */
    public void addCredentials(AuthorizationProcessImpl authZProcess, 
                               UserSession userSession) {

        logger.debug("addCredentials method");

        try {

            if (userSession != null) {

                logger.debug("userSession is not empty: " + 
                             userSession.getUserName());

                Credentials credentials = userSession.getUserCredentials();

                if (credentials != null) {

                    logger.debug("Setting credentials for authorization");

                    //Adding credentials
                    authZProcess.setCredentials(credentials);

                } else {
                    logger.debug("There are no credentials available");
                }

            }

        } catch (Exception ex) {
            logger.error("Error when adding credentials: " + ex.getMessage(), 
                         ex);
        } finally {
        }

    }

    /**
     * It manages session and checks the session (if it exists) is still valid.
     * 
     * @param gsaAuthCookie authentication cookie
     * 
     * @return the user session if it exists, null otherwise
     * 
     * @throws nonValidSessionException
     */
    public UserSession manageSessions(Cookie gsaAuthCookie) throws nonValidSessionException {

        UserSession userSession = null;

        logger.debug("ManageSessions method. Check if Session is enabled [" + 
                     isSessionEnabled + "]");

        if (isSessionEnabled) {

            //check if the session is active
            logger.debug("The session is enabled");

            String userID = null;
            try {
                userID = URLDecoder.decode(gsaAuthCookie.getValue(), ENCODING);
            } catch (UnsupportedEncodingException e) {
                logger.error("Error during decoding Auth Cookie: " + 
                             e.getMessage(), e);
                userID = gsaAuthCookie.getValue();
            }

            logger.debug("the userID has been read: " + userID);

            boolean isSessionInvalid = sessions.isSessionInvalid(userID);
            logger.debug("Session invalidity checked: " + isSessionInvalid);
            if (isSessionInvalid) {
                //protect this code
                synchronized (sessions) {
                    logger.debug("the session is invalid");
                    boolean doesSessionStillExist = 
                        sessions.doesSessionExist(userID);
                    logger.debug("Session still exists: " + 
                                 doesSessionStillExist);
                    if (doesSessionStillExist) {
                        logger.debug("the session does exists: let's delete it");
                        //delete Session
                        sessions.deleteSession(userID);
                    }

                    logger.debug("Setting session invalidity");
                    throw new nonValidSessionException("The session is invalid. It does not longer exists");
                }

            } //end session invalid

            //look for the existing session
            userSession = sessions.getUserSession(userID);
            if (userSession == null) {

                logger.error("User Session is not valid");
                throw new nonValidSessionException("The session does not exists");

            } else {
                if (isSessionEnabled) {
                    //update the last access
                    int sessionTimeout = 
                        new Integer(valveConf.getSessionConfig().getSessionTimeout()).intValue();
                    if (sessionTimeout >= 0) {
                        long lastAccessTime = getCurrentTime();
                        if (lastAccessTime > 0) {
                            logger.debug("New access time: " + lastAccessTime);
                            userSession.setSessionLastAccessTime(lastAccessTime);
                            sessions.addSession(userID, userSession);
                        }
                    }
                }
            }

        }

        return userSession;
    }

    /**
     * Gets the current time
     * 
     * @return current time
     */
    public long getCurrentTime() {
        long currentTime = System.currentTimeMillis();
        return currentTime;
    }

    /**
     * Deletes all cookies that start with "gsa"
     * 
     * @param request HTTP request
     * @param response HTTP response
     */
    public void deleteCookies(HttpServletRequest request, 
                              HttpServletResponse response) {

        // Retrieve cookies
        Cookie[] allCookies = request.getCookies();
        try {
            // Protection
            if (allCookies != null) {

                // Look for the authentication cookie
                for (int i = 0; i < allCookies.length; i++) {

                    logger.debug("Cookie: " + allCookies[i].getName());

                    //look for all the cookies start with "gsa" and delete them
                    if ((allCookies[i].getName()).startsWith("gsa")) {

                        Cookie gsaCookie = 
                            new Cookie(allCookies[i].getName(), allCookies[i].getValue());

                        gsaCookie.setMaxAge(0);

                        response.addCookie(gsaCookie);

                        // Debug
                        if (logger.isDebugEnabled())
                            logger.debug("GSA cookie: [" + 
                                         gsaCookie.getName() + 
                                         " has been deleted ]");

                    }

                }

            }
        } catch (Exception e) {
            logger.error("Error when deleting cookies: " + e.getMessage(), e);
        }
    }

    /**
     * Gets the redirect URL when it's needed to reauthenticate
     * 
     * @param url request url
     * @param loginUrl login url 
     * 
     * @return the redirect url
     */
    public String redirectUrl(String url, String loginUrl) {
        //redirect
        String redirectUrl = null;
        if (url != null) {
            redirectUrl = loginUrl + "?returnPath=" + url;
        } else {
            redirectUrl = loginUrl;
        }
        logger.debug("redirecting to " + redirectUrl);
        return redirectUrl;
    }

    /**
     * Updates in the session the last access time
     * 
     * @param userSession user session
     */
    public void updateLastAccessTime(UserSession userSession) {
        long currentTime = System.currentTimeMillis();
        logger.debug("Last access time: " + 
                     userSession.getSessionLastAccessTime());
        userSession.setSessionLastAccessTime(currentTime);
    }

    /**
     * Reads only once the configuration parameter needed
     * 
     */
    private void setValveConf() {

        logger.debug("Starting setValveConf method");
        try {

            if (sessionVarsSet == -1) {
                //These vars have never been set for this instance

                isSessionEnabled = 
                        new Boolean(valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
                logger.debug("Setting isSessionEnabled: " + isSessionEnabled);

                isKerberos = 
                        new Boolean(valveConf.getKrbConfig().isKerberos()).booleanValue();
                logger.debug("Setting isKerberos: " + isKerberos);

                if (isSessionEnabled) {
                    sendCookies = 
                            new Boolean(valveConf.getSessionConfig().getSendCookies()).booleanValue();
                } else {
                    sendCookies = false;
                }
                logger.debug("Setting sendCookies: " + sendCookies);

                isSAML = 
                        new Boolean(valveConf.getSAMLConfig().isSAML()).booleanValue();
                logger.debug("Setting isSAML: " + isSAML);

                authCookieName = valveConf.getAuthCookieName();
                logger.debug("Setting authCookieName: " + authCookieName);

                internalURL = valveConf.getLoginUrl();
                logger.debug("Setting internalURL: " + internalURL);

                //Set the the following var to a value distinct than "-1"
                sessionVarsSet = 0;

            }

        } catch (Exception e) {
            logger.error("Error reading config parameters. Check config file");
        }
    }

}
