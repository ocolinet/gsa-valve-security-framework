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
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveRepositoryConfiguration;

import java.util.HashMap;
import java.util.Map;
import java.util.Vector;


/**
 * This is the default class that processes the authentication. It reads the 
 * repositories defined in the config file and invokes those repository's 
 * authentication classes that require it to be triggered. Those that includes 
 * the tag "checkauthN" set to false are not processed.
 * <p>
 * The name of the authentication classes that need to be processed are included 
 * in a vector that is reused multiple times. Whenever a new authentication 
 * process needs to be relaunched, all these classes are processed and the 
 * individual authentication process is treated.
 * <p>
 * There is a special repository named "root" that is treatly in a special way. 
 * If any repository is named as "root", it means this is the main authentication 
 * mechanim and that's why it's trated first. If it fails, the authentication 
 * process stops here and the return result is an error. If not, the whole 
 * processing continues.
 * 
 * @see RootAuthorizationProcess
 * 
 */
public class RootAuthenticationProcess implements AuthenticationProcessImpl {

    //logger
    private Logger logger = null;

    //Valve configuration
    private ValveConfiguration valveConf = null;

    //Support for Krb creds
    boolean isKerberos = false;
    boolean isNegotiate = false;
    String loginUrl = null;

    private Vector<Cookie> rootAuthCookies = new Vector<Cookie>();
    private Vector<Cookie> repositoryAuthCookies = new Vector<Cookie>();

    //Map that represents the authentication modules
    private Map<String, AuthenticationProcessImpl> authenticationImplementations = 
        new HashMap<String, AuthenticationProcessImpl>();

    //Map that represents the order of the authentication modules
    private Map<Integer, String> authenticationImplementationsOrder = 
        new HashMap<Integer, String>();


    /**
     * Class constructor
     * 
     */
    public RootAuthenticationProcess() {

        // Invoke parent constructor
        super();

        // Instantiate logger
        logger = Logger.getLogger(RootAuthenticationProcess.class);

        logger.debug("Initializing " + 
                     RootAuthenticationProcess.class.getName());


    }

    /**
     * Sets the request is a Kerberos negotiation process
     *  
     * @param newIsNegotiate boolean - if it's a negotiation process
     */
    public void setIsNegotiate(boolean newIsNegotiate) {
        isNegotiate = newIsNegotiate;
    }

    /**
     * Gets if the request is a Kerberos negotiation process
     * 
     * @return boolean - if it's a negotiation process
     */
    public boolean getIsNegotiate() {
        return isNegotiate;
    }


    /**
     * This is the main method that drives the whole authentication 
     * process. It launches each individual authentication method declared in 
     * the configuration files. Those that includes the tag "checkauthN" set to 
     * false are not processed.
     * <p>
     * The name of the authentication classes that need to be processed are included 
     * in a vector that is reused multiple times. Whenever a new authentication 
     * process needs to be relaunched, all these classes are processed and the 
     * individual authentication process is treated.
     * <p>
     * It returns the HTTP error code associated to the process result. If it was 
     * OK, this methods returns a 200 and 401 (unauthorized) otherwise.
     * <p>
     * There is a special repository named "root" that is treatly in a special way. 
     * If any repository is named as "root", it means this is the main authentication 
     * mechanim and that's why it's trated first. If it fails, the authentication 
     * process stops here and the return result is an error. If not, the whole 
     * processing continues.
     * <p>
     * If there is a "root" repository and the authentication process for this 
     * repository is OK, although any other repository would fail, the overall 
     * authentication method returns an OK. If there is not such a "root" 
     * repository, any authentication error will cause the authentication process 
     * to fail.
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

        // Initialize status code
        int rootStatusCode = HttpServletResponse.SC_UNAUTHORIZED;
        int repositoryAuthStatusCode = HttpServletResponse.SC_UNAUTHORIZED;
        //Check if authn is Ok in multiple repository
        boolean repositoryOKAuthN = false;

        //clear authCookies
        authCookies.clear();

        boolean rootAuthNDefined = false;
        logger.debug("AuthN authenticate [" + url + "]");

        //Read vars
        if (valveConf != null) {
            isKerberos = 
                    new Boolean(valveConf.getKrbConfig().isKerberos()).booleanValue();
            if (isKerberos) {
                isNegotiate = 
                        new Boolean(valveConf.getKrbConfig().isNegotiate()).booleanValue();
            }
            loginUrl = valveConf.getLoginUrl();
        } else {
            logger.error("Configuration error: Config file is not present");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                               "Configuration error - Kerberos is not set properly");
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        //ValveHost: it's the same URL as the login page, without 
        String valveHost = 
            loginUrl.substring(0, loginUrl.lastIndexOf("/") + 1);

        RE internal = new RE(valveHost, RE.MATCH_CASEINDEPENDENT);

        // The host and URL of the GSA for the search
        //TODO add support for multiple GSA's
        RE query = new RE("/search", RE.MATCH_CASEINDEPENDENT);


        //Request has come from the same host as the valve, so must be the login authenticate
        if (internal.match(url)) {

            //Authentication vars
            String repositoryID = null;
            AuthenticationProcessImpl authProcess = null;
            ValveRepositoryConfiguration repositoryConfig = null;

            int order = 1;
            int size = authenticationImplementationsOrder.size();
            if (authenticationImplementationsOrder == null) {
                order = 0;
                logger.error("No Authentication module has been defined. Please check and add those needed at config file");
            }

            while ((1 <= order) && (order <= size)) {

                //Get the repository ID
                logger.debug("###Processing repository # " + order + " ###");
                Integer orderInt = new Integer(order);
                if (authenticationImplementationsOrder.containsKey(orderInt)) {
                    repositoryID = 
                            authenticationImplementationsOrder.get(orderInt);
                } else {
                    logger.error("Error during processing authentication methods. Order is not valid");
                    break;
                }

                //Get the Repository config and authentication class                                                    
                authProcess = authenticationImplementations.get(repositoryID);
                repositoryConfig = valveConf.getRepository(repositoryID);

                logger.debug("Authenticating ID: " + repositoryConfig.getId());
                if (repositoryConfig.getId().equals("root")) {
                    //Root should be used for main authentication against an identity repository (LDAP, DB, ..)
                    //and should not be used as a content repository that contains documents
                    try {
                        //add support to cookie array
                        rootAuthCookies.clear();
                        rootStatusCode = 
                                authProcess.authenticate(request, response, 
                                                         rootAuthCookies, url, 
                                                         creds, "root");
                        logger.info("Repository authentication - " + 
                                    repositoryConfig.getId() + 
                                    " completed. Response was " + 
                                    rootStatusCode);
                        if (rootStatusCode == 
                            HttpServletResponse.SC_UNAUTHORIZED) {
                            logger.error("Root AuthN failed");
                        } else {
                            //Support to cookie array
                            if (rootStatusCode == HttpServletResponse.SC_OK) {
                                logger.debug("Root AuthN is SC_OK (200)");
                                if (!rootAuthCookies.isEmpty()) {
                                    logger.debug("Root AuthN returns cookies");
                                    for (int j = 0; j < rootAuthCookies.size(); 
                                         j++) {
                                        logger.debug("Root Cookie found: " + 
                                                     rootAuthCookies.elementAt(j).getName() + 
                                                     ":" + 
                                                     rootAuthCookies.elementAt(j).getValue());
                                        authCookies.add(rootAuthCookies.elementAt(j));
                                    }
                                } else {
                                    logger.debug("Root AuthN does NOT return cookies");
                                }
                            }
                        }

                        //If no repository is defined called root then rootStatusCode must be set to OK
                        // This flag is used to indicate that a root repository has been defined.
                        rootAuthNDefined = true;
                        //
                    } catch (Exception e) {
                        logger.debug("Exception with authentication for ID: " + 
                                     repositoryConfig.getId() + " - " + 
                                     e.getMessage());
                        rootAuthNDefined = true;
                    }
                } else {
                    try {

                        //add support to cookie array
                        repositoryAuthCookies.clear();

                        logger.debug("Let's do the authentication");

                        repositoryAuthStatusCode = 
                                authProcess.authenticate(request, response, 
                                                         repositoryAuthCookies, 
                                                         url, creds, 
                                                         repositoryConfig.getId());

                        //add support to cookie array
                        if (repositoryAuthStatusCode == 
                            HttpServletResponse.SC_OK) {
                            logger.debug("Repository AuthN [" + 
                                         repositoryConfig.getId() + 
                                         "] is SC_OK (200)");
                            //check if multiple repository is set to valid
                            if (repositoryOKAuthN == false) {
                                repositoryOKAuthN = true;
                            }
                            //check if cookie array is not empty and consume it
                            if (!repositoryAuthCookies.isEmpty()) {
                                logger.debug("Repository AuthN [" + 
                                             repositoryConfig.getId() + 
                                             "] returns " + 
                                             repositoryAuthCookies.size() + 
                                             " cookies");
                                for (int j = 0; 
                                     j < repositoryAuthCookies.size(); j++) {
                                    logger.debug("Repository Cookie found: " + 
                                                 repositoryAuthCookies.elementAt(j).getName() + 
                                                 ":" + 
                                                 repositoryAuthCookies.elementAt(j).getValue());
                                    authCookies.add(repositoryAuthCookies.elementAt(j));
                                }
                            } else {
                                logger.debug("Repository AuthN [" + 
                                             repositoryConfig.getId() + 
                                             "] does NOT return cookies");
                            }
                        }

                        //end Krb support
                        logger.info("Repository authentication - " + 
                                    repositoryConfig.getId() + 
                                    " completed. Response was " + 
                                    repositoryAuthStatusCode);
                    } catch (Exception e) {
                        logger.debug("Exception with authentication for ID: " + 
                                     repositoryConfig.getId() + " - " + 
                                     e.getMessage());
                    }
                }

                //increase order
                order++;
            }
        } else if (query.match(url)) {

            logger.debug("Query pattern [" + url + "]");

            // Don't do anything in here
            rootStatusCode = HttpServletResponse.SC_OK;

        } else {

            logger.error("No pattern defined for URL: " + url + 
                         ". It should not have been possible to get here!");

            // Protection
            rootStatusCode = HttpServletResponse.SC_UNAUTHORIZED;

        }

        //add support to multiple repositories
        if ((!rootAuthNDefined) && (repositoryOKAuthN)) {
            //If no root repository has been defined then rootStatusCode has to be set valid, to OK
            rootStatusCode = HttpServletResponse.SC_OK;
        }

        // Return status code
        logger.debug("RootAuthN Complete - Status Code: " + rootStatusCode);

        return rootStatusCode;


    }

    /**
     * Sets the Valve Configuration instance to read the parameters 
     * from there
     * 
     * @param valveConf the Valve configuration instance
     */
    public void setValveConfiguration(ValveConfiguration valveConf) {

        this.valveConf = valveConf;

        //Protection. Make sure the Map is empty before proceeding
        authenticationImplementations.clear();

        //Authentication process instance
        AuthenticationProcessImpl authenticationProcess = null;

        String repositoryIds[] = valveConf.getRepositoryIds();

        ValveRepositoryConfiguration repository = null;

        int order = 1;

        for (int i = 0; i < repositoryIds.length; i++) {
            try {

                repository = valveConf.getRepository(repositoryIds[i]);

                //Check if repository has to be included in the authentication process. By default set it to true
                boolean checkAuthN = true;
                try {
                    if ((repository.getCheckAuthN() != null) && 
                        (!repository.getCheckAuthN().equals(""))) {
                        checkAuthN = 
                                new Boolean(repository.getCheckAuthN()).booleanValue();
                    }
                } catch (Exception e) {
                    logger.error("Error when reading checkAuthN param: " + 
                                 e.getMessage(), e);
                    //protection
                    checkAuthN = true;
                }

                if (checkAuthN) {
                    logger.info("Initialising authentication process for " + 
                                repository.getId() + " [#" + order + "]");
                    authenticationProcess = 
                            (AuthenticationProcessImpl)Class.forName(repository.getAuthN()).newInstance();
                    authenticationProcess.setValveConfiguration(valveConf);
                    //add this authentication process to the Map
                    synchronized (authenticationImplementations) {
                        synchronized (authenticationImplementations) {
                            authenticationImplementations.put(repository.getId(), 
                                                              authenticationProcess);
                            authenticationImplementationsOrder.put(new Integer(order), 
                                                                   repository.getId());
                            order++;
                        }
                    }

                } else {
                    logger.debug("Authentication process for repository [" + 
                                 repository.getId() + 
                                 "] is not going to be launched");
                }

            } catch (LinkageError le) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthenticationProcess-LinkageError]: " + 
                             le.getMessage(), le);
            } catch (InstantiationException ie) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthenticationProcess-InstantiationException]: " + 
                             ie.getMessage(), ie);
            } catch (IllegalAccessException iae) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthenticationProcess-IllegalAccessException]: " + 
                             iae.getMessage(), iae);
            } catch (ClassNotFoundException cnfe) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthenticationProcess-ClassNotFoundException]: " + 
                             cnfe.getMessage(), cnfe);
            } catch (Exception e) {
                logger.error(repository.getId() + 
                             " - Can't instantiate class [AuthenticationProcess-Exception]: " + 
                             e.getMessage(), e);
            }
        }
        logger.debug(RootAuthenticationProcess.class.getName() + 
                     " initialised");
    }

}
