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
import java.util.Map;
import java.util.Vector;

/**
 * The Security Framework is able to manage more than one credential per user. 
 * This class is able to manage multiple credentials in a LDAP server. This has 
 * been implemented using some attributes extended in the LDAP that hold the 
 * credential information for accessing multiple sources. It checks the main 
 * authentication credentials provided by the user against the LDAP, but once 
 * the user is authenticated, it populates the multiple credentials to be 
 * available during the whole security process.
 * <p>
 * It's able to read multiple username and password attributes from the LDAP 
 * and populate them in the credential container. It enables the other 
 * AuthN/AuthZ modules to use them when securely accessing the backend 
 * systems.
 * <p>
 * This authentication module uses Java standard LDAP classes that makes 
 * the integration independent of the directory server.
 * 
 */
public class LDAPSSO implements AuthenticationProcessImpl {

    //logger
    private Logger logger = null;

    //Valve configuration
    private ValveConfiguration valveConf = null;

    //Hastable and Vector that contains authentication LDAP attributes
    private Vector<String> repositories = new Vector<String>();
    private Map<String, LDAPAttrRepository> ldapAttributes = 
        new HashMap<String, LDAPAttrRepository>();

    //LDAP vars parameters
    private String ldapBaseuser = null;
    private String ldapHost = null;
    private String ldapDomain = null;
    private String rdnAttr = null;

    private static final String SSO_COOKIE_NAME = "gsa_ldap_auth";

    //Cookie Max Age
    private int authMaxAge = -1;

    /**
     * Class constructor
     * 
     */
    public LDAPSSO() {
        logger = Logger.getLogger(LDAPSSO.class);

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
     * This is the main method that does the authentication and should be 
     * invoked by the classes that would like to populate new user authentication 
     * credentials from the LDAP server.
     * <p>
     * It also authenticates the user against the LDAP server, so that only 
     * priviledged users are able to read the LDAP attributes. These multiple 
     * credentials are stored in the directory server and populate them in the 
     * user's credential container. It enables the other AuthN/AuthZ modules to 
     * use them when securely accessing the backend systems.
     * <p>
     * If the LDAP authentication result is OK, it creates an 
     * authentication cookie. Anyway, the HTTP response code is returned in this 
     * method to inform the caller on the status.
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

        logger.debug("Start LDAPSSO AuthN process");

        //protection
        repositories.clear();
        ldapAttributes.clear();

        //Insert LDAP attributes from the config file
        getLDAPAttributes(id);

        //First read the u/p the credentails store, in this case using the same as the root login
        logger.debug("LDAPSSO: trying to get creds from repository ID: " + id);
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
                logger.error("LDAPSSO: No credentials available for " + id);
            }
        }

        Cookie[] cookies = null;

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        // Read cookies
        cookies = request.getCookies();

        try {
            authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());
        } catch (NumberFormatException nfe) {
            logger.error("Configuration error: chack the configuration file as the number set for authMaxAge is not OK:");
        }

        //If the required cookie was not found need to authenticate.
        logger.info("Authenticating root user with LDAP");
        try {

            //Check if the LDAP credentials are OK                    	
            Ldap ldapconn = 
                new Ldap(ldapHost, cred.getUsername(), cred.getPassword(), 
                         ldapBaseuser, ldapDomain, rdnAttr);
            try {
                logger.debug("Connecting to LDAP");
                DirContext ctx = ldapconn.openConnection();
                if (ctx == null) {
                    //Just send a comment  
                    logger.debug("The user(" + cred.getUsername() + 
                                 ")/password doesn't match");
                    ldapconn.closeConnection(ctx);
                    return (HttpServletResponse.SC_UNAUTHORIZED);
                }


                //Fetching credentials
                logger.debug("Fetching credentials from the LDAP");

                fetchingCredentials(ldapconn, ctx, cred.getUsername(), creds);

                //Close the connection
                ldapconn.closeConnection(ctx);

            } catch (Exception ex) {
                logger.error("LDAP connection problem during user access: " + 
                             ex.getMessage(), ex);
                return (HttpServletResponse.SC_UNAUTHORIZED);
            } finally {
            }


            Cookie extAuthCookie = null;

            extAuthCookie = settingCookie();

            //add sendCookies support
            logger.debug("Setting session");
            boolean isSessionEnabled = 
                new Boolean(valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
            boolean sendCookies = false;
            if (isSessionEnabled) {
                sendCookies = 
                        new Boolean(valveConf.getSessionConfig().getSendCookies()).booleanValue();
            }
            if ((!isSessionEnabled) || ((isSessionEnabled) && (sendCookies))) {
                response.addCookie(extAuthCookie);
            }

            //add cookie to the array
            authCookies.add(extAuthCookie);

            //This would be set to OK or 401 in a real AuthN module
            statusCode = HttpServletResponse.SC_OK;

        } catch (Exception e) {

            // Log error
            logger.error("LDAP SSO authentication failure: " + e.getMessage(), 
                         e);


            // Update status code
            statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        }


        // Debug
        logger.debug("Sample Authentication completed (" + statusCode + ")");

        // Return status code
        return statusCode;

    }

    /**
     * Sets the LDAP authentication cookie
     * 
     * @return the LDAP authentication cookie
     */
    public Cookie settingCookie() {
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
        extAuthCookie.setMaxAge(authMaxAge);

        // Log info
        logger.debug("Adding cookie: " + extAuthCookie.getName() + ":" + 
                     extAuthCookie.getValue() + ":" + extAuthCookie.getPath() + 
                     ":" + extAuthCookie.getDomain() + ":" + 
                     extAuthCookie.getSecure());

        return extAuthCookie;
    }

    /**
     * Gets the LDAP attributes coming from the config file
     * 
     * @param id the repository id
     */
    public void getLDAPAttributes(String id) {

        logger.debug("Getting LDAP Attributes");

        ValveRepositoryConfiguration repositoryConfig = 
            valveConf.getRepository(id);

        if (repositoryConfig != null) {

            //Reading LDAP vars from configfile     

            logger.debug("Reading LDAP Attributes from config file");

            ldapBaseuser = repositoryConfig.getParameterValue("ldapBaseuser");
            if ((ldapBaseuser != null) && (ldapBaseuser == "")) {
                ldapBaseuser = null;
            }
            ldapHost = repositoryConfig.getParameterValue("ldapHost");
            if ((ldapHost != null) && (ldapHost == "")) {
                ldapHost = null;
            }
            ldapDomain = repositoryConfig.getParameterValue("ldapDomain");
            if ((ldapDomain != null) && (ldapDomain == "")) {
                ldapDomain = null;
            }
            rdnAttr = repositoryConfig.getParameterValue("rdnAttr");
            if ((rdnAttr != null) && (rdnAttr == "")) {
                rdnAttr = null;
            }

            //Getting attributes username and password for all the credentials
            logger.debug("Getting LDAP username and password attributes per each repository");
            boolean attributeExist = true;
            int index = 1;
            while (attributeExist) {
                String idAttr = "id" + index;
                logger.debug("ID is : " + idAttr);
                if (repositoryConfig.getParameterValue(idAttr) != null) {
                    String userNameAttr = "username" + index;
                    String passwordAttr = "password" + index;
                    if ((repositoryConfig.getParameterValue(userNameAttr) != 
                         null) && 
                        (repositoryConfig.getParameterValue(passwordAttr) != 
                         null)) {
                        logger.debug("Adding LDAP attributes for: " + 
                                     repositoryConfig.getParameterValue(idAttr));
                        LDAPAttrRepository attrRepository = 
                            new LDAPAttrRepository(repositoryConfig.getParameterValue(userNameAttr), 
                                                   repositoryConfig.getParameterValue(passwordAttr));
                        ldapAttributes.put(repositoryConfig.getParameterValue(idAttr), 
                                           attrRepository);
                        repositories.add(repositoryConfig.getParameterValue(idAttr));
                    } else {
                        logger.error("LDAP attribute username or password for repository number " + 
                                     index + " [" + 
                                     repositoryConfig.getParameterValue(idAttr) + 
                                     "] does NOT exist in the config file. Review configuration");
                    }
                } else {
                    attributeExist = false;
                }
                index++;
            }
        }

    }

    /**
     * 
     * For every credentials read at the configuration file it gets the 
     * LDAP attributes from the LDAP.
     * 
     * @param ldapconn LDAP connection
     * @param ctx LDAP context
     * @param username user id
     * @param creds user credentials
     */
    public void fetchingCredentials(Ldap ldapconn, DirContext ctx, 
                                    String username, Credentials creds) {

        for (int i = 0; i < repositories.size(); i++) {
            String id = repositories.elementAt(i);
            logger.debug("ID [" + id + "] found at position #" + i);

            LDAPAttrRepository attrRepository;

            //fetch credentials
            try {
                attrRepository = ldapAttributes.get(id);

                //Get User's DN
                String userDName = ldapconn.getDN(username, ctx);

                logger.info("fetching credentials for (" + id + ")");
                String usernameAttr = 
                    ldapconn.getAttributeByDN(attrRepository.getUsernameAttr(), 
                                              userDName, ctx);
                String passwordAttr = null;
                if (!usernameAttr.equals(null)) {
                    logger.debug("UserName id[" + id + "]: " + usernameAttr);
                    passwordAttr = 
                            ldapconn.getAttributeByDN(attrRepository.getPasswordAttr(), 
                                                      userDName, ctx);
                    //add the credentials into the "creds" object
                    logger.debug("LDAP credentials were acquired OK. Adding them into the credential container");
                    Credential credAttr = new Credential(id);
                    credAttr.setUsername(usernameAttr);
                    credAttr.setPassword(passwordAttr);
                    creds.add(credAttr);
                } else {
                    logger.debug("Credentials for " + id + 
                                 " were not found for the user " + username);
                }
            } catch (NullPointerException e) {
                logger.warn("NullPointerException when fetching attrs in the LDAP. Probably due to the user does not have those attrs");
            } catch (Exception e) {
                logger.error("Exception fetching LDAP attributes: " + 
                             e.getMessage(), e);
            }

        }

    }

    /**
     * Class that implements a pair of username and password LDAP attribute 
     * names associated to a one or more repositories (i.e. a user can be 
     * authenticated using the value of those attributes in the LDAP against 
     * a repository)
     * 
     */
    public class LDAPAttrRepository {

        //Username and password pair
        String usernameAttr = null;
        String passwordAttr = null;

        /**
         * Class constructor
         * 
         * @param usernameAttr LDAP username attribute
         * @param passwordAttr
         */
        public LDAPAttrRepository(String usernameAttr, String passwordAttr) {
            setUsernameAttr(usernameAttr);
            setPasswordAttr(passwordAttr);
        }

        /**
         * Gets the LDAP username attribute
         * 
         * @return LDAP username attribute
         */
        public String getUsernameAttr() {
            return usernameAttr;
        }

        /**
         * Sets the LDAP username attribute
         * 
         * @param usernameAttr LDAP username attribute
         */
        public void setUsernameAttr(String usernameAttr) {
            this.usernameAttr = usernameAttr;
        }

        /**
         * Gets the LDAP password attribute
         * 
         * @return LDAP password attribute
         */
        public String getPasswordAttr() {
            return passwordAttr;
        }

        /**
         * Sets the LDAP password attribute
         * 
         * @param passwordAttr LDAP password attribute
         */
        public void setPasswordAttr(String passwordAttr) {
            this.passwordAttr = passwordAttr;
        }

    }

}
