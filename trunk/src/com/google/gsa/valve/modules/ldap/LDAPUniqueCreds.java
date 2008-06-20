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

import java.util.Vector;

/**
 * Authenticates the user against an LDAP server. It gets the username and 
 * password credentials passed to the authenticate() method and uses it 
 * to check the authentication. The LDAP connection details are as well passed 
 * to the classes.
 * <p>
 * This authentication module uses Java standard LDAP classes that makes 
 * the integration independent of the directory server.
 * <p>
 * If the LDAP authentication result is OK, it creates an 
 * authentication cookie. Anyway, the HTTP response code is returned in this 
 * method to inform the caller on the status.
 * 
 */
public class LDAPUniqueCreds implements AuthenticationProcessImpl {

    //logger
    private Logger logger = null;

    //Valve Configuration
    private ValveConfiguration valveConf = null;

    //LDAP vars parameters
    private String ldapBaseuser = null;
    private String ldapHost = null;
    private String ldapDomain = null;
    private String rdnAttr = null;

    //Cookie Max Age - default value
    private int authMaxAge = -1;

    /**
     * Class constructor
     * 
     */
    public LDAPUniqueCreds() {
        logger = Logger.getLogger(LDAPUniqueCreds.class);

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
     * This is the main method that does the LDAP authentication using user's 
     * credential in the format of username and password. It creates a 
     * connection with the user credentials and reads his/her own information. 
     * It does not read any other LDAP attribute out of the user entry.
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

        logger.debug("LDAP Unique Credentials Start");

        Cookie[] cookies = null;

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        // Read cookies
        cookies = request.getCookies();

        //First read the u/p the credentails store, in this case using the same as the root login
        logger.debug("LDAPUniqueCreds: trying to get creds from repository ID: " + 
                     id);
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
                logger.error("LDAPUniqueCreds: No credentials available for " + 
                             id);
            }
        }


        try {
            authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());
        } catch (NumberFormatException nfe) {
            logger.error("Configuration error: chack the configuration file as the number set for authMaxAge is not OK:");
        }

        //If the required cookie was not found need to authenticate.
        logger.debug("Authenticating");
        try {

            //read values from config file (if any)
            readLDAPParameters(id);

            //Check if the LDAP credentials are OK                      
            logger.debug("Base user is: " + ldapBaseuser);
            Ldap ldapconn = 
                new Ldap(ldapHost, cred.getUsername(), cred.getPassword(), 
                         ldapBaseuser, ldapDomain, rdnAttr);

            try {
                logger.debug("Connection to LDAP");
                DirContext ctx = ldapconn.openConnection();
                if (ctx == null) {
                    //Just send a comment  
                    logger.debug("The user(" + cred.getUsername() + 
                                 ")/password doesn't match");
                    ldapconn.closeConnection(ctx);
                    return (HttpServletResponse.SC_UNAUTHORIZED);
                }

                logger.debug("User properly authenticated against the LDAP");

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
            logger.error("Sample authentication failure: " + e.getMessage(), 
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
        Cookie extAuthCookie = new Cookie("gsa_ad_auth", "true");
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
     * Reads LDAP parameters from the config file
     * 
     * @param id the repository id that holds the LDAP parameters
     */
    public void readLDAPParameters(String id) {
        if (valveConf != null) {

            //Reading LDAP vars from configfile                
            ldapBaseuser = 
                    valveConf.getRepository(id).getParameterValue("ldapBaseuser");
            if ((ldapBaseuser != null) && (ldapBaseuser == "")) {
                ldapBaseuser = null;
            }
            ldapHost = 
                    valveConf.getRepository(id).getParameterValue("ldapHost");
            if ((ldapHost != null) && (ldapHost == "")) {
                ldapHost = null;
            }
            ldapDomain = 
                    valveConf.getRepository(id).getParameterValue("ldapDomain");
            if ((ldapDomain != null) && (ldapDomain == "")) {
                ldapDomain = null;
            }
            rdnAttr = valveConf.getRepository(id).getParameterValue("rdnAttr");
            if ((rdnAttr != null) && (rdnAttr == "")) {
                rdnAttr = null;
            }

        }
    }

}

