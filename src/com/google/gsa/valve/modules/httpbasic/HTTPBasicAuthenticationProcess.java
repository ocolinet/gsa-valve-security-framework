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


package com.google.gsa.valve.modules.httpbasic;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.RequestType;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.io.IOException;

import java.net.URLEncoder;

import java.util.Hashtable;

import java.util.Vector;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.log4j.Logger;


/**
 * This class manages the authentication process for HTTP Basic protected 
 * content sources. It creates an HTTP connection to any HTTP Basic URL 
 * that is passed to the authenticate method. If the authentication 
 * process is succesful, a 200 (OK) error message is returned, and if there 
 * is any other error is sent back as well.
 * <p>
 * Once the process has finished successfully, a cookie is created with the 
 * HTTP Basic credentials to be reused as many times as needed during the 
 * authorization.
 * 
 * @see HTTPBasicAuthorizationProcess
 * 
 */
public class HTTPBasicAuthenticationProcess implements AuthenticationProcessImpl {

    //Multi-threaded webProcessor
    private static WebProcessor webProcessor = null;

    //Valve configuration
    private ValveConfiguration valveConf = null;

    private static final String encoder = "UTF-8";

    private static final String BASIC_COOKIE = "gsa_basic_auth";

    //Logger
    private Logger logger = null;


    /**
     * Class constructor
     * 
     */
    public HTTPBasicAuthenticationProcess() {
        //Instantiate logger
        logger = Logger.getLogger(HTTPBasicAuthenticationProcess.class);

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
     * invoked by the classes that would like to open a new authentication 
     * process against an HTTP Basic protected source.
     * <p>
     * The username and password for the source are assumed to be the ones 
     * captured during the authentication. These are stored in creds and in 
     * this case the root parameters. creds is an array of credentials for 
     * all external sources. The first element is 'root' which contains the 
     * credentials captured from the login page. This method reviews if there 
     * is a credential id identical to the name associated to this module 
     * in the config file. If so, these credentials are used to authenticate 
     * against this HTTP Basic source, and if not 'root' one will be used 
     * instead.
     * <p>
     * If the HTTP Basic authentication result is OK, it creates an 
     * authentication cookie containing the HTTP Basic credentials 
     * to be reused during authorization. The content returned back from the 
     * remote secure backend system is sent as well. Anyway, the HTTP 
     * response code is returned in this method to inform the caller on the 
     * status.
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

        Cookie[] cookies = null;

        //Credentials							
        UsernamePasswordCredentials credentials = null;

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        // Read cookies
        cookies = request.getCookies();

        // Debug
        logger.debug("HTTP Basic authentication start");


        //First read the u/p the credentails store, in this case using the same as the root login
        logger.debug("HttpBasic: trying to get creds from repository ID: " + 
                     id);
        Credential httpBasicCred = null;
        try {
            httpBasicCred = creds.getCredential(id);
        } catch (NullPointerException npe) {
            logger.error("NPE while reading credentials of ID: " + id);
        }
        if (httpBasicCred != null) {
            credentials = 
                    new UsernamePasswordCredentials(httpBasicCred.getUsername(), 
                                                    httpBasicCred.getPassword());
        } else {
            logger.debug("HttpBasic: trying to get creds from repository \"root\"");
            httpBasicCred = creds.getCredential("root");
            if (httpBasicCred != null) {
                logger.info("Trying with root credentails");
                credentials = 
                        new UsernamePasswordCredentials(httpBasicCred.getUsername(), 
                                                        httpBasicCred.getPassword());
            }
        }

        logger.debug("Authenticating");
        Header[] headers = null;
        HttpMethodBase method = null;

        //Get Max connections
        int maxConnectionsPerHost = 30;
        int maxTotalConnections = 100;

        //Cookie Max Age
        int authMaxAge = -1;

        try {
            maxConnectionsPerHost = 
                    new Integer(valveConf.getMaxConnectionsPerHost()).intValue();
            maxTotalConnections = 
                    (new Integer(valveConf.getMaxTotalConnections())).intValue();
            authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());
        } catch (NumberFormatException nfe) {
            logger.error("Configuration error: chack the configuration file as the numbers set for any of the following parameters are not OK:");
            logger.error("  * maxConnectionsPerHost    * maxTotalConnections    * authMaxAge");
        }


        // Protection
        if (webProcessor == null) {
            // Instantiate Web processor
            if ((maxConnectionsPerHost != -1) && (maxTotalConnections != -1)) {
                webProcessor = 
                        new WebProcessor(maxConnectionsPerHost, maxTotalConnections);
            } else {
                webProcessor = new WebProcessor();
            }
        }

        //
        // Launch the authentication process
        //

        // A fixed URL in the repository that all users have access to which can be used to authN a user
        // and capture the HTTP Authorization Header
        String authURL = 
            valveConf.getRepository(id).getParameterValue("HTTPAuthPage");

        try {

            // Set HTTP headers
            headers = new Header[1];

            // Set User-Agent
            headers[0] = 
                    new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8) Gecko/20051111 Firefox/1.5");

            // Request page, testing if credentials are valid
            if (credentials != null) {
                logger.debug("Username: " + credentials.getUserName());
                logger.debug("URL: " + authURL);
            }

            //HTTP request
            method = 
                    webProcessor.sendRequest(credentials, RequestType.GET_REQUEST, 
                                             headers, null, authURL);

            //Read the auth header and store in the cookie, the authZ class will use this later
            headers = method.getRequestHeaders();

            Header authHeader = null;
            authHeader = method.getRequestHeader("Authorization");

            // Cache status code
            if (method != null)
                statusCode = method.getStatusCode();

            if (statusCode == HttpServletResponse.SC_OK) {
                //Authentication worked, so create the auth cookie to indicate it has worked
                Cookie extAuthCookie = null;
                extAuthCookie = new Cookie(BASIC_COOKIE, "");

                if (authHeader != null) {

                    String basicCookie = null;

                    try {
                        basicCookie = 
                                URLEncoder.encode(getBasicAuthNChain(authHeader.getValue()), 
                                                  encoder);
                        if (basicCookie == null) {
                            basicCookie = "";
                        }
                    } catch (Exception ex) {
                        logger.error("Error when setting Basic cookie value: " + 
                                     ex.getMessage(), ex);
                        basicCookie = "";
                    }

                    extAuthCookie.setValue(basicCookie);

                }
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
                if (logger.isDebugEnabled())
                    logger.debug("Adding " + BASIC_COOKIE + " cookie: " + 
                                 extAuthCookie.getName() + ":" + 
                                 extAuthCookie.getValue() + ":" + 
                                 extAuthCookie.getPath() + ":" + 
                                 extAuthCookie.getDomain() + ":" + 
                                 extAuthCookie.getSecure());

                //sendCookies support                        
                boolean isSessionEnabled = 
                    new Boolean(valveConf.getSessionConfig().isSessionEnabled()).booleanValue();
                boolean sendCookies = false;
                if (isSessionEnabled) {
                    sendCookies = 
                            new Boolean(valveConf.getSessionConfig().getSendCookies()).booleanValue();
                }
                if ((!isSessionEnabled) || 
                    ((isSessionEnabled) && (sendCookies))) {
                    logger.debug("Adding cookie to response");
                    response.addCookie(extAuthCookie);
                }

                //Add cookies to the Cookie array to support sessions
                authCookies.add(extAuthCookie);
                logger.debug("Cookie added to the array");

            }

            // Clear webProcessor cookies
            webProcessor.clearCookies();

        } catch (Exception e) {

            // Log error
            logger.error("HTTP Basic authentication failure: " + 
                         e.getMessage(), e);

            // Garbagge collect
            method = null;

            // Update status code
            statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        }

        // End of the authentication process
        logger.debug("HTTP Basic Authentication completed (" + statusCode + 
                     ")");


        // Return status code
        return statusCode;

    }

    /**
     * Gets the Basic chain from the response Authorization header
     * 
     * @param basic header
     *  
     * @return the Basic authentication chain
     */
    public String getBasicAuthNChain(String basic) {
        String authNChain = "";
        String basicMsg = "Basic ";

        logger.debug("Basic is: " + basic);
        if ((!basic.equals(null)) && (!basic.equals(""))) {
            //treat basic chain and just get the chain
            int index = basicMsg.length();
            authNChain = basic.substring(index);
            logger.debug("New Basic chain: " + authNChain + "; with index: " + 
                         index);
        }

        return authNChain;
    }

}
