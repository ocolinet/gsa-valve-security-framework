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


import com.google.gsa.valve.modules.utils.HTTPVisitor;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.log4j.Logger;

import org.htmlparser.Parser;
import org.htmlparser.visitors.NodeVisitor;

import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.RequestType;
import com.google.gsa.WebProcessor;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.modules.utils.AuthorizationUtils;
import com.google.gsa.valve.modules.utils.HTTPAuthZProcessor;

import java.net.URLDecoder;


/**
 * This class manages the authorization process for HTTP Basic protected 
 * content sources. It creates an HTTP connection to any HTTP Basic URL 
 * that is passed to the authenticate method. If the authorization 
 * process is succesful, the response is sent back to the caller, including 
 * the content (if it's not a HEAD request). In that case a 200 (OK) error 
 * message is returned, and if there is any other error is sent back as well.
 * <p>
 * The Basic credential are read from the cookie created during the 
 * authentication process. If that cookie does not exist, the process returns 
 * a 401 (Unauthorized) error code.
 * 
 * @see HTTPBasicAuthenticationProcess
 * 
 */
public class HTTPBasicAuthorizationProcess implements AuthorizationProcessImpl {

    //logger
    private Logger logger = null;

    //Multithreaded webProcessor
    private static WebProcessor webProcessor = null;

    //Valve Configuration
    private ValveConfiguration valveConf = null;

    //Method
    private HttpMethodBase method = null;

    //Header
    private Header[] headers = null;
    private Header authHeader = null;

    //Max Connections
    private int maxConnectionsPerHost = 30;
    private int maxTotalConnections = 100;

    //Encoding
    private static final String encoder = "UTF-8";

    //Basic AuthN cookie
    private static final String BASIC_COOKIE = "gsa_basic_auth";


    /**
     * Class constructor
     */
    public HTTPBasicAuthorizationProcess() {
        //Instantiate logger
        logger = Logger.getLogger(HTTPBasicAuthorizationProcess.class);
    }

    /**
     * Sets user credentials
     * <p>
     * In this case it does not set anything as the credentials are read 
     * from the authentication cookie.
     * 
     * @param creds
     */
    public void setCredentials(Credentials creds) {
        //do nothing
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
     * 
     * This is the main method that does the authorization and should be 
     * invoked by the classes that would like to check if the user is 
     * priviledged to access to the document (url) against the HTTP Basic 
     * protected source that serves it.
     * <p>
     * The Basic credential is read from the cookie created during the 
     * authentication process. If that cookie does not exist, the process returns 
     * a 401 (Unauthorized) error code.
     * <p>
     * If it is a HEAD request, it means it's not necessary to get the content, 
     * and that's why this process only cares about the HTTP result code. That 
     * result code is returned back to the caller, and if the request is not a 
     * HEAD (i.e. usually GET), the content is sent as well if the overall 
     * result is OK.
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
                                                       IOException {

        logger.debug("HTTP Basic Authorization");

        String loginUrl = null;

        loginUrl = valveConf.getLoginUrl();

        //Get Max connections
        maxConnectionsPerHost = 
                new Integer(valveConf.getMaxConnectionsPerHost()).intValue();
        maxTotalConnections = 
                (new Integer(valveConf.getMaxTotalConnections())).intValue();

        logger.debug("HttpBasic AuthZ maxConnectionsPerHost: " + 
                     maxConnectionsPerHost);
        logger.debug("HttpBasic AuthZ maxTotalConnections: " + 
                     maxTotalConnections);

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

        //protection
        authHeader = null;
        headers = null;

        //Get the http AuthZ header
        Cookie[] requestCookies = null;

        //add support to authCookies
        requestCookies = authCookies;


        // Protection
        logger.debug("Checking request cookies");
        if (requestCookies != null) {
            // Check if the authentication process already happened by looking at the existing cookie
            // The gsa_basic_auth cookie contains the HTTP Basic AuthZ header
            logger.debug("Number of cookies: " + requestCookies.length);
            for (int i = 0; i < requestCookies.length; i++) {
                // Check cookie name
                logger.debug("request cookie: " + requestCookies[i].getName() + 
                             ":" + requestCookies[i].getValue());
                if ((requestCookies[i].getName()).equals(BASIC_COOKIE)) {
                    if (requestCookies[i].getValue() != null) {
                        logger.debug(BASIC_COOKIE + ": " + 
                                     requestCookies[i].getValue());
                        String basicCookie = null;
                        try {
                            basicCookie = 
                                    URLDecoder.decode(requestCookies[i].getValue(), 
                                                      encoder);
                            if ((basicCookie != null) && 
                                (!basicCookie.equals(""))) {
                                authHeader = 
                                        new Header("Authorization", setBasicAuthNChain(basicCookie));
                            }
                        } catch (Exception ex) {
                            logger.error("Error when getting cookie value: " + 
                                         ex.getMessage(), ex);
                        }


                    }
                }
            }
        }


        //
        // Launch the authorization process
        //

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        if (authHeader == null) {

            // no authZ header, can't auth this URL
            logger.debug("No authZ header");
            return statusCode;

        } else {

            //is a Head request?
            boolean isHead = AuthorizationUtils.isHead(request, valveConf);
            logger.debug("isHead?: " + isHead);
            setHeaders();

            // Protection
            if (webProcessor != null) {

                // Protection
                try {

                    // Process authz request
                    String requestType = RequestType.GET_REQUEST;

                    if (isHead) {
                        requestType = RequestType.HEAD_REQUEST;
                    }

                    method = 
                            webProcessor.sendRequest(null, requestType, headers, 
                                                     null, url);

                    // Protection
                    if (method != null) {
                        // Cache status code
                        statusCode = method.getStatusCode();
                        logger.debug("statusCode is.... " + statusCode);

                        if (statusCode == HttpServletResponse.SC_OK) {
                            //check if it's a Head request
                            if (!isHead) {
                                //Process content
                                HTTPAuthZProcessor.processResponse(response, 
                                                                   method, url, 
                                                                   loginUrl);
                            }
                        } else {

                            logger.debug("not AuthZ : should return response Code");
                        }
                    }

                    // Garbagge collect
                    if (method != null) {
                        method.releaseConnection();
                        method = null;
                    }


                } catch (Exception e) {

                    // Log error
                    logger.error("authorization failure: " + e.getMessage(), 
                                 e);
                    statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

                    // Garbagge collect                                   
                    method.releaseConnection();
                    method = null;
                }

            }

            //
            // End of the authorization process
            //

            // Return status code
            return statusCode;
        }

    }


    /**
     * Sets the HTTP Basic authentication headers when authorizing
     * 
     */
    public void setHeaders() {

        int numHeaders = 2;

        try {
            //Set HTTP headers
            headers = new Header[numHeaders];
            // Set User-Agent
            headers[0] = 
                    new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");
            headers[1] = authHeader;
        } catch (Exception e) {
            logger.error("Error when setting Headers: " + e.getMessage(), e);
        }

    }

    /**
     * Gets the Basic chain from the response Authorization header
     * 
     * @param Authorization header
     *  
     * @return the Basic authentication chain
     */
    public String setBasicAuthNChain(String basic) {
        String authNChain = "";
        String basicMsg = "Basic ";

        logger.debug("Basic is: " + basic);
        if ((!basic.equals(null)) && (!basic.equals(""))) {
            //treat basic chain and just get the chain
            authNChain = basicMsg + basic;
        }

        return authNChain;
    }


}
