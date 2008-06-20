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


package com.google.gsa.valve.modules.noauth;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.io.IOException;

import java.util.Vector;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;

import org.apache.log4j.Logger;

/**
 * It implements the access to a backend repository that does not require any 
 * security, so everyone will be able to access to the document.
 * 
 */
public class HTTPNoAuthenticationProcess implements AuthenticationProcessImpl {

    //Valve configuration
    private ValveConfiguration valveConf = null;

    //logger
    private Logger logger = null;


    /**
     * Class constructor
     * 
     */
    public HTTPNoAuthenticationProcess() {
        //Instantiate logger
        logger = Logger.getLogger(HTTPNoAuthenticationProcess.class);

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
     * This method simulates the authentication process against a content 
     * source, so that every document is consider here as public.
     * <p>
     * Creates the authentication cookie and always return 200, unless there is 
     * any problem processing the request.
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

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        // Read cookies
        cookies = request.getCookies();

        // Debug
        logger.debug("HTTP No authentication start");


        //
        // Launch the authentication process
        //

        // Protection
        try {

            Cookie extAuthCookie = null;
            extAuthCookie = new Cookie("gsa_basic_noauth", "");


            extAuthCookie.setValue("true");


            String authCookieDomain = null;
            String authCookiePath = null;
            int authMaxAge = -1;

            // Cache cookie properties
            authCookieDomain = 
                    (request.getAttribute("authCookieDomain")).toString();
            authCookiePath = 
                    (request.getAttribute("authCookiePath")).toString();
            //authMaxAge
            try {
                authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());
            } catch (NumberFormatException nfe) {
                logger.error("Configuration error: chack the configuration file as the number set for authMaxAge is not OK:");
            }

            // Set extra cookie parameters
            extAuthCookie.setDomain(authCookieDomain);
            extAuthCookie.setPath(authCookiePath);
            extAuthCookie.setMaxAge(authMaxAge);

            // Log info
            if (logger.isDebugEnabled())
                logger.debug("Adding gsa_basic_noauth cookie: " + 
                             extAuthCookie.getName() + ":" + 
                             extAuthCookie.getValue() + ":" + 
                             extAuthCookie.getPath() + ":" + 
                             extAuthCookie.getDomain() + ":" + 
                             extAuthCookie.getSecure());

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

            statusCode = HttpServletResponse.SC_OK;

        } catch (Exception e) {

            // Log error
            logger.error("HTTP Basic authentication failure: " + 
                         e.getMessage(), e);

            // Update status code
            statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        }

        // End of the authentication process
        logger.debug("HTTP No Authentication completed (" + statusCode + ")");


        // Return status code
        return statusCode;

    }

}
