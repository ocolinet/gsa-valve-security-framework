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

package com.google.gsa.valve.utils;

import com.google.gsa.valve.configuration.ValveConfiguration;

import com.google.gsa.valve.configuration.ValveConfigurationException;

import org.apache.regexp.RE;

import java.net.URI;

import java.net.URISyntaxException;

import java.util.StringTokenizer;
import java.util.Vector;

import javax.naming.NamingException;

import javax.servlet.http.Cookie;

import javax.servlet.http.HttpServletRequest;

import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * It implements some util methods that are called from any of the Security 
 * Framework classes
 * 
 */
public class ValveUtils {

    //Request GSA Cookie
    private static final String REQUESTGSA_COOKIE = "gsaRequestHost";
    
    //Valve Config Parameter
    private static final String VALVE_CONFIG = "gsaValveConfigPath";
    

    //Logger
    private static Logger logger = Logger.getLogger(ValveUtils.class);

    /**
     * Class constructor
     * 
     */
    public ValveUtils() {
    }

    /**
     * Gets the GSA host from the header (if it exists)
     * 
     * @param returnPath url
     * @param valveConf valve configuration 
     * @param cookies request cookies
     * 
     * @return the GSA host (if any)
     */
    public static String getGSAHost(String returnPath, 
                                    ValveConfiguration valveConf, 
                                    Cookie[] cookies) 
                                    throws ValveConfigurationException {
        return getGSAHost(returnPath, valveConf, cookies, REQUESTGSA_COOKIE);
    }

    /**
     * Gets the GSA host from the header (if it exists)
     * 
     * @param returnPath url
     * @param valveConf valve configuration
     * @param cookies request cookies
     * @param requestHost request host
     * 
     * @return the GSA host (if any)
     */
    public static String getGSAHost(String returnPath, 
                                    ValveConfiguration valveConf, 
                                    Cookie[] cookies, String requestHost) 
                                    throws ValveConfigurationException {

        String returnUrl = null;
        
        //Change in version 2.1: only one searchHost is supported. It's got
        //the first reference from the configuration file
        Vector searchHosts = valveConf.getSearchHosts();
        if (searchHosts != null) {
            returnUrl = searchHosts.elementAt(0) + returnPath;
        } else {
            String errorMsg = "Search host must be defined in the config file";
            throw new ValveConfigurationException (errorMsg);
        }

        return returnUrl;
    }

    /**
     * Sets the request url in the referer cookie
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param searchHosts vector with all the declared search hosts
     * @param authCookieDomain cookie domain
     * @param authCookiePath cookie path
     */
    public static void setRequestGSA(HttpServletRequest request, 
                                     HttpServletResponse response, 
                                     Vector searchHosts, 
                                     String authCookieDomain, 
                                     String authCookiePath) {
        setRequestGSA(request, response, searchHosts, authCookieDomain, 
                      authCookiePath, REQUESTGSA_COOKIE);
    }

    /**
     * Sets the request url in the referer cookie
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param searchHosts vector with all the declared search hosts
     * @param authCookieDomain cookie domain
     * @param authCookiePath cookie path
     * @param requestHost request host
     */
    public static void setRequestGSA(HttpServletRequest request, 
                                     HttpServletResponse response, 
                                     Vector searchHosts, 
                                     String authCookieDomain, 
                                     String authCookiePath, 
                                     String requestHost) {
        //In most situations a referer header is available on the first authN redirect that is the host 
        // of the requesting GSA. This is neded later when the authN process is complete and the valve
        // needs to redirect back to the correct GSA. This is important when multiple GSA's could be using the same
        // Valve.

        String requestGSA = null;

        try {
            requestGSA = request.getHeader("referer");
            logger.debug("Referer Header: " + requestGSA);
        } catch (Exception e) {
            logger.error("Error reading the referer header: " + e);
        }
        Cookie gsaRefererHostCookie = null;
        if (requestGSA != null && !requestGSA.equals("") && 
            !requestGSA.equals("null")) {
            try {
                URI refererURI = new URI(requestGSA);
                if (refererURI.getPort() == -1) {
                    requestGSA = 
                            refererURI.getScheme() + "://" + refererURI.getHost();
                } else {
                    requestGSA = 
                            refererURI.getScheme() + "://" + refererURI.getHost() + 
                            ":" + refererURI.getPort();
                }

                // Check if this is a valid GSA host for this configuration
                RE validGSAHosts = null;
                boolean validGSA = false;
                for (int i = 0; i < searchHosts.size(); i++) {
                    validGSAHosts = 
                            new RE((String)searchHosts.elementAt(i), RE.MATCH_CASEINDEPENDENT);
                    if (validGSAHosts.match(requestGSA)) {
                        logger.debug(requestGSA + 
                                     " is a valid GSA host for this configuration");
                        logger.info("Creating " + requestHost + " with " + 
                                    requestGSA);
                        //Instantiate cookie to store the GSA host name that made this request
                        gsaRefererHostCookie = 
                                new Cookie(requestHost, requestGSA);
                        // Set cookie domain
                        gsaRefererHostCookie.setDomain(authCookieDomain);
                        // Set cookie path
                        gsaRefererHostCookie.setPath(authCookiePath);
                        //Add a value to the cookie incase no other subsequent class does

                        response.addCookie(gsaRefererHostCookie);
                        validGSA = true;
                    }

                }
                if (!validGSA) {
                    logger.warn(requestGSA + 
                                " is not defined as a GSA in this implementation. Not all request come from a GSA, warning is not an issue.");
                }

            } catch (URISyntaxException e) {
                logger.error("URISyntaxException while created URI from referer header" + 
                             e);
            }

        }
    }


    /**
     * Global logout process
     * 
     * @param request HTTP request
     * @param response HTTP response 
     * @param returnPath url
     * @param valveConf Valve configuration
     * 
     * @return HTTP response code
     */
    public static int logout(HttpServletRequest request, 
                             HttpServletResponse response, String returnPath, 
                             ValveConfiguration valveConf) {

        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        /*COOKIES
        //Implement here the overall logout process. Till now it deletes all cookies created by the framework
        //Next releases it should invoke the GSA logout process when it'd be available

        //Delete Valve Auth cookies
        Cookie[] allCookies = null;

        // Protection
        try {
            allCookies = request.getCookies();
            if (allCookies != null) {

                // Look for the authentication cookie
                for (int i = 0; i < allCookies.length; i++) {

                    logger.debug("Cookie: "+allCookies[i].getName());

                    //look for all the cookies start with "gsa" and delete them
                    if ((allCookies[i].getName()).startsWith("gsa")) {

                        Cookie gsaCookie = new Cookie (allCookies[i].getName(), allCookies[i].getValue());


                        //the next lines have been added for IE support

                        gsaCookie.setDomain(authCookieDomain);
                        gsaCookie.setPath(authCookiePath);


                        //Set max age to cero
                        gsaCookie.setMaxAge(0);

                        response.addCookie(gsaCookie);

                        // Debug
                        if (logger.isDebugEnabled()) logger.debug("GSA cookie: [" + gsaCookie.getName() + " has been deleted ]");

                    }

                }

            }
        }
        catch (Exception e) {
            logger.error ("Exception during logout process: "+e.getMessage(),e);
        }*/


        //REDIRECTING
        /*
        //returns statusCode (-1 if resending)
        try  {

            if (returnPath != null) {
                //Forms based authentication: able to redirect
                String loginUrl = valveConf.getLoginUrl();
                //String url = loginUrl + "?returnPath=" + returnPath;
                String url = loginUrl;
                response.sendRedirect(url);
                statusCode = -1;
            }

        } catch (Exception ex)  {
            logger.error ("Exception during logout process: "+ex.getMessage(),ex);
        } finally  {
        }
        */

        return statusCode;
    }
    
    
    /**
     * Valve Config parameter reading process
     * 
     * @return Valve Config File Path
     */
    public static String readValveConfigParameter () {        
        
        //Naming context
        javax.naming.Context ctx;
        javax.naming.Context env;
        
        //Valve Config Path
        String gsaValveConfigPath = null;
        
        try {
            ctx = new javax.naming.InitialContext();
            env = (javax.naming.Context)ctx.lookup("java:comp/env");
            //Get gsaValveConfigPath
            gsaValveConfigPath = (String) env.lookup(VALVE_CONFIG);
        } catch (NamingException e) {
            logger.error ("Naming Exception during Config File param reading: " +
            e.getMessage(), e);
        }
        
        return gsaValveConfigPath;
    }

}
