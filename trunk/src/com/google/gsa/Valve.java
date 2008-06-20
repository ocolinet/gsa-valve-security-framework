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

import java.net.URL;
import java.net.URLDecoder;

import java.util.Enumeration;
import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;


import org.apache.log4j.Logger;
import org.apache.regexp.RE;

import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveConfigurationDigester;

import com.google.gsa.sessions.nonValidSessionException;
import com.google.gsa.valve.configuration.ValveConfigurationException;
import com.google.gsa.valve.errormgmt.ErrorManagement;
import com.google.gsa.valve.utils.ValveUtils;


/**
 * This is the Valve filter class that processes the requests when Forms Based 
 * authentication is in place. SAML interface does not use this filter at all.
 * It checks if the authentication cookie exists, and if so processes the 
 * authorization request. If the cookie does not exist, the whole authentication 
 * process is launched.
 * 
 */
public class Valve extends ValveBase {

    private static final String info = "com.google.gsa.Valve/1.4.1";
    private static final String REFERER_COOKIE = "gsaReferer";

    private static Logger logger = null;

    private String gsaValveConfigPath = null;

    private boolean isActive = true;
    private String authorizationProcessClsName = null;
    private AuthorizationProcessImpl authorizationProcessCls = null;
    private String authenticationProcessClsName = null;

    private AuthenticationProcessImpl authenticationProcessCls = null;
    private String loginUrl = null;
    private String authUrl = null;
    private String authCookieDomain = null;
    private String authCookiePath = null;
    private String authMaxAge = null;
    private String authCookieName = null;

    //A list of valid search hosts for this configuration
    private Vector searchHosts = null;

    //Valve configuration instance
    private ValveConfiguration valveConf = null;

    //Error management instance
    private ErrorManagement errorMngmt = null;
    private String errorLocation = null;

    private String testFormsCrawlUrl = null;

    /* Kerberos Vars that have to be defined in the config file */
    private boolean isKerberos = false;
    private String KrbLoginUrl = null;
    private boolean KrbUsrPwdCrawler = false;
    private String KrbUsrPwdCrawlerUrl = null;

    /* Session Mgmt */
    private boolean isSessionEnabled = false;

    private static final String GSA_CRAWLER_USER = "gsa-crawler";
    private static final String GSA_CRAWLING_CONTENT = "(Enterprise";

    // URL patterns
    //TODO These should be configuration items
    private static RE gif = new RE(".gif$");
    private static RE jpg = new RE(".jpg$");
    private static RE png = new RE(".png$");
    private static RE js = new RE(".js$");
    private static RE ico = new RE(".ico$");
    private static RE css = new RE(".css$");
    private static RE robots = new RE("robots.txt$");

    private static Vector<RE> filters = new Vector<RE>(0);

    static {

        // Instantiate logger
        logger = Logger.getLogger(Valve.class);

        logger.debug("Valve loaded (" + info + ")");

        // Add filtered URL patterns
        filters.add(gif);
        filters.add(jpg);
        filters.add(png);
        filters.add(js);
        filters.add(ico);
        filters.add(css);
        filters.add(robots);

    }

    /**
     * Gets Valve info
     *  
     * @return info
     */
    public String getInfo() {
        return info;
    }

    /**
     * Gets the authorization process class name
     * 
     * @return authorization process class name
     */
    public String getAuthorizationProcessImpl() {
        return this.authorizationProcessClsName;
    }

    /**
     * Sets the authorization process class name
     * 
     * @param authorizationProcessClsName the authorization process class name
     */
    public void setAuthorizationProcessImpl(String authorizationProcessClsName) {

        logger.debug("Setting authorizationProcessClsName: " + 
                     authorizationProcessClsName);

        // Cache value
        this.authorizationProcessClsName = authorizationProcessClsName;

        // Protection
        if ((this.authorizationProcessClsName == null) || 
            (this.authorizationProcessClsName.equals(""))) {

            // Log error
            logger.error("Valve parameter [authorizationProcessImpl] has not been set correctly (null/empty)");

            // Set flag
            isActive = false;

            // Return
            return;

        }

        try {

            // Instantiate the authorization process class

            authorizationProcessCls = 
                    (AuthorizationProcessImpl)Class.forName(authorizationProcessClsName).newInstance();
            authorizationProcessCls.setValveConfiguration(valveConf);

        } catch (InstantiationException ie) {

            // Log error
            logger.error("Valve parameter [authorizationProcessImpl] has not been set correctly - InstantiationException");

            // Set flag
            isActive = false;

        } catch (IllegalAccessException iae) {

            // Log error
            logger.error("Valve parameter [authorizationProcessImpl] has not been set correctly - IllegalAccessException");

            // Set flag
            isActive = false;

        } catch (ClassNotFoundException cnfe) {

            // Log error
            logger.error("Valve parameter [authorizationProcessImpl] has not been set correctly - ClassNotFoundException");

            // Set flag
            isActive = false;

        }

        if (!isActive) {
            logger.debug("Valve is set inactive in setAuthorizationProcessImpl");
        }

    }

    /**
     * Gets the authentication process class name
     * 
     * @return the authentication process class name
     */
    public String getAuthenticationProcessImpl() {
        return this.authenticationProcessClsName;
    }

    /**
     * Sets the authentication process class name
     * 
     * @param authenticationProcessClsName the authentication process class name
     */
    public void setAuthenticationProcessImpl(String authenticationProcessClsName) {

        logger.debug("Setting authenticationProcessClsName: " + 
                     authenticationProcessClsName);

        // Cache value
        this.authenticationProcessClsName = authenticationProcessClsName;

        // Protection
        if ((this.authenticationProcessClsName == null) || 
            (this.authenticationProcessClsName.equals(""))) {
            logger.debug("authenticationProcessClsName null or empty");
            // Log error
            logger.error("Valve parameter [authenticationProcessImpl] has not been set correctly - null/empty");

            // Set flag
            isActive = false;

            // Return
            return;

        }

        try {

            // Instantiate the authentication process class
            logger.debug("Trying to Instantiate AuthenticationProcessImpl");
            authenticationProcessCls = 
                    (AuthenticationProcessImpl)Class.forName(authenticationProcessClsName).newInstance();
            authenticationProcessCls.setValveConfiguration(valveConf);
            logger.debug("AuthenticationProcessImpl instantiation complete");

        } catch (InstantiationException ie) {

            // Log error
            logger.error("Valve parameter [authenticationProcessImpl] has not been set correctly - InstantiationException");

            // Set flag
            isActive = false;

        } catch (IllegalAccessException iae) {

            // Log error
            logger.error("Valve parameter [authenticationProcessImpl] has not been set correctly - IllegalAccessException");

            // Set flag
            isActive = false;

        } catch (ClassNotFoundException cnfe) {

            // Log error
            logger.error("Valve parameter [authenticationProcessImpl] has not been set correctly - ClassNotFoundException");

            // Set flag
            isActive = false;

        }
        if (!isActive) {
            logger.debug("Valve is set inactive in setAuthenticationProcessImpl");
        }

    }

    /**
     * Gets login url
     * 
     * @return login url
     */
    public String getLoginUrl() {
        return this.loginUrl;
    }

    /**
     * Sets login url
     * 
     * @param loginUrl login url
     */
    public void setLoginUrl(String loginUrl) {

        logger.debug("Setting loginUrl: " + loginUrl);
        // Cache value
        this.loginUrl = loginUrl;

        // Protection
        if ((this.loginUrl == null) || (this.loginUrl.equals(""))) {

            // Log error
            logger.error("Valve parameter [loginUrl] has not been set correctly");

            // Set flag
            isActive = false;

        }

    }


    /**
     * Gets if Kerberos is in place
     * 
     * @return if it's kerberos
     */
    public boolean getIsKerberos() {
        return isKerberos;
    }

    /**
     * Sets if Kerberos is in place
     *  
     * @param isNewKerberos if it's kerberos
     */
    public void setIsKerberos(boolean isNewKerberos) {
        logger.debug("IsKerberos: " + isNewKerberos);
        this.isKerberos = isNewKerberos;
    }

    /**
     * Gets if session is enabled
     * 
     * @return if session is enabled
     */
    public boolean getIsSessionEnabled() {
        return isSessionEnabled;
    }

    /**
     * Sets if session is enabled
     * 
     * @param isSessionEnabled if session is enabled
     */
    public void setIsSessionEnabled(boolean isSessionEnabled) {
        logger.debug("isSessionEnabled: " + isSessionEnabled);
        this.isSessionEnabled = isSessionEnabled;
    }

    /**
     * Gets if the it does the crawling when Kerberos is in place
     * 
     * @return if crawling is done thru username and password for Kerberos
     */
    public boolean getKrbUsrPwdCrawler() {
        return KrbUsrPwdCrawler;
    }

    /**
     * Sets if the it does the crawling when Kerberos is in place
     * 
     * @param KrbUsrPwdCrawler if crawling is done thru username and password for Kerberos
     */
    public void setKrbUsrPwdCrawler(boolean KrbUsrPwdCrawler) {
        logger.debug("KrbUsrPwdCrawler: " + KrbUsrPwdCrawler);
        this.KrbUsrPwdCrawler = KrbUsrPwdCrawler;
    }

    /**
     * Gets the crawling url when Kerberos crawling is in place
     * 
     * @return crawling url
     */
    public String getKrbUsrPwdCrawlerUrl() {
        return KrbUsrPwdCrawlerUrl;
    }

    /**
     * Sets the crawling url when Kerberos crawling is in place
     * 
     * @param KrbUsrPwdCrawlerUrl crawling url
     */
    public void setKrbUsrPwdCrawlerUrl(String KrbUsrPwdCrawlerUrl) {
        logger.debug("KrbUsrPwdCrawlerUrl: " + KrbUsrPwdCrawlerUrl);
        this.KrbUsrPwdCrawlerUrl = KrbUsrPwdCrawlerUrl;
    }

    /**
     * Gets the login url when Kerberos' additional authentication is set
     * 
     * @return login url
     */
    public String getKrbLoginUrl() {
        return KrbLoginUrl;
    }

    /**
     * Sets the login url when Kerberos' additional authentication is set
     * 
     * @param KrbLoginUrl login url
     */
    public void setKrbLoginUrl(String KrbLoginUrl) {
        logger.debug("KrbLoginUrl: " + KrbLoginUrl);
        this.KrbLoginUrl = KrbLoginUrl;
    }

    /**
     * Gets the internal test URL
     * 
     * @return internal test URL
     */
    public String getTestFormsCrawlUrl() {
        return this.testFormsCrawlUrl;
    }

    /**
     * Sets the internal test URL
     * 
     * @param testFormsCrawlUrl internal test URL
     */
    public void setTestFormsCrawlUrl(String testFormsCrawlUrl) {

        logger.debug("testFormsCrawlUrl: " + testFormsCrawlUrl);
        // Cache value
        this.testFormsCrawlUrl = testFormsCrawlUrl;

    }

    /**
     * Gets the authenticate servlet path
     * 
     * @return authenticate servlet path
     */
    public String getAuthenticateServletPath() {
        return this.authUrl;
    }

    /**
     * Sets the authenticate servlet path
     * 
     * @param authUrl authenticate servlet path
     */
    public void setAuthenticateServletPath(String authUrl) {

        logger.debug("Setting authUrl: " + authUrl);

        // Cache value
        this.authUrl = authUrl;

        // Protection
        if ((this.authUrl == null) || (this.authUrl.equals(""))) {

            // Log error
            logger.error("Valve parameter [authenticateServletPath] has not been set correctly");

            // Set flag
            isActive = false;

        }

    }

    /**
     * Gets the authentication cookie domain
     * 
     * @return authentication cookie domain
     */
    public String getAuthCookieDomain() {
        return this.authCookieDomain;
    }

    /**
     * Sets the authentication cookie domain
     * 
     * @param authCookieDomain authentication cookie domain
     */
    public void setAuthCookieDomain(String authCookieDomain) {


        logger.debug("Setting authCookieDomain: " + authCookieDomain);
        // Cache value
        this.authCookieDomain = authCookieDomain;

        // Protection
        if ((this.authCookieDomain == null) || 
            (this.authCookieDomain.equals(""))) {

            // Log error
            logger.error("Valve parameter [authCookieDomain] has not been set correctly");

            // Set flag
            isActive = false;

        }

    }

    /**
     * Gets the authentication cookie path
     * 
     * @return authentication cookie path
     */
    public String getAuthCookiePath() {
        return this.authCookiePath;
    }

    /**
     * Sets the authentication cookie path
     * 
     * @param authCookiePath authentication cookie path
     */
    public void setAuthCookiePath(String authCookiePath) {


        logger.debug("Setting authCookiePath: " + authCookiePath);
        // Cache value
        this.authCookiePath = authCookiePath;

        // Protection
        if ((this.authCookiePath == null) || 
            (this.authCookiePath.equals(""))) {

            // Log error
            logger.error("Valve parameter [authCookiePath] has not been set correctly");

            // Set flag
            isActive = false;

        }

    }

    /**
     * Gets the authentication cookie max age
     * 
     * @return authentication cookie max age
     */
    public String getAuthMaxAge() {
        return this.authMaxAge;
    }

    /**
     * Sets the authentication cookie max age
     * 
     * @param authMaxAge authentication cookie max age
     */
    public void setAuthMaxAge(String authMaxAge) {


        logger.debug("Setting authMaxAge: " + authMaxAge);
        // Cache value
        this.authMaxAge = authMaxAge;

        // Protection
        if ((this.authMaxAge == null) || (this.authMaxAge.equals(""))) {

            // Log error
            logger.error("Valve parameter [authMaxAge] has not been set correctly");

            // Set flag
            isActive = false;

        }

        try {

            // Protection
            Integer.parseInt(authMaxAge);

        } catch (NumberFormatException nfe) {

            // Log error
            logger.error("Valve parameter [authMaxAge] has not been set correctly");

            // Set flag
            isActive = false;

        }

    }

    /**
     * Gets the authentication cookie name
     * 
     * @return authentication cookie name
     */
    public String getAuthCookieName() {
        return this.authCookieName;
    }

    /**
     * Sets the authentication cookie name
     * 
     * @param authCookieName authentication cookie name
     */
    public void setAuthCookieName(String authCookieName) {


        logger.debug("Setting authCookieName: " + authCookieName);
        // Cache value
        this.authCookieName = authCookieName;

        // Protection
        if ((this.authCookieName == null) || 
            (this.authCookieName.equals(""))) {

            // Log error
            logger.error("Valve parameter [authCookieName] has not been set correctly");

            // Set flag
            isActive = false;

        }

    }

    /**
     * Gets the error location path
     * 
     * @return the error location path
     */
    public String getErrorLocation() {
        return this.errorLocation;
    }

    /**
     * Sets the error location path
     * 
     * @param errorLocation the error location path
     */
    public void setErrorManagement(String errorLocation) {

        if (errorMngmt == null) {

            logger.debug("Setting errorLocation: " + errorLocation);

            // Cache value
            this.errorLocation = errorLocation;

            // Protection
            if ((this.errorLocation == null) || 
                (this.errorLocation.equals(""))) {

                // Log error
                logger.error("Valve parameter [errorLocation] has not been set correctly");

                // Set flag
                isActive = false;

            } else {
                try {
                    errorMngmt = new ErrorManagement(errorLocation);
                } catch (ValveConfigurationException e) {
                    logger.error("Error Location was not properly setup in the config file: " + 
                                 e);
                }
            }
        }

    }

    /**
     * Gets the search host vector
     * 
     * @return search host vector
     */
    public Vector getSearchHosts() {
        return this.searchHosts;
    }

    /**
     * Sets the search host vector
     * 
     * @param searchHosts search host vector
     */
    public void setSearchHosts(Vector searchHosts) {

        for (int i = 0; i < searchHosts.size(); i++) {
            logger.debug("Setting search host: " + searchHosts.elementAt(i));
        }
        // Cache value
        this.searchHosts = searchHosts;

        // Protection
        if ((this.searchHosts == null) || (this.searchHosts.isEmpty())) {

            // Log error
            logger.error("Valve parameter [searchHost] has not been set correctly");

            // Set flag
            isActive = false;

        }

    }

    /**
     * Valve's invoke method. It implements the whole authentication and 
     * authorization logic. Checks if the authentication cookie exists, and if 
     * so processes the authorization request. 
     * If the cookie does not exist, the whole authentication process is launched.
     * 
     * 
     * @param request HTTP request
     * @param response HTTP response
     * 
     * @throws IOException
     * @throws ServletException
     */
    public void invoke(Request request, Response response) throws IOException, 
                                                                  ServletException {


        String userAgent = null;
        Cookie cookies[] = null;
        Cookie gsaAuthCookie = null;
        Cookie gsaRefererCookie = null;
        HttpServletRequest httpRequest = null;
        String url = null;
        int statusCode = 0;


        //Useful logging to know where a request came from
        logger.debug("Request from host: " + request.getRemoteAddr());
        // Protection
        if (!isActive) {

            // Process request
            logger.debug("Before not active");
            getNext().invoke(request, response);
            logger.debug("After not active");

            // Return
            return;

        }


        // Retrieve HTTP request
        httpRequest = request.getRequest();

        //Setting request attributes			    
        httpRequest.setAttribute("gsaValveConfigPath", gsaValveConfigPath);
        httpRequest.setAttribute("refererCookie", REFERER_COOKIE);

        // Cache requested URL
        url = (httpRequest.getRequestURL()).toString();


        RE filter = null;

        // Parse filters
        for (Enumeration e = filters.elements(); e.hasMoreElements(); ) {

            // Read pattern
            filter = (RE)e.nextElement();

            // Match patterns
            if (filter.match(url)) {

                // Debug
                if (logger.isDebugEnabled())
                    logger.debug("Filtered URL: [" + url + "]");

                // Process request
                logger.debug("Before filter match");
                getNext().invoke(request, response);
                logger.debug("After filter match");

                // Return
                return;

            }

        }

        // Read User-Agent header
        userAgent = request.getHeader("User-Agent");

        // debug
        logger.trace("User-Agent: [" + userAgent + "]");

        // info
        logger.info("Processing request: [" + url + "]");

        //Get the GSA that made the request as need it later to direct after initial AuthN

        //A cookie to store the GSA host that made this request, required to support mutliple GSA host
        //show all headers in trace logging. Been useful in understand how and when a refere header is set
        Enumeration headers = request.getHeaderNames();
        while (headers.hasMoreElements()) {
            String headerName = (String)headers.nextElement();
            logger.trace("HEADER: " + headerName + "=" + 
                         request.getHeader(headerName));
        }


        ValveUtils.setRequestGSA(request, response, searchHosts, 
                                 authCookieDomain, authCookiePath);


        // Retrieve and display cookies for trace logging
        cookies = request.getCookies();
        if (cookies != null) {
            //Log out the cookies 
            for (int i = 0; i < cookies.length; i++) {
                logger.trace("Cookie[" + i + "]: " + cookies[i].getName() + 
                             " (" + cookies[i].getValue() + ") " + 
                             cookies[i].getDomain());
            }
        }


        // Protection
        if (cookies != null) {

            // Look for the authentication cookie
            for (int i = 0; i < cookies.length; i++) {

                if ((cookies[i].getName()).equals(authCookieName)) {
                    // Cache cookie
                    gsaAuthCookie = cookies[i];

                    // Debug
                    if (logger.isDebugEnabled())
                        logger.debug("Authentication cookie: [" + 
                                     gsaAuthCookie.getName() + ":" + 
                                     gsaAuthCookie.getValue() + "]");

                } else {
                    // Look for referer cookie
                    if ((cookies[i].getName()).equals(REFERER_COOKIE)) {

                        // Cache cookie
                        gsaRefererCookie = cookies[i];

                        // Debug
                        if (logger.isDebugEnabled())
                            logger.debug("Referer cookie: [" + 
                                         gsaRefererCookie.getName() + ", " + 
                                         gsaRefererCookie.getValue() + "]");

                    }
                }

                if ((gsaAuthCookie != null) && (gsaRefererCookie != null)) {
                    // Exit
                    break;
                }

            }

        }

        // Handle the authenticated cases
        if (gsaAuthCookie != null) {

            logger.debug("The user is already authenticated");

            // Handle a GET query (external login server configuration), a proxied request or a 
            // GET access to the login page
            if (((new URL(url)).getPath()).equals((new URL(loginUrl)).getPath())) {

                //logger.debug("authenticated case");
                String returnPath = null;
                String redirectURI = null;

                // Cache the returnPath parameter
                returnPath = request.getParameter("returnPath");
                logger.debug("Return Path:" + returnPath);
                // Protection
                if (returnPath != null) {

                    String queryString = null;

                    // Cache query string
                    queryString = httpRequest.getQueryString();

                    // Extract returnPath parameter value
                    returnPath = 
                            queryString.substring(queryString.indexOf("returnPath=") + 
                                                  "returnPath=".length());

                    returnPath = URLDecoder.decode(returnPath, "UTF-8");

                    // Debug
                    if (logger.isDebugEnabled())
                        logger.debug("Reading HTTP parameter [returnPath]: " + 
                                     returnPath);

                    // Initialize redirect URI
                    redirectURI = returnPath;


                    // Protection
                    if (returnPath.startsWith("/search?")) {
                        logger.debug("Request is for search, need to redirect back to the GSA");
                        redirectURI = 
                                ValveUtils.getGSAHost(returnPath, valveConf, 
                                                      cookies);

                    }

                    // Instantiate referer cookie
                    gsaRefererCookie = new Cookie(REFERER_COOKIE, redirectURI);

                    // Set cookie domain					
                    gsaRefererCookie.setDomain(authCookieDomain);

                    // Set domain path
                    gsaRefererCookie.setPath(authCookiePath);


                    logger.info("Referer cookie set to: [" + 
                                gsaRefererCookie.getName() + ", " + 
                                gsaRefererCookie.getValue() + "]");

                    // Add referer cookie
                    response.addCookie(gsaRefererCookie);

                    // Process the search request
                    if (returnPath.startsWith("/search?")) {

                        // Redirect to the search front-end
                        logger.debug("Sending direct back to GSA to do the search");
                        response.sendRedirect(gsaRefererCookie.getValue());

                        // Debug
                        if (logger.isDebugEnabled())
                            logger.debug("Redirecting user to: " + 
                                         gsaRefererCookie.getValue());

                        // Process the proxied request
                    } else {

                        // Debug
                        if (logger.isDebugEnabled())
                            logger.debug("Launching the authorization process");

                        try {
                            //Set default value
                            statusCode = HttpServletResponse.SC_UNAUTHORIZED;

                            //Retrieve cookies
                            cookies = response.getCookies();
                            if (cookies != null) {
                                //Log out the cookies 
                                for (int i = 0; i < cookies.length; i++) {
                                    logger.trace("BEFORE AuthZ: Response Cookie[" + 
                                                 i + "]: " + 
                                                 cookies[i].getName() + " - " + 
                                                 cookies[i].getDomain() + 
                                                 " - " + 
                                                 cookies[i].getValue());
                                }
                            }
                            cookies = request.getCookies();
                            if (cookies != null) {
                                //Log out the cookies 
                                for (int i = 0; i < cookies.length; i++) {
                                    logger.trace("BEFORE AuthZ: Request Cookie[" + 
                                                 i + "]: " + 
                                                 cookies[i].getName() + " - " + 
                                                 cookies[i].getDomain() + 
                                                 " - " + 
                                                 cookies[i].getValue());
                                }
                            }

                            // Launch the authorization process for this domain
                            authorizationProcessCls.setValveConfiguration(valveConf);

                            //Changing the id to null
                            statusCode = 
                                    authorizationProcessCls.authorize(request, 
                                                                      response, 
                                                                      response.getCookies(), 
                                                                      gsaRefererCookie.getValue(), 
                                                                      null);

                            //set the status code that is coming from the AuthZ
                            setStatusCode(response, statusCode);

                            logger.debug("Response status code is: " + 
                                         statusCode);

                            cookies = response.getCookies();
                            if (cookies != null) {
                                //Log out the cookies 
                                for (int i = 0; i < cookies.length; i++) {
                                    logger.trace("AFTER AuthZ: Response Cookie[" + 
                                                 i + "]: " + 
                                                 cookies[i].getName() + " - " + 
                                                 cookies[i].getDomain() + 
                                                 " - " + 
                                                 cookies[i].getValue());
                                }
                            }

                        } catch (nonValidSessionException nvE) {

                            logger.debug("Non valid session. Proceeding to logout");

                            statusCode = 
                                    ValveUtils.logout(request, response, redirectURI, 
                                                      valveConf);

                            if (statusCode != -1) {
                                logger.debug("Setting the error code to: " + 
                                             statusCode);
                                response.setStatus(statusCode);
                            }


                        } catch (Exception e) {

                            // Debug
                            logger.error("Authorization process raised exception: " + 
                                         e.getMessage(), e);
                            //e.printStackTrace(); 
                            if (statusCode == 0) {
                                statusCode = 
                                        HttpServletResponse.SC_UNAUTHORIZED;
                            }

                            logger.debug("Setting the error code to: " + 
                                         statusCode);
                            response.setStatus(statusCode);

                        }

                        // Protection
                        if (statusCode != HttpServletResponse.SC_OK) {

                            //Send personalized error message (if any)
                            if (errorMngmt != null) {
                                errorMngmt.showHTMLError(response, 
                                                         errorMngmt.processError(statusCode));
                            } else {
                                logger.error("AuthZ error message couldn't be shown as the ErrorMessage instance does not exist");
                            }

                        }

                        // Debug
                        if (logger.isDebugEnabled())
                            logger.debug("Authorization process completed");

                    }

                    return;

                }

                // Perform the request

                logger.debug("Before authz");
                getNext().invoke(request, response);
                logger.debug("After authz");

                // Return
                return;

            }

            // Avoid access to the Authenticate servlet once connected
            if ((request.getServletPath()).equals(authUrl)) {

                // Redirect to the login page
                response.sendRedirect(response.encodeRedirectURL(loginUrl));

                // Return
                return;

            }

            // Initialize status code
            statusCode = HttpServletResponse.SC_UNAUTHORIZED;

            // Debug
            logger.debug("AuthZ for pages on the valve server");

            try {


                // Launch the authorization process for this domain
                statusCode = 
                        authorizationProcessCls.authorize(request, response, 
                                                          response.getCookies(), 
                                                          url, "root");

                setStatusCode(response, statusCode);


            } catch (Exception e) {

                // Debug
                logger.error("Authorization process raised exception: " + 
                             e.getMessage(), e);

            }

            // Protection
            if (statusCode != HttpServletResponse.SC_OK) {

                //Send personalized error message (if any)
                if (errorMngmt != null) {
                    errorMngmt.showHTMLError(response, 
                                             errorMngmt.processError(statusCode));
                } else {
                    logger.error("AuthZ error message couldn't be shown as the ErrorMessage instance does not exist");
                }

                if (logger.isDebugEnabled())
                    logger.debug("Authorization process is distinct to 200 with error code: " + 
                                 statusCode);

                return;

            }

            // Debug
            if (logger.isDebugEnabled())
                logger.debug("Authorization process completed");

            // Perform the request
            logger.debug("Before perform request");
            getNext().invoke(request, response);
            logger.debug("After perform request");
            // Return
            return;

        } // End of the authenticated cases 

        logger.debug("url... " + (new URL(url)).getPath());
        logger.debug("LoginURL: " + loginUrl);

        // Handle a redirect to the login page (302), an initial GET query (external login server configuration) or a proxied request
        if (((new URL(url)).getPath()).equals((new URL(loginUrl)).getPath())) {

            logger.debug("URL is equal to the loginURL");

            String returnPath = null;

            // Cache the returnPath parameter
            returnPath = request.getParameter("returnPath");

            logger.debug("ReturnPath is... " + returnPath);

            // Protection
            if (returnPath != null) {

                String queryString = null;

                // Cache query string
                queryString = httpRequest.getQueryString();

                // Extract 'returnPath' parameter value
                returnPath = 
                        queryString.substring(queryString.indexOf("returnPath=") + 
                                              "returnPath=".length());

                // Debug
                if (logger.isDebugEnabled())
                    logger.debug("Reading HTTP parameter [returnPath]: " + 
                                 returnPath);

                // Instantiate referer cookie
                gsaRefererCookie = 
                        new Cookie(REFERER_COOKIE, response.encodeRedirectURL(loginUrl + 
                                                                              "?returnPath=" + 
                                                                              returnPath));

                // Set cookie domain
                gsaRefererCookie.setDomain(authCookieDomain);

                // Set domain path
                gsaRefererCookie.setPath(authCookiePath);

                // Add referer cookie
                response.addCookie(gsaRefererCookie);
                request.addCookie(gsaRefererCookie);

                // Debug
                if (logger.isDebugEnabled())
                    logger.debug("Referer cookie set to: [" + 
                                 gsaRefererCookie.getName() + ", " + 
                                 gsaRefererCookie.getValue() + "]");

            }

            // Protection
            if (gsaRefererCookie == null) {

                logger.debug("Creating gsaRefererCookie");
                // Instantiate referer cookie
                gsaRefererCookie = 
                        new Cookie(REFERER_COOKIE, response.encodeRedirectURL(loginUrl));

                // Set cookie domain
                gsaRefererCookie.setDomain(authCookieDomain);

                // Set domain path
                gsaRefererCookie.setPath(authCookiePath);

                // Add referer cookie
                response.addCookie(gsaRefererCookie);
                request.addCookie(gsaRefererCookie);

                // Debug
                if (logger.isDebugEnabled())
                    logger.debug("Referer cookie set to: [" + 
                                 gsaRefererCookie.getName() + ", " + 
                                 gsaRefererCookie.getValue() + "]");

            }

            //CLAZARO: support for crawling
            logger.debug("user is " + userAgent);

            //support for crawling multiple credentials with kerberos                    
            if ((isKerberos) && (KrbUsrPwdCrawler)) {
                logger.debug("Crawling done thru Forms based authn");
                //check if the user is crawler
                //if ((userAgent.contains(GSA_CRAWLER_USER))&&(userAgent.indexOf(GSA_CRAWLING_CONTENT) != -1)) { 
                if (userAgent.contains(GSA_CRAWLER_USER)) {
                    logger.debug("user is " + GSA_CRAWLER_USER);
                    logger.debug("testFormsCrawlUrl: " + testFormsCrawlUrl);
                    if ((testFormsCrawlUrl != null) && 
                        ((testFormsCrawlUrl != ""))) {
                        logger.debug("(new URL(testFormsCrawlUrl)).getPath() " + 
                                     (new URL(testFormsCrawlUrl)).getPath());

                        if (returnPath != null) {
                            logger.debug("(new URL(returnPath)).getPath() " + 
                                         (new URL(returnPath)).getPath());

                            if ((new URL(returnPath)).getPath().equals((new URL(testFormsCrawlUrl)).getPath())) {
                                String userIdKrb = 
                                    request.getParameter("UserIDKrb");
                                logger.debug("the Url is equal to the test url for crawling thru forms based authn");
                                if (userIdKrb == null) {
                                    //redirecting to the crawler login page
                                    logger.debug("Redirecting to the Crawler login page: " + 
                                                 KrbUsrPwdCrawlerUrl);
                                    response.sendRedirect(KrbUsrPwdCrawlerUrl);
                                    return;
                                }
                            }
                        }


                    }
                }
            }

            // Perform the request
            logger.debug("Before perform request");
            getNext().invoke(request, response);
            logger.debug("After perform request");
            // Return
            return;

        }

        // Handle the POST request to the Authenticate servlet
        if ((request.getServletPath()).equals(authUrl)) {

            // Perform the request
            logger.debug("Before authUrl : " + request.getServletPath());
            getNext().invoke(request, response);
            logger.debug("After authUrl");
            // Return
            return;

        }

        //Handle the access to the Login pages for Kerberos 
        if (isKerberos) {
            //If the request is the Login pages (Crawler or Forms Based Authn), then go on
            if (((request.getRequestURI()).equals((new URL(KrbLoginUrl)).getPath())) || 
                ((request.getRequestURI()).equals((new URL(KrbUsrPwdCrawlerUrl)).getPath()))) {

                // Perform the request
                logger.debug("Before authUrl");
                getNext().invoke(request, response);
                logger.debug("After authUrl");
                // Return
                return;

            }
        }

        logger.debug("Creating referer cookie (again?)");
        // Instantiate referer cookie
        gsaRefererCookie = new Cookie(REFERER_COOKIE, url);

        // Set cookie domain
        gsaRefererCookie.setDomain(authCookieDomain);

        // Set domain path
        gsaRefererCookie.setPath(authCookiePath);

        // Add referer cookie
        response.addCookie(gsaRefererCookie);

        // Debug
        if (logger.isDebugEnabled())
            logger.debug("Referer cookie set to: [" + 
                         gsaRefererCookie.getName() + ", " + 
                         gsaRefererCookie.getValue() + "]");

        // Redirect to the login page
        response.sendRedirect(response.encodeRedirectURL(loginUrl));

        // Debug
        if (logger.isDebugEnabled())
            logger.debug("Redirecting user from: " + url + " to login page: " + 
                         loginUrl);

    }

    /**
     * Gets the Valve reference string value
     * 
     * @return reference value
     */
    public String toString() {

        StringBuffer sb = new StringBuffer("GSA SSO Valve [");
        if (container != null)
            sb.append(container.getName());
        sb.append("]");
        return (sb.toString());

    }

    /**
     * Gets the Valve config file path
     * 
     * @return config file path
     */
    public String getGsaValveConfigPath() {
        return gsaValveConfigPath;
    }

    /**
     * Sets the Valve config file path
     * 
     * @param gsaValveConfigPath Valve config file path
     */
    public void setGsaValveConfigPath(String gsaValveConfigPath) {
        this.gsaValveConfigPath = gsaValveConfigPath;

        logger.debug("Loading configuration from " + gsaValveConfigPath);
        //Load configuration
        ValveConfigurationDigester valveConfDigester = 
            new ValveConfigurationDigester();
        try {
            logger.debug("Configuration");
            valveConf = valveConfDigester.run(gsaValveConfigPath);
        } catch (Exception e) {
            logger.error("Error getting Config instance: " + e.getMessage(), 
                         e);
            e.printStackTrace();
        }
        logger.debug("Configuration loaded");

        logger.debug("Number of search hosts defined: " + 
                     valveConf.getSearchHosts().size());
        setSearchHosts(valveConf.getSearchHosts());

        setLoginUrl(valveConf.getLoginUrl());
        setAuthCookiePath(valveConf.getAuthCookiePath());
        setAuthMaxAge(valveConf.getAuthMaxAge());
        setAuthCookieName(valveConf.getAuthCookieName());
        setAuthCookieDomain(valveConf.getAuthCookieDomain());
        setAuthenticateServletPath(valveConf.getAuthenticateServletPath());

        setAuthenticationProcessImpl(valveConf.getAuthenticationProcessImpl());
        setAuthorizationProcessImpl(valveConf.getAuthorizationProcessImpl());

        setIsKerberos(new Boolean(valveConf.getKrbConfig().isKerberos()).booleanValue());
        if (getIsKerberos()) {
            setKrbLoginUrl(valveConf.getKrbConfig().getKrbLoginUrl());
            setKrbUsrPwdCrawler(new Boolean(valveConf.getKrbConfig().isKrbUsrPwdCrawler()).booleanValue());
            setKrbUsrPwdCrawlerUrl(valveConf.getKrbConfig().getKrbUsrPwdCrawlerUrl());
        } else {
            setKrbLoginUrl(null);
            setKrbUsrPwdCrawler(false);
            setKrbUsrPwdCrawlerUrl(null);
        }
        setIsSessionEnabled(new Boolean(valveConf.getSessionConfig().isSessionEnabled()).booleanValue());
        setTestFormsCrawlUrl(valveConf.getTestFormsCrawlUrl());

        setErrorManagement(valveConf.getErrorLocation());

    }

    /**
     * Checks the HTTP status code. If this a "-1" value, it means the framework 
     * was not able to determinate the security, so an Unauthorized request is 
     * returned
     * 
     * @param response HTTP response
     * @param statusCode HTTP status code
     */
    public void setStatusCode(HttpServletResponse response, int statusCode) {
        //check if the status code is equal "-1" that means the response is indeterminate
        //as the pattern was not found
        if (statusCode == -1) {
            statusCode = HttpServletResponse.SC_UNAUTHORIZED;
        }

        response.setStatus(statusCode);

    }


}
