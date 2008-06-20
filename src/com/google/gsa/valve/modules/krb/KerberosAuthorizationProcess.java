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

package com.google.gsa.valve.modules.krb;

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
import com.google.gsa.valve.modules.utils.HTTPVisitor;
import com.google.krb5.Krb5Credentials;

import java.net.MalformedURLException;
import java.net.URL;

import java.net.URLDecoder;

/**
 * This class manages the authorization process for Kerberos protected 
 * content sources. It creates an HTTP connection to any Kerberized URL 
 * that is passed to the authenticate method. If the authorization 
 * process is succesful, the response is sent back to the caller, including 
 * the content (if it's not a HEAD request). In that case a 200 (OK) error 
 * message is returned, and if there is any other error is sent back as well.
 * <p>
 * It uses the user Kerberos ticket that has to be passed to its authorize() 
 * method. The default Kerberos credential, where the ticket is recovered, 
 * is "krb5".
 * 
 * @see KerberosAuthenticationProcess
 * 
 */
public class KerberosAuthorizationProcess implements AuthorizationProcessImpl {

    private Logger logger = null;
    private WebProcessor webProcessor = null;
    private Krb5Credentials credentials = null;
    private Credentials creds = null;
    //Header
    private Header[] headers = null;
    //Max Connections
    private int maxConnectionsPerHost = -1;
    private int maxTotalConnections = -1;
    //Method
    private HttpMethodBase method = null;

    //Var that tells the default Credential ID for Kerberos
    private static final String KRB5_ID = "krb5";

    //Config
    private ValveConfiguration valveConf;

    //Encoding
    private static final String encoder = "UTF-8";

    /**
     * Class constructor - default
     */
    public KerberosAuthorizationProcess() {
        //Instantiate logger
        logger = Logger.getLogger(KerberosAuthorizationProcess.class);
    }

    /**
     * Class constructor
     * <p>
     * It sets the user credentials at the same time
     * 
     * @param credentials Kerberos credentials
     */
    public KerberosAuthorizationProcess(Krb5Credentials credentials) {

        //Instantiate logger
        logger = Logger.getLogger(KerberosAuthorizationProcess.class);

        //set credentials
        this.credentials = credentials;

    }

    /**
     * Sets user's Kerberos credentials
     * 
     * @param credentials Kerberos credentials
     */
    public void setKrbCredentials(Krb5Credentials credentials) {
        this.credentials = credentials;
    }

    /**
     * Gets Kerberos credentials
     * 
     * @return Kerberos credentials
     */
    public Krb5Credentials getKrbCredentials() {
        return (this.credentials);
    }

    /**
     * Sets user generic credentials
     * 
     * @param creds user credentials
     */
    public void setCredentials(Credentials creds) {
        this.creds = creds;
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
     * priviledged to access to the document (url) against the Kerberized 
     * protected source that serves it.
     * <p>
     * The Kerberos user ticket is read from the credentials sent in the 
     * setCredentials() method. The default Kerberos credential, where the 
     * ticket is recovered, is "krb5".
     * <p>
     * If it is a HEAD request, it means it's not necessary to get the content, 
     * and that's why this process only cares about the HTTP result code. That 
     * result code is returned back to the caller, and if the request is not a 
     * HEAD (i.e. usually GET), the content is sent as well if the overall 
     * result is OK.
     * 
     * @param request HTTP request
     * @param response HTTP response
     * @param responseCookies vector that contains the authentication cookies
     * @param url the document url
     * @param id the default credential id
     * 
     * @return the HTTP error code
     * 
     * @throws HttpException
     * @throws IOException
     */
    public int authorize(HttpServletRequest request, 
                         HttpServletResponse response, 
                         Cookie[] responseCookies, String url, 
                         String id) throws HttpException, IOException {

        logger.debug("Krb Authorization");

        String loginUrl = null;

        loginUrl = valveConf.getLoginUrl();

        maxConnectionsPerHost = 
                (new Integer(valveConf.getMaxConnectionsPerHost())).intValue();
        maxTotalConnections = 
                (new Integer(valveConf.getMaxTotalConnections())).intValue();

        logger.debug("KrbAuthZ maxConnectionsPerHost: " + 
                     maxConnectionsPerHost);
        logger.debug("KrbAuthZ maxTotalConnections: " + maxTotalConnections);

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
        // Launch the authorization process
        //

        // Initialize status code
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        //set credentials
        if (creds != null) {
            logger.debug("creds is not null");
            if (creds.getCredential(KRB5_ID) != null) {
                credentials = 
                        new Krb5Credentials(valveConf.getKrbConfig().getKrbconfig(), 
                                            valveConf.getKrbConfig().getKrbini(), 
                                            creds.getCredential(KRB5_ID).getSubject());
            }
        }

        if (credentials == null) {

            // no authZ header, can't auth this URL
            logger.debug("No Kerberos credentials");
            return statusCode;

        } else {

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
                            webProcessor.sendRequest(credentials, requestType, headers, 
                                                     null, url);

                    // Protection
                    if (method != null) {
                        // Cache status code
                        statusCode = method.getStatusCode();
                        logger.debug("statusCode is.... " + statusCode);

                        if (statusCode == HttpServletResponse.SC_OK) {
                            //check if it's a Head request
                            if (!isHead) {
                                //call HTTPAuthZProcessor
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
                    logger.debug("Let's release the connection");
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
     * Sets the Kerberos authentication headers when authorizing
     * 
     */
    public void setHeaders() {

        int numHeaders = 1;

        //Set HTTP headers
        headers = new Header[numHeaders];
        // Set User-Agent
        headers[0] = 
                new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");

    }

}
