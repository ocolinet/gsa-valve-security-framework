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


import java.io.IOException;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;


import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;


/**
 * It implements the access to a backend repository that does not require any 
 * security, so everyone will be able to access to the document.
 * 
 */
public class HTTPNoAuthorizationProcess implements AuthorizationProcessImpl {

    //logger
    private Logger logger = null;

    //Valve configuration        
    private ValveConfiguration valveConf = null;

    /**
     * Class contructor
     * 
     */
    public HTTPNoAuthorizationProcess() {
        //Instantiate logger
        logger = Logger.getLogger(HTTPNoAuthorizationProcess.class);
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
     * This method simply returns an OK code as the content is considered as 
     * public.
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


        logger.debug("HTTP No Authorization");

        int statusCode = response.SC_OK;

        // Return status code
        return statusCode;


    }

}
