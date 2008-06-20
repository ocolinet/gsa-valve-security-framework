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

package com.google.gsa.valve.modules.utils;

import com.google.gsa.RequestType;

import com.google.gsa.valve.configuration.ValveConfiguration;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

/**
 * It implements some util methods that are called from the authorization
 * modules. 
 * 
 */
public class AuthorizationUtils {

    //logger
    private static Logger logger = Logger.getLogger(AuthorizationUtils.class);

    /*Var to force to send (or not) a Head Request. Values:
     *      -1: Not set (take a decision based on the other vars)
     *       0: true (It's a Head Request)
     *       1: false (It's not a Head Request)
     */
    private static int headRequest = -1;

    /*Var to force to process (or not) the HTML content. Values:
     *      -1: Not set (take a decision based on the other vars)
     *       0: true (It has to be processed)
     *       1: false (It has not to be processed)
     *Processing means rewritten URLs to always redirect to the Valve Framework (only for Forms Based)
     */
    private static int processHTML = -1;


    /**
     * Class constructor
     * 
     */
    public AuthorizationUtils() {
    }


    /**
     * Forces the request to be a HEAD
     *  
     * @param isHead boolean - if it's a HEAD request
     */
    public static void setHeadRequest(boolean isHead) {
        if (isHead) {
            headRequest = 0;
        } else {
            headRequest = 1;
        }
    }

    /**
     * Checks if the request is a Head request or not
     * 
     * @param request HTTP request
     * @param valveConf valve configuration
     * 
     * @return boolean - if it's a HEAD request
     */
    public static boolean isHead(HttpServletRequest request, 
                                 ValveConfiguration valveConf) {

        boolean isHead = false;

        //Process if Head request has been set
        if (headRequest == -1) {
            //Head request has not been set initially. Identify if it's HEAD request
            //based on the environment

            boolean isSAML = false;

            if (valveConf.getSAMLConfig().isSAML().equals("true")) {
                isSAML = true;
            }

            if (isSAML) {

                isHead = true;

            } else {

                //check if the request is either a HEAD or contains Range:0-0 header
                String range = request.getHeader("Range");
                logger.debug("Range Header: " + range);

                if (request.getMethod().equals(RequestType.HEAD_REQUEST)) {
                    isHead = true;
                } else {
                    if (range != null) {
                        if (range.contains("0-0")) {
                            isHead = true;
                        }
                    }
                }

            }
        } else {
            if (headRequest == 0) {
                //It's a Head Request
                isHead = true;
            } else {
                //It's not a Head Request (value 1)
                isHead = false;
            }

        }

        return isHead;

    }

    /**
     * Processes if the URLs have to be rewritten in HTML docs
     * 
     * @return the value (-1,0,1) that tells if URLs have to be rewritten
     */
    public static boolean isProcessHTML() {
        //Default value is true
        boolean isProcessHTML = true;
        //check if processHTML is "1", if so it's the only case URLs are not going to be rewritten
        if (processHTML == 1) {
            isProcessHTML = false;
        }
        return isProcessHTML;
    }

    /**
     * Forces the response to be processed in order to rewrite URLs
     * 
     * @param isProcess boolean - sets if it's HTML have to be processed
     */
    public static void setProcessHTML(boolean isProcess) {
        if (isProcess) {
            processHTML = 0;
        } else {
            processHTML = 1;
        }
    }

}
