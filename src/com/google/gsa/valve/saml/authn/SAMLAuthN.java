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

package com.google.gsa.valve.saml.authn;

import java.io.UnsupportedEncodingException;

import java.net.URLEncoder;

import org.apache.log4j.Logger;

/**
 * Offers support for redirecting to the proper SAML client URL when 
 * authenticating.
 * 
 */
public class SAMLAuthN {

    //Logger
    private static Logger logger = Logger.getLogger(SAMLAuthN.class);

    //Encoding
    private static final String encoding = "UTF-8";

    //GSA URL
    private static final String samlArtifactConsumerURL = 
        "/SamlArtifactConsumer";

    /**
     * Class constructor
     * 
     */
    public SAMLAuthN() {
    }

    /**
     * Builds the URL to redirect back to the client SAML
     * 
     * @param gsaHost client's host
     * @param relayState relayState parameter
     * @param artifact artifact parameter
     * 
     * @return the redirection URL
     * 
     * @throws UnsupportedEncodingException
     */
    public static String redirectLocation(String gsaHost, String relayState, 
                                          String artifact) throws UnsupportedEncodingException {

        String relayAddress = gsaHost;
        logger.debug("GSA Url is: " + relayAddress);

        String SAMLart = URLEncoder.encode(artifact, encoding);
        logger.debug("SAMLart is: " + SAMLart);

        logger.debug("relayState is: " + relayState);
        String RelayState = URLEncoder.encode(relayState, encoding);
        logger.debug("RelayState is: " + RelayState);

        //build URL        
        relayAddress = 
                relayAddress + samlArtifactConsumerURL + "?SAMLart=" + SAMLart + 
                "&RelayState=" + RelayState;
        return relayAddress;
    }

}
