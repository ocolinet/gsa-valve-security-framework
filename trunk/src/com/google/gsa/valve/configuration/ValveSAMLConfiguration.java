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

package com.google.gsa.valve.configuration;

/**
 * This class implements the SAML configuration logic. It contains all the 
 * needed parameters to configure the SAML frontend in the Security 
 * Framework.
 * 
 */
public class ValveSAMLConfiguration {

    //SAML parameters
    private String isSAML = "false";
    private String maxArtifactAge = null;
    private String samlTimeout = null;

    /**
     * Class constructor
     * 
     */
    public ValveSAMLConfiguration() {
    }

    /**
     * Sets if SAML interface is configured
     * 
     * @param isSAML if SAML interface is configured
     */
    public void setIsSAML(String isSAML) {
        this.isSAML = isSAML;
    }

    /**
     * Gets if SAML interface is configured
     * 
     * @return if SAML interface is configured
     */
    public String isSAML() {
        return isSAML;
    }

    /**
     * Sets the maximum artifact age (in secs)
     * 
     * @param maxArtifactAge maximum artifact age
     */
    public void setMaxArtifactAge(String maxArtifactAge) {
        this.maxArtifactAge = maxArtifactAge;
    }

    /**
     * Gets the maximum artifact age (in secs)
     * 
     * @return maximum artifact age
     */
    public String getMaxArtifactAge() {
        return maxArtifactAge;
    }

    /**
     * Sets the SAML timeout (in minutes)
     * 
     * @param samlTimeout SAML timeout
     */
    public void setSamlTimeout(String samlTimeout) {
        this.samlTimeout = samlTimeout;
    }

    /**
     * Gets the SAML timeout (in minutes)
     * 
     * @return SAML timeout
     */
    public String getSamlTimeout() {
        return samlTimeout;
    }
}
