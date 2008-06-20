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
 * Reads the configuration parameters related to the Kerberos configuration.
 * It processes these parameters to configure the Kerberos frontend and the
 * access to kerberized content sources.
 * Kerberos can be used in two ways in the security framework:
 * <ul>
 *   <li>
 *      Silent authentication: the kerberos credentials as a result of a 
 *      negotiation process between the server and the client (browser)
 *   </li>
 *   <li> 
 *      Username/Password: the kerberos ticket is obtained from the user
 *      credentials passed thru a login form
 *   </li>
 * </ul>
 * 
 * @see ValveConfiguration
 * @see ValveConfigurationDigester
 * @see ValveConfigurationInstance
 * @see ValveRepositoryConfiguration
 * @see ValveSAMLConfiguration
 * @see ValveSessionConfiguration
 */
public class ValveKerberosConfiguration {
    
    //Kerberos parameters
    private String isKerberos = "false";
    private String isNegotiate = "false";
    private String krbini = null;
    private String krbconfig = null;
    private String krbAdditionalAuthN = null;
    private String krbLoginUrl = null;
    private String krbUsrPwdCrawler = "false";   
    private String krbUsrPwdCrawlerUrl = null;
    
    /**
     * Class constructor
     */
    public ValveKerberosConfiguration() {
    }

    /**
     * Defines if Kerberos is being used or not. It has two possible values:
     * true or false.
     * <p>
     * This is associated to the tag isKerberos in the config file
     * 
     * @param isKerberos kerberos is in place ("true") or not ("false")
     */
    public void setIsKerberos(String isKerberos) {
        this.isKerberos = isKerberos;
    }
    
    /**
     * Gets if Kerberos has to be used in the security framework
     * <p>
     * This is associated to the tag isKerberos in the config file
     * 
     * @return if kerberos is in place ("true") or not ("false")
     */
    public String isKerberos() {
        return isKerberos;
    }
    
    /**
     * Defines if Kerberos negotiation process is being used or not. The negotiation
     * process means the kerberos credentials are obtained as a consequence of
     * a conversation kept between the browser and the server.
     * It has two possible values:true or false.
     * <p>
     * This is associated to the tag isNegotiate in the config file
     * 
     * @param isNegotiate kerberos negotiation is in place ("true") or not ("false")
     */
    public void setIsNegotiate(String isNegotiate) {
        this.isNegotiate = isNegotiate;
    }
    
    /**
     * Gets if Kerberos negotiation process is being used or not. 
     * <p>
     * This is associated to the tag isNegotiate in the config file
     * 
     * @return if kerberos negotiation is in place ("true") or not ("false")
     */
    public String isNegotiate() {
        return isNegotiate;
    }
    
    /**
     * Sets the location of the system's Kerberos configuration (krb5.ini or
     * krb5.conf). This standard file sets the kerberos configuration in the
     * system, containing information like where the KDC servers are, the 
     * domains included and many other properties.
     * <p>
     * This is associated to the tag krbini in the config file
     * 
     * @param krbini the location of the krb5.ini (win) or krb5.conf (linux) file
     */
    public void setKrbini(String krbini) {
        this.krbini = krbini;
    }
    
    /**
     * Gets the location of the Kerberos configuration in the network. By default
     * this file is named krb5.ini in Windows environments and krb5.conf for
     * Linux/Unix systems.
     * <p>
     * This is associated to the tag krbini in the config file
     * 
     * @return the Kerberos network configuration file
     */
    public String getKrbini() {
        return krbini;
    }
    
    /**
     * It sets the kerberos configuration file when using the Kerberos 
     * silent frontend. It's a standard Java security config file that contains
     * the config needed to implement the silent interface.
     * <p>
     * This is associated to the tag krbconfig in the config file
     * 
     * @param krbconfig the location of the Java configuration file
     */
    public void setKrbconfig(String krbconfig) {
        this.krbconfig = krbconfig;
    }

    /**
     * Gets the pointer to where the Java config file is located in the host.
     * <p>
     * This is associated to the tag krbconfig in the config file
     * 
     * @return the Java config file path that contains the Kerberos configuration
     */
    public String getKrbconfig() {
        return krbconfig;
    }

    /**
     * It sets if there is an aditional username/password authentication method 
     * when kerberos silent authentication (isNegotiate was set to "true") is
     * in place. This is meant to merge the security coming from two different
     * environments.
     * It has two possible values:true or false.
     * <p>
     * This is associated to the tag krbAdditionalAuthN in the config file
     * 
     * @param krbAdditionalAuthN additional non-kerberos authn method ("true")
     */
    public void setKrbAdditionalAuthN(String krbAdditionalAuthN) {
        this.krbAdditionalAuthN = krbAdditionalAuthN;
    }
    
    /**
     * Gets if the additional non-Kerberos authentication mechanism is in
     * place ("true") or not ("false"). If it's "true" means that a login
     * authentication form is displayed to the user in order to get 
     * username and password, right after the kerberos credentials were obtained
     * silently.
     * <p>
     * This is associated to the tag krbAdditionalAuthN in the config file
     * 
     * @return additional non-kerberos authn method is set ("true") or not ("false")
     */
    public String isKrbAdditionalAuthN() {
        return krbAdditionalAuthN;
    }

    /**
     * Sets the login URL for the non-Kerberos additional mechanism when this
     * is set (krbAdditionalAuthN is "true"). It points to the forms login 
     * associated to the additional authentication schema.
     * <p>
     * This is associated to the tag krbLoginUrl in the config file
     * 
     * @param krbLoginUrl additional non-Kerberos login form URL
     */
    public void setKrbLoginUrl(String krbLoginUrl) {
        this.krbLoginUrl = krbLoginUrl;
    }

    /**
     * Gets the login form URL when additional non-Kerberos mechanism is set
     * <p>
     * This is associated to the tag krbLoginUrl in the config file
     * 
     * @return additional non-Kerberos login form URL
     */
    public String getKrbLoginUrl() {
        return krbLoginUrl;
    }
    
    /**
     * Sets if the GSA crawl process will go through the security framework
     * when Kerberos has been set in the security framework. 
     * The reason behind this parameter is the GSA can send username and password
     * credentials that can be used to create a Kerberos ticket for crawling.
     * This is just meant when Forms Based interface (isSAML is "false") is in place.
     * It has two possible values:true or false.
     * <p>
     * This is associated to the tag krbUsrPwdCrawler in the config file
     * 
     * @param krbUsrPwdCrawler if 
     */
    public void setKrbUsrPwdCrawler(String krbUsrPwdCrawler) {
        this.krbUsrPwdCrawler = krbUsrPwdCrawler;
    }

    /**
     * Gets if the crawling process for Kerberos is going to go through the 
     * security framework ("true") or not ("false") when Kerberos silent 
     * configuration is in place
     * <p>
     * This is associated to the tag krbUsrPwdCrawler in the config file
     * 
     * @return
     */
    public String isKrbUsrPwdCrawler() {
        return krbUsrPwdCrawler;
    }
    
    /**
     * Sets the login form URL that the crawler can use for getting the 
     * kerberized content. It can be set only when the krbUsrPwdCrawler 
     * parameter is "true" and the Forms Based interface is being used.
     * <p>
     * This is associated to the tag krbUsrPwdCrawlerUrl in the config file
     * 
     * @param krbUsrPwdCrawlerUrl the Kerberos crawling URL
     */
    public void setKrbUsrPwdCrawlerUrl(String krbUsrPwdCrawlerUrl) {
        this.krbUsrPwdCrawlerUrl = krbUsrPwdCrawlerUrl;
    }

    /**
     * Gets the login form URL used for by the GSA crawler process to 
     * get the kerberized content.
     * <p>
     * This is associated to the tag krbUsrPwdCrawlerUrl in the config file
     * 
     * @return the Kerberos crawling URL
     */
    public String getKrbUsrPwdCrawlerUrl() {
        return krbUsrPwdCrawlerUrl;
    }
}
