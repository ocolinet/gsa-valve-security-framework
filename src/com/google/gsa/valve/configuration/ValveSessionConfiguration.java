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
 * It represents the Session configuration information to be used by the 
 * Security Framework classes. 
 * 
 */
public class ValveSessionConfiguration {

    //Parameters
    private String isSessionEnabled = "false";
    private String sessionTimeout = null;
    private String maxSessionAge = null;
    private String sessionCleanup = null;
    private String sendCookies = null;

    /**
     * Class constructor
     * 
     */
    public ValveSessionConfiguration() {
    }

    /**
     * Sets if the session is enabled
     * 
     * @param isSessionEnabled if the session is enabled
     */
    public void setIsSessionEnabled(String isSessionEnabled) {
        this.isSessionEnabled = isSessionEnabled;
    }

    /**
     * Gets if the session is enabled
     * 
     * @return if the session is enabled
     */
    public String isSessionEnabled() {
        return isSessionEnabled;
    }

    /**
     * Sets the session timeout since the last access (in minutes). It has a big 
     * impact in performance, so it's recommended to be disabled using "-1" 
     * value.
     * 
     * @param sessionTimeout session timeout
     */
    public void setSessionTimeout(String sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    /**
     * Gets the session timeout since the last access (in minutes).
     * 
     * @return session timeout
     */
    public String getSessionTimeout() {
        return sessionTimeout;
    }

    /**
     * Sets the maximum session age (in minutes)
     * 
     * @param maxSessionAge maximum session age
     */
    public void setMaxSessionAge(String maxSessionAge) {
        this.maxSessionAge = maxSessionAge;
    }

    /**
     * Gets the maximum session age (in minutes)
     * 
     * @return maximum session age
     */
    public String getMaxSessionAge() {
        return maxSessionAge;
    }

    /**
     * Sets the session cleanup interval (in minutes). It triggers an internal 
     * cleanup process that deletes all the invalid sessions. This way memory 
     * leaks are avoided.
     * 
     * @param sessionCleanup session cleanup interval
     */
    public void setSessionCleanup(String sessionCleanup) {
        this.sessionCleanup = sessionCleanup;
    }

    /**
     * Gets the session cleanup interval (in minutes)
     * 
     * @return session cleanup interval
     */
    public String getSessionCleanup() {
        return sessionCleanup;
    }

    /**
     * Sets if authentication cookies are sent back in the Servlet response 
     * instance. This way all the authentication cookies will be available at 
     * the browser, so that users can have SSO experience when accessing results
     * 
     * @param sendCookies if authentication cookies are returned
     */
    public void setSendCookies(String sendCookies) {
        this.sendCookies = sendCookies;
    }

    /**
     * Sets if authentication cookies are sent back in the Servlet response 
     * instance.
     * 
     * @return if authentication cookies are returned
     */
    public String getSendCookies() {
        return sendCookies;
    }

}
