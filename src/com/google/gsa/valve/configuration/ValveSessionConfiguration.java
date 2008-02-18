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

public class ValveSessionConfiguration {
    
    private String isSessionEnabled = null;
    private String sessionTimeout = null;
    private String maxSessionAge = null;
    private String sessionCleanup = null;
    private String sendCookies = null;
    
    public ValveSessionConfiguration() {
    }

    public void setIsSessionEnabled(String isSessionEnabled) {
        this.isSessionEnabled = isSessionEnabled;
    }

    public String isSessionEnabled() {
        return isSessionEnabled;
    }

    public void setSessionTimeout(String sessionTimeout) {
        this.sessionTimeout = sessionTimeout;
    }

    public String getSessionTimeout() {
        return sessionTimeout;
    }

    public void setMaxSessionAge(String maxSessionAge) {
        this.maxSessionAge = maxSessionAge;
    }

    public String getMaxSessionAge() {
        return maxSessionAge;
    }

    public void setSessionCleanup(String sessionCleanup) {
        this.sessionCleanup = sessionCleanup;
    }

    public String getSessionCleanup() {
        return sessionCleanup;
    }
        
    public void setSendCookies(String sendCookies) {
        this.sendCookies = sendCookies;
    }

    public String getSendCookies() {
        return sendCookies;
    }
    
}
