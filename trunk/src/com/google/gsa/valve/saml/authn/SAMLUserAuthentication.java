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

/**
 * Represents the user information when authenticating through SAML
 * 
 */
public class SAMLUserAuthentication {

    /**
     * Holds value of property userName.
     */
    private String userName;

    /**
     * Holds value of property time.
     */
    private long time;


    /**
     * Class constructor
     * 
     * @param userName
     * @param time
     */
    public SAMLUserAuthentication(String userName, long time) {
        setUserName(userName);
        setTime(time);
    }

    /**
     * Gets the userName.
     * @return userName
     */
    public String getUserName() {
        return this.userName;
    }

    /**
     * Sets the userName.
     * @param userName user name
     */
    public void setUserName(String userName) {
        this.userName = userName;
    }

    /**
     * Gets the time.
     * @return time.
     */
    public long getTime() {
        return this.time;
    }

    /**
     * Sets the time.
     * @param time time
     */
    protected void setTime(long time) {
        this.time = time;
    }

}
