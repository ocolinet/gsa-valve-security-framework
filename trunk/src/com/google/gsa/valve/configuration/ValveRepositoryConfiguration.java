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


import java.util.Vector;

/**
 * It's the class that represents a Repository, a content source location the 
 * security framework has to have an AuthN/AuthZ module to connect to in order 
 * to check security. Each repository includes a URL pattern that lets the 
 * security framework to compare the requested URL with that pattern and if 
 * matches, the authorization module configure on it is triggered.
 * 
 */
public class ValveRepositoryConfiguration {

    //Configuration parameters
    private String id;
    private String pattern;
    private String authN;
    private String authZ;
    private String failureAllow = "false";
    private String checkAuthN = "true";

    private Vector<ValveRepositoryParameter> parameters;

    /**
     * Class constructor
     * 
     */
    public ValveRepositoryConfiguration() {
        parameters = new Vector<ValveRepositoryParameter>();
    }

    /**
     * Adds a new parameter in the list of additional attributes
     * 
     * @param parameter a repository parameter
     */
    public void addParameter(ValveRepositoryParameter parameter) {
        parameters.addElement(parameter);
    }

    /**
     * Gets a repository parameter (if it exists) from the list of additional 
     * attributes
     * 
     * @param name parameter name
     * 
     * @return the value of the parameter
     */
    public String getParameterValue(String name) {
        String parameterValue = null;
        if (parameters == null) {
            return null;
        } else {
            for (int i = 0; i < parameters.size(); i++) {
                if (parameters.elementAt(i).getName().equals(name)) {
                    parameterValue = parameters.elementAt(i).getValue();
                }
            }
            return parameterValue;
        }
    }

    /**
     * Gets the authentication class name associated to the repository
     * 
     * @return authentication class name
     */
    public String getAuthN() {
        return authN;
    }

    /**
     * Sets the authentication class name associated to the repository
     * 
     * @param authN authentication class name
     */
    public void setAuthN(String authN) {
        this.authN = authN;
    }

    /**
     * Gets the authorization class name associated to the repository
     * 
     * @return authorization class name
     */
    public String getAuthZ() {
        return authZ;
    }

    /**
     * Sets the authorization class name associated to the repository
     * 
     * @param authZ authorization class name
     */
    public void setAuthZ(String authZ) {
        this.authZ = authZ;
    }

    /**
     * Gets if an auhtN/authZ failure is allow. This has to be implemented in 
     * the authN/authZ classes associated to this repository
     * 
     * @return if an auhtN/authZ failure is allow
     */
    public String isFailureAllow() {
        return failureAllow;
    }

    /**
     * Sets if an auhtN/authZ failure is allow. This has to be implemented in 
     * the authN/authZ classes associated to this repositoru
     * 
     * @param failureAllow if an auhtN/authZ failure is allow
     */
    public void setFailureAllow(String failureAllow) {
        this.failureAllow = failureAllow;
    }

    /**
     * Gets if authentication has to be checked here. This is useful when there 
     * are multiple repository instances that do the same authentication
     * 
     * @return if authentication has to be checked here
     */
    public String getCheckAuthN() {
        return checkAuthN;
    }

    /**
     * Sets if authentication has to be checked here. This is useful when there 
     * are multiple repository instances that do the same authentication
     * 
     * @param checkAuthN if authentication has to be checked here
     */
    public void setCheckAuthN(String checkAuthN) {
        this.checkAuthN = checkAuthN;
    }

    /**
     * Gets the repository Id
     * 
     * @return repository Id
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the repository Id
     * 
     * @param id repository Id
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the URL pattern associated to the repository
     * 
     * @return the URL pattern
     */
    public String getPattern() {
        return pattern;
    }

    /**
     * Sets the URL pattern associated to the repository
     * 
     * @param pattern the URL pattern
     */
    public void setPattern(String pattern) {
        this.pattern = pattern;
    }
}
