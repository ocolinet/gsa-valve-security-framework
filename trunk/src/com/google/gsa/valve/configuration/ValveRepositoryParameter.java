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
 * It represents a Repository parameter. Each content repository can be 
 * configured with some parameters that sends setup information to the 
 * repository's AuthN/AuthZ modules.
 * 
 */
public class ValveRepositoryParameter {

    //Parameter attributes
    private String name;
    private String value;

    /**
     * Class constructor
     * 
     */
    public ValveRepositoryParameter() {
    }

    /**
     * Gets the parameter's name
     * 
     * @return parameter's name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the parameter's name
     * 
     * @param name parameter's name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the parameter's value
     * 
     * @return parameter's value
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the parameter's value
     * 
     * @param value parameter's value
     */
    public void setValue(String value) {
        this.value = value;
    }


}
