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
 * Class that implements a configuration exception. This is used by the other
 * classes part of the configuration framework.
 * 
 */ 
public class ValveConfigurationException extends Exception {
    
    //Error message
    private String message = null;
    
    /**
     * Class constructor
     */
    public ValveConfigurationException() {
    }
    
    /**
     * Class constructor with an error message
     * 
     * @param message error message
     */
    public ValveConfigurationException(String message) {
        super (message);
        setMessage (message);        
    }
    
    /**
     * Sets the error message associated to the exception
     * 
     * @param message error message
     */
    private void setMessage(String message) {
        this.message = message;
    }
    
    /**
     * Gets the error message linked with the exception
     * 
     * @return error message
     */
    public String getMessage() {
        return message;
    }
}
