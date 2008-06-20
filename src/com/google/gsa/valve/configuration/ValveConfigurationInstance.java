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


import org.apache.log4j.Logger;

/**
 * It permits to manage a single configuration instance that can be used
 * in all the security framework classes that need to read config parameters.
 * It implements a singleton pattern, so you need to invoke the getValveConfig()
 * method to obtain the reference to the unique config instance.
 * 
 * @see ValveConfiguration
 * @see ValveConfigurationDigester
 * @see ValveKerberosConfiguration
 * @see ValveRepositoryConfiguration
 * @see ValveSAMLConfiguration
 * @see ValveSessionConfiguration
 */
public class ValveConfigurationInstance {
    
    //logger
     private Logger logger = null;              
    
    //Valve Configuration instance
    private static ValveConfiguration valveConfig = null;
    
    //Valve Configuration Path
    private static String valveConfigPath = null;
    
    //ValveConfigurationInstance
    private static ValveConfigurationInstance valveConfigurationInstance = null;


    /**
     * Class constructor
     * <p>
     * It creates the singleton instance that is returned by the
     * getValveConfig() method.
     */
    private ValveConfigurationInstance() {
        
        logger = Logger.getLogger(ValveConfigurationInstance.class);
        
        logger.debug("Loading configuration from " + valveConfigPath);
        //Load configuration
        ValveConfigurationDigester valveConfDigester = new ValveConfigurationDigester();
        try {           
            logger.debug("Configuration");
            
            valveConfig = valveConfDigester.run(valveConfigPath);
        } catch (Exception e) {
                logger.error("Error getting Config instance: "+e.getMessage(),e);
                valveConfig = null;
        }
        
    }
    
    /**
     * This method gets the singleton configuration instance. This class returns
     * such instance if it already exists, and if not, it  invokes the private
     * constructor to generate it before returning.
     * This is the method that is used by those classes that have the ability to
     * read the config file location.
     * 
     * @param valveConfigurationPath location of the config file
     * @return the unique configuration instance
     * @throws ValveConfigurationException
     */
    public static ValveConfiguration getValveConfig (String valveConfigurationPath) throws ValveConfigurationException {
        //protection
        if ((valveConfigurationPath != null)&&(!valveConfigurationPath.equals(""))) {
            valveConfigPath = valveConfigurationPath;
        }
        return getValveConfig ();
    }
    
    /**
     * This method is equivalent to the previous one but it does not pass the
     * config file path. 
     * 
     * @return the unique configuration instance
     * @throws ValveConfigurationException
     */
    public static ValveConfiguration getValveConfig () throws ValveConfigurationException {
        if (valveConfig == null) {
            if ((valveConfigPath != null)&&(!valveConfigPath.equals(""))) {
                valveConfigurationInstance = new ValveConfigurationInstance();
            } else {
                throw new ValveConfigurationException ("Configuration error: valveConfigPath has not been properly defined");
            }
        }
        return valveConfig;
    }

    /**
     * Sets the config file path in order to read and parse it
     * 
     * @param valveConfigPath the config file location
     */
    public void setValveConfigPath(String valveConfigPath) {
        this.valveConfigPath = valveConfigPath;
    }

    /**
     * Gets the config file path
     * 
     * @return the config file location
     */
    public String getValveConfigPath() {
        return valveConfigPath;
    }
}
