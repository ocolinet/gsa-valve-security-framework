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

import org.apache.log4j.Logger;

/**
 * This is the main configuration class that holds all the parameters. It reads
 * the config file present at wherever location you specify in the security framework.
 * It points to the other config classes that reads other tags like Session.
 * 
 * @see ValveConfigurationDigester
 * @see ValveConfigurationInstance
 * @see ValveKerberosConfiguration
 * @see ValveRepositoryConfiguration
 * @see ValveSAMLConfiguration
 * @see ValveSessionConfiguration
 * 
 */

public class ValveConfiguration {
	
        //Configuration parameters
        private String loginUrl;
	private String authCookieDomain;
	private String authenticationProcessImpl;
	private String authorizationProcessImpl;
	private String authenticateServletPath;
	private String authCookiePath;
	private String authMaxAge;
        private String authCookieName;
        private String refererCookieName;
	private Vector<String> searchHosts;
        
        //Max connections vars and test Url
        private String maxConnectionsPerHost;
        private String maxTotalConnections;
        private String testFormsCrawlUrl;  
        
        //Error location
        private String errorLocation;
        
        //Logger
        private static Logger logger = Logger.getLogger(ValveConfiguration.class);
	
        //Valve Repositories	
	private Vector<ValveRepositoryConfiguration> repositories;
        
        //Session and Krb objects
        ValveKerberosConfiguration krbConfig;
        ValveSessionConfiguration sessionConfig;
        
        //SAML
        ValveSAMLConfiguration samlConfig;
        
        
        /**
         * Class constructor
         * <p>
         * Initializes the repositories and search hosts vectors by default
         */
        public ValveConfiguration() {
                repositories = new Vector<ValveRepositoryConfiguration>();
                searchHosts = new Vector<String>();
        }
    
        
        /**
         * Gets the main authentication cookie's domain. This is set in the cookies
         * created by the security framework
         * <p>
         * This is associated to the tag authCookieDomain in the config file
         * 
         * @return the domain of the authentication cookies managed in the framework
         */
	public String getAuthCookieDomain() {
		return authCookieDomain;
	}
        
        /**
         * Sets the main authentication cookie's domain. This is set by default in the cookies
         * created by the security framework
         * <p>
         * This is associated to the tag authCookieDomain in the config file
         * 
         * @param authCookieDomain the main domain of the cookies managed in the Valve
         */        
	public void setAuthCookieDomain(String authCookieDomain) {
		this.authCookieDomain = authCookieDomain;
	}
        
        /**
        * Gets the authentication cookie's path. This is set by default in the cookies
        * created by the security framework
        * <p>
         * This is associated to the tag authCookiePath in the config file
        * 
        * @return the domain of the authentication cookies managed in the framework
        */
	public String getAuthCookiePath() {
		return authCookiePath;
	}
        
    /**
     * Sets the main authentication cookie's path. This is set by default in the cookies
     * created by the security framework
     * <p>
     * This is associated to the tag authCookiePath in the config file
     * 
     * @param authCookiePath the default path for the cookies managed by this application
     */  
	public void setAuthCookiePath(String authCookiePath) {
		this.authCookiePath = authCookiePath;
	}
        
        /**
     * Gets the authentication servlet path defined in the configuration. This is used
     * to reference the servlet that manages authentication in the framework
     * <p>
         * This is associated to the tag authenticateServletPath in the config file
     * 
     * @return the servlet authentication URL
     */
	public String getAuthenticateServletPath() {
		return authenticateServletPath;
	}
        
        /**
     * Sets the servlet authentication path read in the config file
     * <p>
         * This is associated to the tag authenticateServletPath in the config file
     * 
     * @param authenticateServletPath the URL to point to the authentication servlet
     */
	public void setAuthenticateServletPath(String authenticateServletPath) {
		this.authenticateServletPath = authenticateServletPath;
	}
        
        /**
     * Gets the Java class name resposible for managing the authentication process.
     * It usually is "com.google.gsa.valve.rootAuth.RootAuthenticationProcess"
     * <p>
         * This is associated to the tag authenticationProcessImpl in the config file
         * 
     * @return the name of the authentication process class
     */
	public String getAuthenticationProcessImpl() {
		return authenticationProcessImpl;
	}
        
        /**
     * Sets the name of the Java class that drives the authentication process
     * in the framework.
     * <p>
         * This is associated to the tag authenticationProcessImpl in the config file
     * 
     * @param authenticationProcessImpl the name of the authentication class
     */
	public void setAuthenticationProcessImpl(String authenticationProcessImpl) {
		this.authenticationProcessImpl = authenticationProcessImpl;
	}
        
    /**
    * Gets the Java class name resposible for managing the authorization process.
    * It usually is "com.google.gsa.valve.rootAuth.RootAuthorizationProcess"
    * <p>
         * This is associated to the tag authorizationProcessImpl in the config file
    *
    * @return the name of the authorization class
    */
    public String getAuthorizationProcessImpl() {
            return authorizationProcessImpl;
    }
    
    /**
     * Sets the name of the Java class that drives the authorization process
     * in the framework.
     * <p>
         * This is associated to the tag authorizationProcessImpl in the config file
     * 
     * @param authorizationProcessImpl the name of the authorization class
     */
    public void setAuthorizationProcessImpl(String authorizationProcessImpl) {
            this.authorizationProcessImpl = authorizationProcessImpl;
    }
        
        /**
     * Gets the maximum age of the cookies managed in the application
     * <p>
         * This is associated to the tag authMaxAge in the config file
     * 
     * @return the maximum age for the authentication cookies
     */
	public String getAuthMaxAge() {
		return authMaxAge;
	}
        
        /**
     * Sets the maximum age of the authentication cookies
     * <p>
         * This is associated to the tag authMaxAge in the config file
     * 
     * @param authMaxAge the maximum cookie age
     */
	public void setAuthMaxAge(String authMaxAge) {
		this.authMaxAge = authMaxAge;
	}  
        
        /**
     * Gets the name of the authentication cookie used in the framework
     * as the one that drives the security lifecycle when using Forms based
     * interface
     * <p>
         * This is associated to the tag authCookieName in the config file
     * 
     * @return the name of the authentication cookie
     */
        public String getAuthCookieName() {
            return authCookieName;
        }
        
        /**
     * Sets the name of the cookie that drives the authentication and authorization
     * process in the framework that acts as a SSO token. For instance: gsaSSOCookie
     * <p>
         * This is associated to the tag authCookieName in the config file
     * 
     * @param authCookieName the name of the authentication cookie
     */
        public void setAuthCookieName(String authCookieName) {
            this.authCookieName = authCookieName;
        }    
        
        /**
     * Gets the name of the cookie that stores the referer pointer in order
     * to keep the reference URL to be invoked right after the authentication
     * process is successfully done
     * <p>
         * This is associated to the tag refererCookieName in the config file
     * 
     * @return the referer cookie name
     */
        public String getRefererCookieName() {
            return refererCookieName;
        }
        
        /**
     * Sets the name of the referer cookie that contains the original URL. This
     * is used during the authentication process to request the URL that
     * initially invoked it. For instance: gsaRefererCookie
     * <p>
         * This is associated to the tag refererCookieName in the config file
     * 
     * @param refererCookieName the name of the referer cooki
     */
        public void setRefererCookieName(String refererCookieName) {
            this.refererCookieName = refererCookieName;
        }
        
        
        /**
     * Gets the login URL invoked during the authentication process
     * <p>
         * This is associated to the tag loginUrl in the config file
     * 
     * @return the login URL
     */
	public String getLoginUrl() {
		return loginUrl;
	}
	
        /**
     * Sets the login URL used during the authentication process
     * <p>
         * This is associated to the tag loginUrl in the config file
     * 
     * @param loginUrl the login URL
     */
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}
	
        /**
     * It adds a new repository read from the configuration file. The config
     * framework incokes this method for each repository defined in the
     * configuration. A repository contains the enough information to set
     * the access to a backend system that holds content (documents)
     * 
     * @param repository a new content repository
     */
	public void addRepository(ValveRepositoryConfiguration repository) {
		  repositories.addElement(repository);
	}
	
	
        /**
     * Gets the entire repository list defined in the configuration
     * 
     * @return an array that contains all the repositories
     */
	public String[] getRepositoryIds() {
		String[] ids = new String[getRepositoryCount()];
		
		for (int i = 0; i < repositories.size(); i++) {
			ids[i] = repositories.elementAt(i).getId();
		}
				
		return ids;
	}
	
	/**
     * Gets a repository, if it exists, using its identifier
     * 
     * @param id repository Identifier (id attribute)
     * @return the repository if it exists. If not, null
     */
	public ValveRepositoryConfiguration getRepository(String id) {
        ValveRepositoryConfiguration repository = null;
		if (repositories == null) {
			logger.debug ("Repositories are null");
			return null;
		} else {
			for (int i = 0; i < repositories.size(); i++) {
				if (repositories.elementAt(i).getId().equals(id)) {
					repository = repositories.elementAt(i);
				}
			}
			return repository;
		}
	}
	
        /**
     * Gets the total number of backend repositories defined in the config file
     * 
     * @return the number of existing repositories
     */
	public int getRepositoryCount() {
		int count = 0;
		
		count = repositories.size();
		
		return count;
	}
	
        /**
     * Gets all the search hosts (appliances) defined in your environment that
     * point to the security framework instance
     * <p>
         * This is associated to the tag searchHost in the config file
     * 
     * @return all the search appliances connected to this security server
     */
	public Vector getSearchHosts() {
		return searchHosts;
	}

        /**
     * Sets the search hosts that are configured in the environment. This is used
     * when reading those declared in the config file
     * <p>
         * This is associated to the tag searchHost in the config file
     * 
     * @param searchHosts the search host (appliances) list
     */
	public void setSearchHosts(Vector searchHosts) {
		this.searchHosts = searchHosts;
	}
	
    /**
    * Adds a new search host (appliance)
    * <p>
     * This is associated to the tag searchHost in the config file
    *
    * @param searchHosts the search host (appliances) list
    */
	public void addSearchHost(String searchHost) {
		searchHosts.addElement(searchHost);
        }
        
        /**
     * Sets the session configuration defined in the config file. 
     * <p>
     * This is associated to the tag session in the config file
     * 
     * @param sessionConfig the session config
     */
        public void setSessionConfig (ValveSessionConfiguration sessionConfig) {
            logger.debug ("Setting Session config");
            this.sessionConfig = sessionConfig;
        }
        
        /**
     * Gets the session configuration declared in the security framework
     * <p>
     * This is associated to the tag session in the config file
     * 
     * @return the session configuration
     */
        public ValveSessionConfiguration getSessionConfig () {
            return sessionConfig;
        }
        
        /**
     * Sets the configuration for the Kerberos frontend
     * <p>
     * This is associated to the tag kerberos in the config file
     * 
     * @param krbConfig the Kerberos config
     */
        public void setKrbConfig (ValveKerberosConfiguration krbConfig) {
            logger.debug ("Setting Krb config");
            this.krbConfig = krbConfig;
        }
    
    /**
    * Gets the configuration for the Kerberos frontend
    * <p>
    * This is associated to the tag kerberos in the config file
    *
    * @return the Kerberos config
    */
        public ValveKerberosConfiguration getKrbConfig () {
            return krbConfig;
        }        
        
    /**
    * Sets the configuration for the SAML interface
    * <p>
    * This is associated to the tag saml in the config file
    *
    * @param samlConfig the SAML config
    */
        public void setSAMLConfig (ValveSAMLConfiguration samlConfig) {
            logger.debug ("Setting SAML config");
            this.samlConfig = samlConfig;
        }
    
    /**
    * Gets the configuration for the SAML interface
    * <p>
    * This is associated to the tag saml in the config file
    *
    * @return the SAML config
    */
        public ValveSAMLConfiguration getSAMLConfig () {
            return samlConfig;
        }

    /**
     * Sets the maximum number of connections per host for those AuthN/AuthZ modules
     * thats make use of them. For example this is used by the HTTP Basic
     * module
     * <p>
    * This is associated to the tag maxConnectionsPerHost in the config file
     * 
     * @param maxConnectionsPerHost maximum number of connections per each host
     */
    public void setMaxConnectionsPerHost(String maxConnectionsPerHost) {
        this.maxConnectionsPerHost = maxConnectionsPerHost;
    }
    
    /**
     * Gets the maximum number of connections that can be created per host.
     * This is just used in some modules like for example the HTTP Basic one.
     * Your custom ones can also use it.
     * <p>
    * This is associated to the tag maxConnectionsPerHost in the config file
    * 
     * @return maximum number of connections per each host
     */
    public String getMaxConnectionsPerHost() {
        return maxConnectionsPerHost;
    }

    /**
     * Sets the maximum total number of connections for all the hosts.
     * This is just for those AuthN/AuthZ modules
     * thats make use of them. For example this is used by the HTTP Basic
     * module
     * <p>
    * This is associated to the tag maxTotalConnections in the config file
     * 
     * @param maxTotalConnections maximum total number of connections
     */
    public void setMaxTotalConnections(String maxTotalConnections) {
        this.maxTotalConnections = maxTotalConnections;
    }
    
    /**
     * Gets the total number of connections that can be created for all the content sources.
     * This is just used in some modules like for example the HTTP Basic one.
     * Your custom ones can also use it.
     * <p>
    * This is associated to the tag maxTotalConnections in the config file
     * 
     * @return maximum total number of connections
     */

    public String getMaxTotalConnections() {
        return maxTotalConnections;
    }

    /**
     * Sets the test URL used during specially for crawling content
     * but it's used as well during serving. This is always an internal
     * security framework URL like for example: 
     * http://valveserver:port/valve/test.html
     * <p>
    * This is associated to the tag testFormsCrawlUrl in the config file
    * 
     * @param testFormsCrawlUrl points to a test Url
     */
    public void setTestFormsCrawlUrl(String testFormsCrawlUrl) {
        this.testFormsCrawlUrl = testFormsCrawlUrl;
    }

    /**
     * Gets the internal test URL. This is a security framework protected URL
     * served by the same application instance. This is usually the following one:
     * http://valveserver:port/valve/test.html
     * <p>
    * This is associated to the tag testFormsCrawlUrl in the config file
    * 
     * @return the test internal Url
     */
    public String getTestFormsCrawlUrl() {
        return testFormsCrawlUrl;
    }
    
    /**
     * Sets the location where the error files are. They contain the friendly
     * customized error messages the framework returns when any associated
     * error arises.
     * <p>
    * This is associated to the tag errorLocation in the config file
     * 
     * @param errorLocation path that points to the custom error message files
     */
    public void setErrorLocation(String errorLocation) {
        this.errorLocation = errorLocation;
    }

    /**
     * Gets the path to where the error files are originally located.
     * <p>
    * This is associated to the tag errorLocation in the config file
     * 
     * @return path that points to the custom error message files
     */
    public String getErrorLocation() {
        return errorLocation;
    }

}
