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


public class ValveConfiguration {
	
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
		
	private Vector<ValveRepositoryConfiguration> repositories;
        
        //Session and Krb objects
        ValveKerberosConfiguration krbConfig;
        ValveSessionConfiguration sessionConfig;                
        
        
        public ValveConfiguration() {
                repositories = new Vector<ValveRepositoryConfiguration>();
                searchHosts = new Vector<String>();
        }
    
        
	public String getAuthCookieDomain() {
		return authCookieDomain;
	}
	public void setAuthCookieDomain(String authCookieDomain) {
		this.authCookieDomain = authCookieDomain;
	}
	public String getAuthCookiePath() {
		return authCookiePath;
	}
	public void setAuthCookiePath(String authCookiePath) {
		this.authCookiePath = authCookiePath;
	}
	public String getAuthenticateServletPath() {
		return authenticateServletPath;
	}
	public void setAuthenticateServletPath(String authenticateServletPath) {
		this.authenticateServletPath = authenticateServletPath;
	}
	public String getAuthenticationProcessImpl() {
		return authenticationProcessImpl;
	}
	public void setAuthenticationProcessImpl(String authenticationProcessImpl) {
		this.authenticationProcessImpl = authenticationProcessImpl;
	}
	public String getAuthMaxAge() {
		return authMaxAge;
	}
	public void setAuthMaxAge(String authMaxAge) {
		this.authMaxAge = authMaxAge;
	}    
        public String getAuthCookieName() {
            return authCookieName;
        }
        public void setAuthCookieName(String authCookieName) {
            this.authCookieName = authCookieName;
        }    
        public String getRefererCookieName() {
            return refererCookieName;
        }
        public void setRefererCookieName(String refererCookieName) {
            this.refererCookieName = refererCookieName;
        }
	public String getAuthorizationProcessImpl() {
		return authorizationProcessImpl;
	}            	
	public void setAuthorizationProcessImpl(String authorizationProcessImpl) {
		this.authorizationProcessImpl = authorizationProcessImpl;
	}
	
	public String getLoginUrl() {
		return loginUrl;
	}
	
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}
	
	public void addRepository(ValveRepositoryConfiguration repository) {
		  repositories.addElement(repository);
	}
	
	
	public String[] getRepositoryIds() {
		String[] ids = new String[getRepositoryCount()];
		
		for (int i = 0; i < repositories.size(); i++) {
			ids[i] = repositories.elementAt(i).getId();
		}
		
		
		return ids;
	}
	
	
	public ValveRepositoryConfiguration getRepository(String id) {
        ValveRepositoryConfiguration repository = null;
		if (repositories == null) {
			System.out.println("repositories are null");
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
	
	public int getRepositoryCount() {
		int count = 0;
		
		count = repositories.size();
		
		return count;
	}
	
	public Vector getSearchHosts() {
		return searchHosts;
	}

	public void setSearchHosts(Vector searchHosts) {
		this.searchHosts = searchHosts;
	}
	
	public void addSearchHost(String searchHost) {
		searchHosts.addElement(searchHost);
        }
        
        public void setSessionConfig (ValveSessionConfiguration sessionConfig) {
            logger.debug ("Setting Session config");
            this.sessionConfig = sessionConfig;
        }
        
        public ValveSessionConfiguration getSessionConfig () {
            return sessionConfig;
        }
        
        public void setKrbConfig (ValveKerberosConfiguration krbConfig) {
            logger.debug ("Setting Krb config");
            this.krbConfig = krbConfig;
        }
    
        public ValveKerberosConfiguration getKrbConfig () {
            return krbConfig;
        }                

    public void setMaxConnectionsPerHost(String maxConnectionsPerHost) {
        this.maxConnectionsPerHost = maxConnectionsPerHost;
    }

    public String getMaxConnectionsPerHost() {
        return maxConnectionsPerHost;
    }

    public void setMaxTotalConnections(String maxTotalConnections) {
        this.maxTotalConnections = maxTotalConnections;
    }

    public String getMaxTotalConnections() {
        return maxTotalConnections;
    }

    public void setTestFormsCrawlUrl(String testFormsCrawlUrl) {
        this.testFormsCrawlUrl = testFormsCrawlUrl;
    }

    public String getTestFormsCrawlUrl() {
        return testFormsCrawlUrl;
    }
    
    public void setErrorLocation(String errorLocation) {
        this.errorLocation = errorLocation;
    }

    public String getErrorLocation() {
        return errorLocation;
    }
    
    public void logValveConfiguration () {
        logger.debug ("loginUrl: "+this.getLoginUrl());
        logger.debug ("authCookieDomain: "+this.getAuthCookieDomain());
        logger.debug ("authenticationProcessImpl: "+this.getAuthenticationProcessImpl());
        logger.debug ("authenticateServletPath: "+this.getAuthenticateServletPath());
        logger.debug ("authorizationProcessImpl: "+this.getAuthorizationProcessImpl());
        logger.debug ("authCookiePath: "+this.getAuthCookiePath());
        logger.debug ("authMaxAge: "+this.getAuthMaxAge());
        logger.debug ("authCookieName: "+this.getAuthCookieName());
        for (int i=0; i < searchHosts.size(); i++) {
            logger.debug ("searchHost ("+i+"): "+this.getSearchHosts().elementAt(i));
        }

        logger.debug ("maxConnectionsPerHost: "+this.getMaxConnectionsPerHost());
        logger.debug ("maxTotalConnections: "+this.getMaxTotalConnections());
        logger.debug ("testFormsCrawlUrl: "+this.getTestFormsCrawlUrl());
        logger.debug ("errorLocation: "+this.getErrorLocation());
        
        logger.debug("***Kerberos Configuration***");
        logger.debug ("isKerberos: "+this.getKrbConfig().isKerberos());
        logger.debug ("isNegotiate: "+this.getKrbConfig().isNegotiate());        
        logger.debug ("krbini: "+this.getKrbConfig().getKrbini());
        logger.debug ("krbconfig: "+this.getKrbConfig().getKrbconfig());
        logger.debug ("KrbAdditionalAuthN: "+this.getKrbConfig().isKrbAdditionalAuthN());
        logger.debug ("KrbLoginUrl: "+this.getKrbConfig().getKrbLoginUrl());
        logger.debug ("KrbUsrPwdCrawler: "+this.getKrbConfig().isKrbUsrPwdCrawler());
        logger.debug ("KrbUsrPwdCrawlerUrl: "+this.getKrbConfig().getKrbUsrPwdCrawlerUrl());
        
        logger.debug("***Session Configuration***");
        logger.debug("isSessionEnabled: "+this.getSessionConfig().isSessionEnabled());
        logger.debug("SessionTimeout: "+this.getSessionConfig().getSessionTimeout());
        logger.debug("MaxSessionAge: "+this.getSessionConfig().getMaxSessionAge());
        logger.debug("SessionCleanup: "+this.getSessionConfig().getSessionCleanup());
        logger.debug("SendCookies: "+this.getSessionConfig().getSendCookies());
                        
    }

}
